"""The analyst's SQL guard: one read-only query over the 11 marts, rendered again.

``check(text)`` parses a model-written query with sqlglot's Postgres dialect and
returns a ``Checked`` (the SQL to run, the marts it reads and the functions it
calls) or a ``Refusal`` with a reason. Nothing runs the model's own text: the
runner executes ``Checked.sql``, the guard's rendering of its own tree, where
every table is written ``marts.<name>`` and the outer LIMIT is at most
``ROW_CAP + 1``.

The rules, in order:

1. Text over ``MAX_CHARS`` characters is refused, and so is text with no tokens
   (empty, whitespace or only comments).
2. One statement: at most one ``;``, and only as the last token, counted on
   sqlglot's own tokens, so a ``;`` inside a string or a comment doesn't count.
3. The statement, and every CTE body, is a query: SELECT, UNION, INTERSECT,
   EXCEPT or VALUES, with or without WITH.
4. Every node's class must be on an allow-list, so writes, DDL, SELECT INTO,
   row locks and every other statement are refused by absence. E'' and U&''
   strings are refused by name: sqlglot writes E-strings back without escaping
   their backslashes, so a rendering could turn the rest of a string into SQL.
5. A typed function must be on ``_FUNCTIONS``, and an ``Anonymous`` one's
   lower-cased name on ``_FUNCTION_NAMES``. A schema-qualified function call is
   refused. A function in FROM is checked here, as a function.
6. A cast must be to one of the built-in types in ``_CAST_TYPES``.
7. Identifiers are first normalized the way Postgres folds them (unquoted names
   to lower case; quoted ones stay as written), so sqlglot's scope analysis
   matches a CTE reference the way Postgres does. Every table that isn't a CTE
   reference must be one of the 11 marts, written ``marts.<name>`` or
   ``<name>``, with no catalog part. A CTE named like a mart is refused.
8. The rendering writes every table as ``marts.<name>`` and caps the outer
   LIMIT (or FETCH FIRST) at ``ROW_CAP + 1``; LIMIT NULL, LIMIT ALL, no limit
   or a limit that isn't an integer literal becomes ``ROW_CAP + 1``. FETCH
   with WITH TIES or PERCENT is refused, since neither keeps a row cap. The
   rendering is then parsed again, must pass rules 1-7 again, and must render
   to the same text. sqlglot rewrites some constructs as it writes them (it
   writes ``date_part``'s unit string back as bare SQL), so the guard checks
   the query as it will run, not only the tree it first read.
9. sqlglot also rewrites some literals: it reads only the leading number and
   unit of an interval string (``'1 day 12:00'`` becomes ``'1 DAY'``) and
   converts to_char formats through its own notation (``'%Y'`` becomes
   ``'YYYY'``). The guard reads both kinds from the tokens of the model's text
   and of the rendering, and refuses the query unless they match: interval
   text ignoring case and whitespace, as Postgres reads it, and to_char formats
   exactly, since their patterns are case-sensitive. A field word after an
   interval string is read as part of it when the string is a whole number
   (``interval '1' day`` is ``1 day``, as the rendering writes it). After any
   other string the query is refused: Postgres reads the word as a field limit
   and drops the smaller units (``interval '1.5' hour`` is 1 hour,
   ``interval '36 hours' day`` is 0), while the rendering keeps them, either
   inside the string (``'1.5 HOUR'`` is 1:30) or with the word written as a
   column alias (``INTERVAL '36 HOURS' AS day``). A to_char format must be one
   plain string literal, checked on the tree: sqlglot converts strings nested
   anywhere in that argument (``('%Y')``, ``'%Y'::text``, ``coalesce('%Y', ...)``),
   where the tokens can't show it.

Postgres reads attribute notation ``t.f`` as the function call ``f(t)``, while
sqlglot parses it as a column, so the function allow-list doesn't see it. That
reaches only functions that take one row argument, none of which has a side
effect; ``t.pg_sleep`` fails as an unknown column, and the role still limits
what any call can read.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.dialects.dialect import Dialect
from sqlglot.errors import SqlglotError
from sqlglot.expressions.datatypes import DType
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers
from sqlglot.optimizer.scope import Scope, traverse_scope
from sqlglot.tokenizer_core import Token, TokenType

from cyber_threat_pipeline.analyst.schema import MART_NAMES, MART_SCHEMA

MAX_CHARS = 20_000
ROW_CAP = 1_000

_DIALECT = "postgres"

_QUERIES = (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Values)

_ESCAPE_STRINGS = (exp.ByteString, exp.UnicodeString)

# Query structure, values and operators. Every node class not listed here, in
# _FUNCTIONS, or as an allowed Anonymous name is refused.
_NODES: frozenset[type[exp.Expr]] = frozenset(
    {
        exp.Select,
        exp.Union,
        exp.Intersect,
        exp.Except,
        exp.Values,
        exp.With,
        exp.CTE,
        exp.Subquery,
        exp.From,
        exp.Join,
        exp.Lateral,
        exp.Where,
        exp.Group,
        exp.Having,
        exp.Order,
        exp.Ordered,
        exp.Limit,
        exp.Offset,
        exp.Fetch,
        exp.LimitOptions,
        exp.Distinct,
        exp.Window,
        exp.WindowSpec,
        exp.Filter,
        exp.WithinGroup,
        exp.Table,
        exp.TableAlias,
        exp.Alias,
        exp.Column,
        exp.Identifier,
        exp.Star,
        exp.Tuple,
        exp.Paren,
        exp.Literal,
        exp.RawString,
        exp.Boolean,
        exp.Null,
        exp.Interval,
        exp.Var,
        exp.Array,
        exp.Bracket,
        exp.Cast,
        exp.DataType,
        exp.DataTypeParam,
        exp.And,
        exp.Or,
        exp.Not,
        exp.Neg,
        exp.EQ,
        exp.NEQ,
        exp.GT,
        exp.GTE,
        exp.LT,
        exp.LTE,
        exp.NullSafeEQ,
        exp.NullSafeNEQ,
        exp.Is,
        exp.In,
        exp.Between,
        exp.Any,
        exp.Exists,
        exp.Like,
        exp.ILike,
        exp.RegexpLike,
        exp.RegexpILike,
        exp.Add,
        exp.Sub,
        exp.Mul,
        exp.Div,
        exp.Mod,
        exp.DPipe,
        exp.Case,
        exp.If,
        exp.JSONExtract,
        exp.JSONExtractScalar,
        exp.JSONPath,
        exp.JSONPathRoot,
        exp.JSONPathKey,
        exp.JSONPathSubscript,
    }
)

# Typed functions, by the class sqlglot 30.21.0 parses each one to.
_FUNCTIONS: frozenset[type[exp.Expr]] = frozenset(
    {
        # aggregates: count, sum, avg, min, max, bool_and, bool_or, string_agg,
        # array_agg, percentile_cont, percentile_disc
        exp.Count,
        exp.Sum,
        exp.Avg,
        exp.Min,
        exp.Max,
        exp.LogicalAnd,
        exp.LogicalOr,
        exp.GroupConcat,
        exp.ArrayAgg,
        exp.PercentileCont,
        exp.PercentileDisc,
        # window functions
        exp.RowNumber,
        exp.Rank,
        exp.DenseRank,
        exp.Lag,
        exp.Lead,
        exp.FirstValue,
        exp.LastValue,
        exp.Ntile,
        # math (mod is the Mod operator above)
        exp.Round,
        exp.Trunc,
        exp.Floor,
        exp.Ceil,
        exp.Abs,
        exp.Greatest,
        exp.Least,
        exp.Coalesce,
        exp.Nullif,
        exp.Pow,
        exp.Sqrt,
        # text: lower, upper, length, btrim and trim, substring, left, right,
        # position, replace, split_part, concat
        exp.Lower,
        exp.Upper,
        exp.Length,
        exp.Trim,
        exp.Substring,
        exp.Left,
        exp.Right,
        exp.StrPosition,
        exp.Replace,
        exp.SplitPart,
        exp.Concat,
        # time: now and current_timestamp, current_date, date_trunc,
        # date_part and extract, to_char
        exp.CurrentTimestamp,
        exp.CurrentDate,
        exp.TimestampTrunc,
        exp.Extract,
        exp.TimeToStr,
        # set-returning: generate_series; unnest in SELECT and in FROM
        exp.ExplodingGenerateSeries,
        exp.Explode,
        exp.Unnest,
    }
)

# Functions sqlglot has no class for (it parses them to Anonymous), by the
# lower-cased name.
_FUNCTION_NAMES: frozenset[str] = frozenset(
    {
        "age",
        "jsonb_agg",
        "jsonb_array_elements",
        "jsonb_array_elements_text",
        "jsonb_array_length",
        "jsonb_each",
        "jsonb_each_text",
        "jsonb_object_keys",
        "jsonb_typeof",
        "make_date",
    }
)

_CAST_TYPES: frozenset[DType] = frozenset(
    {
        DType.SMALLINT,
        DType.INT,
        DType.BIGINT,
        DType.DECIMAL,
        DType.FLOAT,
        DType.DOUBLE,
        DType.TEXT,
        DType.VARCHAR,
        DType.BOOLEAN,
        DType.DATE,
        DType.TIMESTAMP,
        DType.TIMESTAMPTZ,
        DType.INTERVAL,
        DType.JSONB,
        DType.JSON,
    }
)

_INTEGER = re.compile(r"[0-9]+")
_SIGNED_INTEGER = re.compile(r"[+-]?[0-9]+")


@dataclass(frozen=True)
class Checked:
    """A query the guard accepted.

    ``sql`` is the guard's rendering, the only text to execute. ``marts`` names
    the marts it reads. ``functions`` names the functions it calls: sqlglot's
    lower-cased class name for a typed one (``timestamptrunc`` for
    ``date_trunc``), the lower-cased name for any other.
    """

    sql: str
    marts: tuple[str, ...]
    functions: tuple[str, ...]


@dataclass(frozen=True)
class Refusal:
    """A query the guard refused, and why."""

    reason: str


class _Refused(Exception):
    """Raised inside the guard; ``check`` returns it as a ``Refusal``."""


def check(text: str) -> Checked | Refusal:
    """Check one model-written query; see the module docstring for the rules."""
    try:
        tree = _parse(text)
        tables, functions = _inspect(tree)
        rendering = _render(tree, tables)
        _check_stable(rendering)
        _check_literals(text, rendering)
    except _Refused as refused:
        return Refusal(str(refused))
    except RecursionError:
        return Refusal("query is too deeply nested")
    except Exception as error:
        # sqlglot raises plain errors (ValueError and others) on some malformed
        # SQL; whatever it raises, the query is refused, never run.
        return Refusal(f"parse error: {_first_line(error)}")
    marts = tuple(sorted({table.name for table in tables}))
    return Checked(sql=rendering, marts=marts, functions=functions)


def _parse(text: str) -> exp.Expr:
    """Rules 1 and 2: the text's one statement, with identifiers normalized."""
    if len(text) > MAX_CHARS:
        raise _Refused(f"query is longer than {MAX_CHARS:,} characters")
    try:
        tokens = Dialect.get_or_raise(_DIALECT).tokenize(text)
    except SqlglotError as error:
        raise _Refused(f"parse error: {_first_line(error)}") from None
    kinds = [token.token_type for token in tokens]
    if kinds[-1:] == [TokenType.SEMICOLON]:
        kinds.pop()
    if not kinds:
        raise _Refused("query is empty")
    if TokenType.SEMICOLON in kinds:
        raise _Refused("more than one statement")
    try:
        parsed = sqlglot.parse(text, read=_DIALECT)
    except SqlglotError as error:
        raise _Refused(f"parse error: {_first_line(error)}") from None
    # A comment after the trailing ';' parses to a Semicolon node of its own.
    statements = [s for s in parsed if s is not None and not isinstance(s, exp.Semicolon)]
    if len(statements) != 1:
        raise _Refused("more than one statement")
    return normalize_identifiers(statements[0], dialect=_DIALECT)


def _inspect(tree: exp.Expr) -> tuple[list[exp.Table], tuple[str, ...]]:
    """Rules 3-7: the tables to qualify, and the functions the query calls."""
    _check_queries(tree)
    functions = _check_nodes(tree)
    return _mart_tables(tree), functions


def _check_queries(tree: exp.Expr) -> None:
    """Rule 3: the statement and every CTE body is a query."""
    for node in (tree, *(cte.this for cte in tree.find_all(exp.CTE))):
        if not isinstance(node, _QUERIES):
            raise _Refused(f"not a query: {type(node).__name__}")


def _check_nodes(tree: exp.Expr) -> tuple[str, ...]:
    """Rules 4-6 (node classes, strings, functions and casts) and rule 9's to_char format."""
    nodes = list(tree.walk())
    if any(isinstance(node, _ESCAPE_STRINGS) for node in nodes):
        raise _Refused("escape strings are not allowed")
    functions: set[str] = set()
    for node in nodes:
        if isinstance(node, exp.Dot) and isinstance(node.expression, exp.Func):
            raise _Refused("schema-qualified function calls are not allowed")
        if isinstance(node, exp.LimitOptions) and (
            node.args.get("with_ties") or node.args.get("percent")
        ):
            raise _Refused("FETCH WITH TIES and PERCENT are not allowed")
        if isinstance(node, exp.TimeToStr) and not _plain_string(node.args.get("format")):
            raise _Refused("to_char format must be one string literal")
        if isinstance(node, exp.Anonymous):
            name = node.name.lower()
            if name not in _FUNCTION_NAMES:
                raise _Refused(f"function not allowed: {name}")
            functions.add(name)
        elif isinstance(node, exp.Cast) and not isinstance(node.to, exp.DataType):
            raise _Refused(f"cast not allowed: {node.to.sql(dialect=_DIALECT).lower()}")
        elif isinstance(node, exp.DataType) and node.this not in _CAST_TYPES:
            raise _Refused(f"cast not allowed: {node.sql(dialect=_DIALECT).lower()}")
        elif type(node) in _FUNCTIONS:
            functions.add(type(node).__name__.lower())
        elif type(node) not in _NODES:
            kind = "function" if isinstance(node, exp.Func) else "syntax"
            raise _Refused(f"{kind} not allowed: {type(node).__name__}")
    return tuple(sorted(functions))


def _plain_string(node: exp.Expr | None) -> bool:
    return isinstance(node, exp.Literal) and node.is_string


def _mart_tables(tree: exp.Expr) -> list[exp.Table]:
    """Rule 7: every table that isn't a CTE reference or a function is a mart."""
    for cte in tree.find_all(exp.CTE):
        if cte.alias in MART_NAMES:
            raise _Refused(f"CTE name shadows a mart: {cte.alias}")
    try:
        scopes = traverse_scope(tree)
    except SqlglotError as error:
        raise _Refused(f"parse error: {_first_line(error)}") from None
    cte_refs = {id(table) for scope in scopes for table in scope.tables if _names_cte(table, scope)}
    tables: list[exp.Table] = []
    # A table no scope resolves (as in a VALUES statement's subquery) is checked
    # as a table, never assumed to be a CTE reference.
    for table in tree.find_all(exp.Table):
        if isinstance(table.this, exp.Func):
            if table.db or table.catalog:
                raise _Refused("schema-qualified function calls are not allowed")
            continue
        if id(table) in cte_refs:
            continue
        if not (
            isinstance(table.this, exp.Identifier)
            and not table.catalog
            and table.db in ("", MART_SCHEMA)
            and table.name in MART_NAMES
        ):
            name = ".".join(part.sql(dialect=_DIALECT) for part in table.parts)
            raise _Refused(f"table not allowed: {name}")
        tables.append(table)
    return tables


def _names_cte(table: exp.Table, scope: Scope) -> bool:
    return (
        isinstance(table.this, exp.Identifier)
        and not table.db
        and not table.catalog
        and table.name in scope.cte_sources
    )


def _render(tree: exp.Expr, tables: list[exp.Table]) -> str:
    """Rule 8: qualify every mart, cap the outer limit, write the SQL."""
    for table in tables:
        table.set("db", exp.to_identifier(MART_SCHEMA))
    cap = exp.Literal.number(ROW_CAP + 1)
    limit = tree.args.get("limit")
    if isinstance(limit, exp.Fetch):
        count = limit.args.get("count")
        # FETCH FIRST ROW ONLY, with no count, is one row.
        if count is not None and not _within_cap(count):
            limit.set("count", cap)
    elif isinstance(limit, exp.Limit):
        if not _within_cap(limit.expression):
            limit.set("expression", cap)
    else:
        tree.set("limit", exp.Limit(expression=cap))
    return tree.sql(dialect=_DIALECT, comments=False)


def _within_cap(count: exp.Expr) -> bool:
    return (
        isinstance(count, exp.Literal)
        and not count.is_string
        and _INTEGER.fullmatch(count.this) is not None
        and int(count.this) <= ROW_CAP + 1
    )


def _check_stable(rendering: str) -> None:
    """Rule 8's fixpoint: the rendering, read again, passes and renders the same."""
    try:
        again = _parse(rendering)
        tables, _ = _inspect(again)
        second = _render(again, tables)
    except _Refused as refused:
        raise _Refused(f"rendering is not stable: {refused}") from None
    if second != rendering:
        raise _Refused("rendering is not stable")


_INTERVAL_FIELDS = frozenset({"year", "month", "day", "hour", "minute", "second"})


def _check_literals(text: str, rendering: str) -> None:
    """Rule 9: the rendering keeps every interval literal and to_char format."""
    source, rendered = Counter(_literals(text)), Counter(_literals(rendering))
    changed = (source - rendered) or (rendered - source)
    if changed:
        kind, value = min(changed)
        raise _Refused(f"rendering changes {kind}: {value!r}")


def _literals(sql: str) -> list[tuple[str, str]]:
    """The interval literals and to_char formats in ``sql``, read from its tokens."""
    tokens = Dialect.get_or_raise(_DIALECT).tokenize(sql)
    found: list[tuple[str, str]] = []
    for i, token in enumerate(tokens):
        following = tokens[i + 1 : i + 3]
        if (
            token.token_type is TokenType.INTERVAL
            and following[:1]
            and (following[0].token_type is TokenType.STRING)
        ):
            value = following[0].text
            if len(following) > 1 and following[1].text.lower() in _INTERVAL_FIELDS:
                field = following[1].text
                # interval '1' day: the field word belongs to a whole-number literal.
                # After any other string Postgres reads it as a field limit, which
                # the rendering drops (rule 9 in the module docstring).
                if not _SIGNED_INTEGER.fullmatch(value):
                    raise _Refused(f"rendering changes an interval literal: {value!r} {field}")
                value += " " + field
            found.append(("an interval literal", " ".join(value.lower().split())))
        elif (
            token.text.lower() == "to_char"
            and following[:1]
            and (following[0].token_type is TokenType.L_PAREN)
        ):
            fmt = _second_argument(tokens, i + 1)
            if fmt is not None:
                found.append(("a to_char format", fmt))
    return found


def _second_argument(tokens: list[Token], open_paren: int) -> str | None:
    """The text of a call's second argument when it is one string token."""
    depth, argument, current = 0, 0, []
    for token in tokens[open_paren:]:
        if token.token_type is TokenType.L_PAREN:
            depth += 1
            if depth == 1:
                continue
        elif token.token_type is TokenType.R_PAREN:
            depth -= 1
            if depth == 0:
                break
        elif token.token_type is TokenType.COMMA and depth == 1:
            argument += 1
            continue
        if argument == 1:
            current.append(token)
    if len(current) == 1 and current[0].token_type is TokenType.STRING:
        return current[0].text
    return None


def _first_line(error: Exception) -> str:
    lines = str(error).splitlines()
    return lines[0] if lines else type(error).__name__
