"""The analyst's prompts, the SQL block read from a reply, and escaping model text.

The SQL prompt is one user message: the rules, the schema card, then the
question last, so the prefix stays the same across questions. It holds no data
value. Only the explanation prompt holds rows: at most ``EXPLAIN_ROWS``, with
long text cut at ``TEXT_CUT`` characters, the row count and whether the result
was cut at the row cap. ``rows_text`` is that part, which the eval's judge also
sees.

A reply must hold exactly one fenced ``sql`` block, or start with
``CANNOT_ANSWER`` and a reason; anything else is refused as "no single SQL
block". ``escape`` writes control and format characters, and the Unicode line
and paragraph separators, in model-written text (and in values, which come from
OTX) as visible escapes, so nothing a model or a feed wrote can move the
terminal's cursor, clear it, retitle it or break a line in a report.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cyber_threat_pipeline.analyst import schema
from cyber_threat_pipeline.analyst.guard import ROW_CAP, Refusal

EXPLAIN_ROWS = 50
TEXT_CUT = 200
CANNOT_ANSWER = "CANNOT_ANSWER"

_RULES = f"""\
You answer questions about a threat-intelligence pipeline's data by writing SQL.

Rules:
- Write one PostgreSQL query that runs on PostgreSQL 15 or later: SELECT, or WITH ... SELECT.
- Read only the 11 tables below, written marts.<name>, and only the columns listed.
- Break ties explicitly in ORDER BY, and LIMIT a list to what the question asks.
  Results are cut at {ROW_CAP:,} rows.
- If these tables can't answer the question, reply {CANNOT_ANSWER} and one sentence saying why.
- Otherwise reply with one fenced ```sql block holding the query, and nothing else.

Tables:
"""

_EXPLAIN = """\
Explain the result of a SQL query to the person who asked the question, in 2 to 5 plain
sentences. Use only numbers that appear in the rows below. If the result is empty, or cut
at the row cap, say so.
"""

_SQL_BLOCK = re.compile(r"```sql[ \t]*\n(.*?)```", re.DOTALL)
_KEEP = frozenset("\n\t")
# Control, format, line separator and paragraph separator characters.
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


@dataclass(frozen=True)
class CannotAnswer:
    """The model said the marts can't answer the question."""

    reason: str


def sql_prompt(question: str) -> str:
    """The SQL-writing prompt for one question."""
    return f"{_RULES}{schema.card()}\nQuestion: {question}\n"


def extract_sql(reply: str) -> str | CannotAnswer | Refusal:
    """The SQL in a reply, the model's CANNOT_ANSWER reason, or a refusal."""
    text = reply.strip()
    if text.startswith(CANNOT_ANSWER):
        reason = text[len(CANNOT_ANSWER) :].strip(" \t\r\n:-")
        return CannotAnswer(reason or "(no reason given)")
    blocks = _SQL_BLOCK.findall(reply)
    if len(blocks) != 1 or reply.count("```sql") != 1:
        return Refusal("no single SQL block")
    return str(blocks[0]).strip()


def explanation_prompt(
    question: str,
    sql: str,
    columns: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    cut: bool,
) -> str:
    """The explanation prompt: the question, the SQL, and at most EXPLAIN_ROWS rows."""
    return f"{_EXPLAIN}\nQuestion: {question}\n\nSQL:\n{sql}\n\n" + rows_text(
        columns, rows, cut=cut
    )


def rows_text(columns: Sequence[str], rows: Sequence[Sequence[Any]], *, cut: bool) -> str:
    """The row count, whether the result was cut, and at most EXPLAIN_ROWS rows as a table."""
    if cut:
        count = f"More than {ROW_CAP:,} rows: the result was cut at the row cap."
    elif not rows:
        count = "No rows."
    else:
        count = f"{len(rows):,} rows."
    shown = rows[:EXPLAIN_ROWS]
    table = "\n".join(" | ".join(_cell(value) for value in row) for row in (columns, *shown))
    if len(rows) > len(shown):
        count += f" The first {len(shown)} are shown."
    return f"{count}\n" + (f"\nRows:\n{table}\n" if rows else "")


def _cell(value: Any) -> str:
    text = "NULL" if value is None else str(value)
    return text if len(text) <= TEXT_CUT else text[:TEXT_CUT] + "..."


def escape(text: str, *, keep_newlines: bool = True) -> str:
    """``text`` with control and format characters written as visible escapes."""
    keep = _KEEP if keep_newlines else frozenset()
    return "".join(
        char
        if char in keep or unicodedata.category(char) not in _ESCAPED_CATEGORIES
        else _escaped(char)
        for char in text
    )


def _escaped(char: str) -> str:
    code = ord(char)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"
