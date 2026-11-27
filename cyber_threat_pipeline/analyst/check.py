"""``make analyst-check``: the analyst's offline check, run after ``dbt build``.

CI's dbt job runs it, and so does local proof on a throwaway postgres:15. It
connects with ``NEON_DATABASE_URL`` from the environment, the owner of that
database (``Settings`` isn't built, so ``OTX_API_KEY`` isn't needed), and checks:

1. ``analyst_ro`` can SELECT exactly the 11 marts and nothing else in
   ``marts``, and has no USAGE on ``raw``, ``pipeline`` or ``dbt_test__audit``;
2. the schema card's columns and types equal ``information_schema.columns``
   for the 11 marts, less the column the card leaves out;
3. then as ``analyst_ro`` (``SET ROLE``, so the runner's session check passes),
   every gold query passes the guard, and its rendering returns the same rows
   as the gold text, in one snapshot;
4. a gold-echo eval scores 100%. The gold-echo is a test double: it answers
   each question with that question's gold SQL, and skips the explanation and
   the judge. It proves the eval loop, the guard, the runner and the result
   match agree on every gold query.

It prints what it checked, and each failure. ``run`` returns the failures.
"""

from __future__ import annotations

from typing import Any

import psycopg

from cyber_threat_pipeline.analysis.completion import Completion
from cyber_threat_pipeline.analyst import guard, runner
from cyber_threat_pipeline.analyst.compare import compare
from cyber_threat_pipeline.analyst.evaluate import GoldQuestion, evaluate, summary
from cyber_threat_pipeline.analyst.schema import CARD_LEAVES_OUT, MART_NAMES, MART_SCHEMA, MARTS

_ROLE = "analyst_ro"
_CLOSED_SCHEMAS = ("raw", "pipeline", "dbt_test__audit")


def run(conn: psycopg.Connection[tuple[Any, ...]], questions: list[GoldQuestion]) -> list[str]:
    """Run the four checks as the database's owner; return every failure found."""
    failures = _role(conn) + _card(conn)
    conn.execute(f"SET ROLE {_ROLE}", prepare=False)
    runner.check_session(conn)
    failures += _renderings(conn, questions)
    failures += _gold_echo(conn, questions)
    return failures


def _role(conn: psycopg.Connection[tuple[Any, ...]]) -> list[str]:
    # Readable means SELECT on the table or on any of its columns: has_table_privilege
    # doesn't see a column-level grant.
    rows = conn.execute(
        "select c.relname, has_any_column_privilege(%s, c.oid, 'select')"
        " from pg_class c join pg_namespace n on n.oid = c.relnamespace"
        " where n.nspname = %s and c.relkind in ('r', 'v', 'm', 'p', 'f')",
        (_ROLE, MART_SCHEMA),
        prepare=False,
    ).fetchall()
    present = {name for name, _ in rows}
    readable = {name for name, can in rows if can}
    failures = [f"mart missing from {MART_SCHEMA}: {name}" for name in sorted(MART_NAMES - present)]
    failures += [f"{_ROLE} can read {MART_SCHEMA}.{name}" for name in sorted(readable - MART_NAMES)]
    failures += [
        f"{_ROLE} cannot read {MART_SCHEMA}.{name}"
        for name in sorted((MART_NAMES & present) - readable)
    ]
    open_schemas = conn.execute(
        "select nspname from pg_namespace"
        " where nspname = any(%s) and has_schema_privilege(%s, oid, 'usage') order by nspname",
        (list(_CLOSED_SCHEMAS), _ROLE),
        prepare=False,
    ).fetchall()
    failures += [f"{_ROLE} has USAGE on schema {name}" for (name,) in open_schemas]
    print(f"role: {len(readable & MART_NAMES)} of {len(MART_NAMES)} marts readable by {_ROLE}")
    return failures


def _card(conn: psycopg.Connection[tuple[Any, ...]]) -> list[str]:
    rows = conn.execute(
        "select table_name, column_name, data_type from information_schema.columns"
        " where table_schema = %s and table_name = any(%s)",
        (MART_SCHEMA, sorted(MART_NAMES)),
        prepare=False,
    ).fetchall()
    database = {(t, c, d) for t, c, d in rows if (t, c) not in CARD_LEAVES_OUT}
    card = {(m.name, c.name, c.type) for m in MARTS for c in m.columns}
    failures = [
        f"schema card lacks {t}.{c} ({d}), which the database has"
        for t, c, d in sorted(database - card)
    ]
    failures += [
        f"schema card has {t}.{c} ({d}), which the database lacks"
        for t, c, d in sorted(card - database)
    ]
    print(f"schema card: {len(card)} columns checked against information_schema.columns")
    return failures


def _renderings(
    conn: psycopg.Connection[tuple[Any, ...]], questions: list[GoldQuestion]
) -> list[str]:
    failures: list[str] = []
    for q in questions:
        checked = guard.check(q.sql)
        if isinstance(checked, guard.Refusal):
            failures.append(f"{q.id}: the guard refuses the gold query: {checked.reason}")
            continue
        try:
            with runner.transaction(conn, repeatable_read=True) as read:
                text = read(q.sql)
                # A read cut at cap + 1 can leave the transaction aborted (psycopg
                # cancels the rest of the query), so nothing more is read after one.
                rendering = None if text.cut else read(checked.sql)
        except runner.QueryFailed as error:
            failures.append(f"{q.id}: {error.sqlstate}: {error.message}")
            continue
        if rendering is None or rendering.cut:
            failures.append(f"{q.id}: a result is cut at the row cap")
            continue
        verdict = compare(text.rows, rendering.rows, ordered=q.ordered)
        if not verdict.passed:
            failures.append(
                f"{q.id}: the rendering's rows differ from the gold text's: {verdict.reason}"
            )
    print(f"renderings: {len(questions)} gold queries run as the guard renders them")
    return failures


def gold_echo(q: GoldQuestion) -> Completion:
    """The gold-echo test double's SQL call: the question's own gold SQL."""
    return Completion(
        text=f"```sql\n{q.sql}\n```",
        model="gold-echo",
        stop_reason=None,
        input_tokens=None,
        cached_input_tokens=None,
        output_tokens=None,
        reasoning_tokens=None,
        raw={},
    )


def _gold_echo(
    conn: psycopg.Connection[tuple[Any, ...]], questions: list[GoldQuestion]
) -> list[str]:
    result = evaluate(conn, questions, provider="gold-echo", write_sql=gold_echo)
    totals = summary(result)
    print(f"gold-echo eval: {totals['passed']}/{totals['total']} ({totals['percent']:.1f}%)")
    return [f"gold-echo {a.id}: {a.reason}" for a in result.answers if not a.passed]
