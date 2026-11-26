"""The threat-data analyst's command line: ``python -m cyber_threat_pipeline.analyst ask "<q>"``.

``make ask Q="..."`` runs it. One question goes to Grok (``ANALYST_GROK_MODEL``,
at temperature 0) for one SQL query; the guard checks it; the runner executes
the guard's rendering through ``ANALYST_DATABASE_URL`` (never
``NEON_DATABASE_URL``); then Grok explains the rows. The SQL call ends before
the query's transaction opens, and the explanation call starts after its
rollback.

It prints the SQL, up to 20 rows with the row count, and the explanation, then
each call's stop reason and tokens. Every model-written string (the SQL, a
CANNOT_ANSWER reason, a refusal's reason, the explanation, column names) and
every value is printed with control characters escaped. sqlglot's warning when
it falls back to parsing a statement as a generic command holds the statement's
text, so its logger is kept below WARNING.

Exit codes: 0 when an answer is printed; 1 on a refusal, a CANNOT_ANSWER or a
query error; 2 on a setup error (a missing setting or key, no connection, or a
session that isn't analyst_ro's).
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable, Sequence
from functools import partial
from typing import Any

import psycopg
from pydantic import ValidationError

from cyber_threat_pipeline.analysis import providers
from cyber_threat_pipeline.analysis.completion import Completion
from cyber_threat_pipeline.analyst import guard, prompt, runner
from cyber_threat_pipeline.core.config import Settings

MAX_TOKENS = 4000
TEMPERATURE = 0
SHOWN_ROWS = 20

_esc = prompt.escape


def main(argv: Sequence[str] | None = None) -> int:
    logging.getLogger("sqlglot").setLevel(logging.ERROR)
    parser = argparse.ArgumentParser(prog="python -m cyber_threat_pipeline.analyst")
    commands = parser.add_subparsers(dest="command", required=True)
    ask_parser = commands.add_parser("ask", help="answer one plain-English question")
    ask_parser.add_argument("question")
    args = parser.parse_args(argv)
    return ask(args.question)


def ask(question: str) -> int:
    """Answer one question; return the exit code."""
    try:
        cfg = Settings()
    except ValidationError as error:
        missing = ", ".join(str(e["loc"][0]) for e in error.errors())
        return _setup_error(f"settings are missing or invalid: {missing}")
    if cfg.analyst_database_url is None:
        return _setup_error("ANALYST_DATABASE_URL is not set")
    if cfg.xai_api_key is None:
        return _setup_error("XAI_API_KEY is not set")
    provider = providers.resolve("grok")
    if provider.complete is None:
        return _setup_error("the grok provider has no completion call")
    complete: Callable[[str], Completion] = partial(
        provider.complete,
        api_key=cfg.xai_api_key.get_secret_value(),
        model=cfg.analyst_grok_model,
        max_tokens=MAX_TOKENS,
        temperature=TEMPERATURE,
    )
    try:
        conn = runner.connect(cfg.analyst_database_url.get_secret_value())
    except psycopg.Error as error:
        return _setup_error(f"cannot connect: {str(error).splitlines()[0]}")
    with conn:
        try:
            runner.check_session(conn)
        except runner.SessionRefused as error:
            return _setup_error(f"session refused: {error}")
        return _answer(question, conn, complete)


def _answer(question: str, conn: Any, complete: Callable[[str], Completion]) -> int:
    calls: list[tuple[str, Completion]] = []
    sql_call = complete(prompt.sql_prompt(question))
    calls.append(("sql", sql_call))
    reply = prompt.extract_sql(sql_call.text)
    if isinstance(reply, prompt.CannotAnswer):
        print(f"Cannot answer: {_esc(reply.reason)}")
        return _done(1, calls)
    if isinstance(reply, guard.Refusal):
        print(f"Refused: {_esc(reply.reason)}")
        return _done(1, calls)
    checked = guard.check(reply)
    if isinstance(checked, guard.Refusal):
        print(f"Refused: {_esc(checked.reason)}")
        print(f"The model's SQL:\n{_esc(reply)}")
        return _done(1, calls)
    print(f"SQL:\n{_esc(checked.sql)}\n")
    try:
        result = runner.run(conn, checked.sql)
    except runner.QueryFailed as error:
        if error.timed_out:
            print(f"Query error: cancelled after {runner.STATEMENT_TIMEOUT}")
        else:
            print(f"Query error: {error.sqlstate}: {_esc(error.message)}")
        return _done(1, calls)
    _print_rows(result)
    explanation = complete(
        prompt.explanation_prompt(
            question, checked.sql, result.columns, result.rows, cut=result.cut
        )
    )
    calls.append(("explanation", explanation))
    print(f"\n{_esc(explanation.text)}")
    return _done(0, calls)


def _print_rows(result: runner.Result) -> None:
    if not result.rows:
        print("no rows")
        return
    print(" | ".join(_esc(name, keep_newlines=False) for name in result.columns))
    for row in result.rows[:SHOWN_ROWS]:
        print(" | ".join(_value(value) for value in row))
    if result.cut:
        print(f"(truncated at {guard.ROW_CAP:,} rows)")
    else:
        shown = min(len(result.rows), SHOWN_ROWS)
        print(
            f"({len(result.rows):,} rows"
            + (f", {shown} shown)" if shown < len(result.rows) else ")")
        )


def _value(value: Any) -> str:
    return "NULL" if value is None else _esc(str(value), keep_newlines=False)


def _done(code: int, calls: list[tuple[str, Completion]]) -> int:
    print()
    for name, call in calls:
        print(
            f"{name}: {_esc(call.model)}, stop {_esc(str(call.stop_reason))}, tokens in "
            f"{_count(call.input_tokens)} (cached {_count(call.cached_input_tokens)}), "
            f"out {_count(call.output_tokens)} (reasoning {_count(call.reasoning_tokens)})"
        )
    return code


def _count(tokens: int | None) -> str:
    return "unreported" if tokens is None else f"{tokens:,}"


def _setup_error(message: str) -> int:
    print(f"setup error: {_esc(message)}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
