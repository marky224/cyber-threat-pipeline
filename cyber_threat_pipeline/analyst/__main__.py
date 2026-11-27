"""The threat-data analyst's command line: ``python -m cyber_threat_pipeline.analyst <command>``.

- ``ask "<question>"`` (``make ask Q="..."``): one question goes to Grok
  (``ANALYST_GROK_MODEL``, at temperature 0) for one SQL query; the guard checks
  it; the runner executes the guard's rendering through ``ANALYST_DATABASE_URL``
  (never ``NEON_DATABASE_URL``); then Grok explains the rows. The SQL call ends
  before the query's transaction opens, and the explanation call starts after
  its rollback. It prints the SQL, up to 20 rows with the row count, and the
  explanation, then each call's stop reason, tokens and dollars, and the total.
- ``eval --provider grok|claude --record 0|1`` (``make analyst-eval``): every
  gold question through that provider (Grok at ``ANALYST_GROK_MODEL``, Claude at
  the registry's default model), each explanation graded by Claude Haiku, and
  the reports written to ``analyst-evals/`` (``evaluate.py``). It needs
  ``ANALYST_DATABASE_URL``, the provider's key and ``ANTHROPIC_API_KEY``.
- ``check`` (``make analyst-check``): the offline check after ``dbt build``,
  on ``NEON_DATABASE_URL`` from the environment (``check.py``).

Every model-written string (the SQL, a CANNOT_ANSWER reason, a refusal's reason,
the explanation, column names) and every value is printed with control
characters escaped. sqlglot's warning when it falls back to parsing a statement
as a generic command holds the statement's text, so its logger is kept below
WARNING.

Exit codes: ``ask`` 0 when an answer is printed, 1 on a refusal, a
CANNOT_ANSWER or a query error; ``eval`` 0 once the run completes, whatever the
accuracy; ``check`` 0 when every check passes, 1 when one fails. All three exit
2 on a setup error (a missing setting or key, no connection, an unreadable gold
file or a gold query the guard refuses, a session that isn't analyst_ro's, or a
database error outside a checked query, such as a lost connection), printed as
one ``setup error:`` line. What a database failure prints depends on where it
happens:

- a URL libpq can't parse: a fixed line that never quotes it, since libpq's parse
  error quotes the token it can't read, which can be the password;
- a well-formed URL that fails to connect: libpq's first line (``_connect``),
  which names the host and port (and the user, for a refused login), not the
  password;
- a query error: the server's message, or libpq's first line when the
  connection broke during the query (``runner._message``). ``ask`` prints it
  after ``Query error:``, the eval records it as that question's reason, and the
  check prints it in that query's failure line;
- any other database error that reaches ``main``: its SQLSTATE and the server's
  message, or one fixed line when it has no SQLSTATE, as for a lost connection
  (``_database_error``).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Callable, Sequence
from decimal import Decimal
from functools import partial
from pathlib import Path
from typing import Any

import psycopg
from psycopg.conninfo import conninfo_to_dict
from pydantic import SecretStr, ValidationError

from cyber_threat_pipeline.analysis import judge, providers
from cyber_threat_pipeline.analysis.completion import Completion
from cyber_threat_pipeline.analyst import check, evaluate, guard, prices, prompt, runner
from cyber_threat_pipeline.core.config import Settings

MAX_TOKENS = 4000
TEMPERATURE = 0
SHOWN_ROWS = 20
EVAL_DIR = Path("analyst-evals")
EVAL_PROVIDERS = ("grok", "claude")

_esc = prompt.escape


class _SetupError(Exception):
    """A missing setting or key, no connection, an unreadable gold file or a refused session."""


def main(argv: Sequence[str] | None = None) -> int:
    logging.getLogger("sqlglot").setLevel(logging.ERROR)
    parser = argparse.ArgumentParser(prog="python -m cyber_threat_pipeline.analyst")
    commands = parser.add_subparsers(dest="command", required=True)
    ask_parser = commands.add_parser("ask", help="answer one plain-English question")
    ask_parser.add_argument("question")
    eval_parser = commands.add_parser("eval", help="run the gold set through one provider")
    eval_parser.add_argument("--provider", choices=EVAL_PROVIDERS, default="grok")
    eval_parser.add_argument("--record", choices=("0", "1"), default="0")
    commands.add_parser("check", help="the offline check after dbt build")
    args = parser.parse_args(argv)
    try:
        if args.command == "ask":
            return ask(args.question)
        if args.command == "eval":
            return run_eval(args.provider, record=args.record == "1")
        return run_check()
    except (_SetupError, evaluate.GoldFileError) as error:
        message = str(error)
    except psycopg.Error as error:
        message = _database_error(error)
    print(f"setup error: {_esc(message)}", file=sys.stderr)
    return 2


def _database_error(error: psycopg.Error) -> str:
    """One line for a database error that reaches ``main``, outside a checked query.

    A server error gives its SQLSTATE and the server's message; an error with no
    SQLSTATE, as for a lost connection, gives one fixed line instead of libpq's text.
    """
    if error.sqlstate:
        # A server error: its message is the server's, never the connection string.
        lines = (error.diag.message_primary or str(error)).splitlines()
        return f"database error: {error.sqlstate}: {lines[0] if lines else type(error).__name__}"
    return f"database error: {type(error).__name__}: the connection failed or was lost"


def ask(question: str) -> int:
    """Answer one question; return the exit code."""
    cfg = _settings()
    url = _required(cfg.analyst_database_url, "ANALYST_DATABASE_URL")
    complete = _completer(cfg, "grok")
    with _connect(url, "ANALYST_DATABASE_URL") as conn:
        _check_session(conn)
        return _answer(question, conn, complete)


def run_eval(provider: str, *, record: bool) -> int:
    """Run the gold set through one provider and write the reports; return the exit code."""
    cfg = _settings()
    url = _required(cfg.analyst_database_url, "ANALYST_DATABASE_URL")
    complete = _completer(cfg, provider)
    _required(cfg.anthropic_api_key, "ANTHROPIC_API_KEY")  # the judge's
    questions = _gold()
    with _connect(url, "ANALYST_DATABASE_URL") as conn:
        _check_session(conn)
        result = evaluate.evaluate(
            conn,
            questions,
            provider=provider,
            write_sql=lambda q: complete(prompt.sql_prompt(q.question)),
            explain=complete,
            judge=lambda q, sql, rows, text: judge.judge_answer(q, sql, rows, text, cfg),
        )
    written = evaluate.write_reports(result, EVAL_DIR, record=record)
    totals = evaluate.summary(result)
    dollars = totals["dollars"]
    print(
        f"{provider}: {totals['passed']}/{totals['total']} ({totals['percent']:.1f}%), "
        f"meets the {evaluate.PASS_BAR}% bar: {'yes' if totals['meets_bar'] else 'no'}"
    )
    print(
        f"dollars: analyst {dollars['analyst'].text()}, judge {dollars['judge'].text()}, "
        f"total {dollars['total'].text()}"
    )
    for path in written[:2]:
        print(f"report: {path}")
    return 0


def run_check() -> int:
    """The offline check (check.py); return the exit code."""
    url = os.environ.get("NEON_DATABASE_URL")
    if not url:
        raise _SetupError("NEON_DATABASE_URL is not set")
    questions = _gold()
    with _connect(url, "NEON_DATABASE_URL") as conn:
        try:
            failures = check.run(conn, questions)
        except runner.SessionRefused as error:
            raise _SetupError(f"session refused: {error}") from None
    for failure in failures:
        print(f"FAIL {_esc(failure, keep_newlines=False)}")
    print("analyst-check: " + (f"{len(failures)} failures" if failures else "all checks passed"))
    return 1 if failures else 0


def _settings() -> Settings:
    try:
        return Settings()
    except ValidationError as error:
        missing = ", ".join(str(e["loc"][0]) for e in error.errors())
        raise _SetupError(f"settings are missing or invalid: {missing}") from None


def _required(secret: SecretStr | None, name: str) -> str:
    if secret is None:
        raise _SetupError(f"{name} is not set")
    return secret.get_secret_value()


def _completer(cfg: Settings, name: str) -> Callable[[str], Completion]:
    """The provider's completion call with its key, model and limits bound."""
    provider = providers.resolve(name)
    if provider.complete is None:
        raise _SetupError(f"the {name} provider has no completion call")
    key = _required(getattr(cfg, provider.credential_attr), provider.credential_attr.upper())
    if name == "grok":
        return partial(
            provider.complete,
            api_key=key,
            model=cfg.analyst_grok_model,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
    # Claude sends no sampling parameters (claude.py).
    return partial(
        provider.complete, api_key=key, model=provider.default_model, max_tokens=MAX_TOKENS
    )


def _gold() -> list[evaluate.GoldQuestion]:
    try:
        return evaluate.load_gold()
    except evaluate.GoldFileError as error:
        raise _SetupError(str(error)) from None


def _connect(url: str, name: str) -> psycopg.Connection[tuple[Any, ...]]:
    try:
        conninfo_to_dict(url)
    except psycopg.Error:
        # libpq's message quotes the token it can't read, which can be the password.
        raise _SetupError(
            f"cannot connect: {name} is not a valid connection URL"
            " (percent-encode the password's special characters)"
        ) from None
    try:
        return runner.connect(url)
    except psycopg.Error as error:
        raise _SetupError(f"cannot connect: {str(error).splitlines()[0]}") from None


def _check_session(conn: Any) -> None:
    try:
        runner.check_session(conn)
    except runner.SessionRefused as error:
        raise _SetupError(f"session refused: {error}") from None


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
    costs = [prices.dollars(call) for _, call in calls]
    for (name, call), cost in zip(calls, costs, strict=True):
        print(
            f"{name}: {_esc(call.model)}, stop {_esc(str(call.stop_reason))}, tokens in "
            f"{_count(call.input_tokens)} (cached {_count(call.cached_input_tokens)}), "
            f"out {_count(call.output_tokens)} (reasoning {_count(call.reasoning_tokens)}), "
            f"{_esc(prices.describe(cost))}"
        )
    priced = [cost for cost in costs if not isinstance(cost, prices.Unpriced)]
    total = evaluate.Dollars(sum(priced, start=Decimal(0)), len(priced) == len(costs))
    print(f"total: {total.text()}")
    return code


def _count(tokens: int | None) -> str:
    return "unreported" if tokens is None else f"{tokens:,}"


if __name__ == "__main__":
    raise SystemExit(main())
