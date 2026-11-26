"""The analyst's read-only runner: one checked query, in one READ ONLY transaction.

The runner connects with ``ANALYST_DATABASE_URL`` only (the caller passes it),
never ``NEON_DATABASE_URL``. ``check_session`` refuses a session whose
``current_user`` isn't a member of ``analyst_ro``, or has USAGE on ``raw`` or
``pipeline``; a superuser or the owner fails the second test, so an owner URL is
refused before any query.

``run`` opens ``BEGIN READ ONLY`` (``REPEATABLE READ`` for the eval), sets three
``SET LOCAL`` limits, sends the guard's rendering by the extended protocol
(``cursor.stream(..., binary=True)``), where the server refuses a second
command, reads at most ``cap + 1`` rows as the server sends them, and rolls
back. The simple protocol, which ``execute()`` uses for a query with no
parameters and text results, runs every statement in the text, and a
client-side cursor receives the whole result before ``fetchmany`` slices it, so
neither is used. No model call happens inside the transaction: the caller makes
the SQL call before ``run`` and the explanation call after it.

``transaction`` is the same transaction for several reads in one snapshot: the
eval runs a question's gold query, then the model's, in one ``REPEATABLE READ``
transaction, so both see the same rows and the same ``now()``.

Statements are never prepared (``prepare_threshold=None``) and every limit is
``SET LOCAL``, so the runner works through a transaction-mode pooler.
"""

from __future__ import annotations

from collections.abc import Callable, Generator, Iterator
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from typing import Any, cast

import psycopg

from cyber_threat_pipeline.analyst.guard import ROW_CAP

STATEMENT_TIMEOUT = "5s"
CONNECT_TIMEOUT_SECONDS = 30  # Neon's cold start
QUERY_CANCELED = "57014"


@dataclass(frozen=True)
class Result:
    """The rows read, at most ``cap + 1``; ``cut`` when there were more than ``cap``.

    ``columns`` is empty when there are no rows: psycopg's stream sets no
    description until a row arrives.
    """

    columns: tuple[str, ...]
    rows: list[tuple[Any, ...]]
    cut: bool


class SessionRefused(Exception):
    """The connection's role isn't a plain member of analyst_ro."""


class QueryFailed(Exception):
    """Postgres refused or cancelled the query."""

    def __init__(self, sqlstate: str | None, message: str) -> None:
        super().__init__(f"{sqlstate}: {message}")
        self.sqlstate = sqlstate
        self.message = message

    @property
    def timed_out(self) -> bool:
        return self.sqlstate == QUERY_CANCELED


def connect(url: str) -> psycopg.Connection[tuple[Any, ...]]:
    """Open the analyst's connection (autocommit; the runner opens its own transaction)."""
    return psycopg.connect(
        url,
        autocommit=True,
        prepare_threshold=None,
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
    )


def check_session(conn: psycopg.Connection[tuple[Any, ...]]) -> None:
    """Refuse a session that isn't a member of analyst_ro, or can use raw or pipeline."""
    row = conn.execute(
        "select current_user,"
        " exists (select 1 from pg_roles where rolname = 'analyst_ro')"
        "   and pg_has_role(current_user, 'analyst_ro', 'member'),"
        " has_schema_privilege(current_user, 'raw', 'usage'),"
        " has_schema_privilege(current_user, 'pipeline', 'usage')",
        prepare=False,
    ).fetchone()
    assert row is not None
    user, member, raw, pipeline = row
    if not member:
        raise SessionRefused(f"{user} is not a member of analyst_ro")
    if raw or pipeline:
        raise SessionRefused(f"{user} can use the raw or pipeline schema")


def run(
    conn: psycopg.Connection[tuple[Any, ...]],
    sql: str,
    *,
    cap: int = ROW_CAP,
    repeatable_read: bool = False,
) -> Result:
    """Run one rendering in a READ ONLY transaction; read at most cap + 1 rows; roll back."""
    with transaction(conn, cap=cap, repeatable_read=repeatable_read) as read:
        return read(sql)


@contextmanager
def transaction(
    conn: psycopg.Connection[tuple[Any, ...]],
    *,
    cap: int = ROW_CAP,
    repeatable_read: bool = False,
) -> Iterator[Callable[[str], Result]]:
    """One READ ONLY transaction with its limits; yields a read that runs one rendering.

    Each read sends its rendering by the extended protocol and reads at most
    cap + 1 rows. The transaction is rolled back when the block ends.
    """
    isolation = " ISOLATION LEVEL REPEATABLE READ" if repeatable_read else ""
    conn.execute(f"BEGIN{isolation} READ ONLY", prepare=False)
    try:
        try:
            for statement in (
                f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'",
                "SET LOCAL search_path = pg_catalog",
                "SET LOCAL standard_conforming_strings = on",
            ):
                conn.execute(statement, prepare=False)
        except psycopg.Error as error:
            raise QueryFailed(error.sqlstate, _message(error)) from None
        yield lambda sql: _read(conn, sql, cap)
    finally:
        _rollback(conn)


def _read(conn: psycopg.Connection[tuple[Any, ...]], sql: str, cap: int) -> Result:
    rows: list[tuple[Any, ...]] = []
    try:
        with conn.cursor() as cur:
            stream = cast(Generator[tuple[Any, ...], None, None], cur.stream(sql, binary=True))
            with closing(stream):
                for row in stream:
                    rows.append(row)
                    if len(rows) > cap:
                        break
                columns = tuple(column.name for column in cur.description or ())
    except psycopg.Error as error:
        raise QueryFailed(error.sqlstate, _message(error)) from None
    return Result(columns=columns, rows=rows, cut=len(rows) > cap)


def _message(error: psycopg.Error) -> str:
    return error.diag.message_primary or str(error).splitlines()[0]


def _rollback(conn: psycopg.Connection[tuple[Any, ...]]) -> None:
    if conn.closed:
        return
    # If the connection broke, the caller's error says why.
    with suppress(psycopg.Error):
        conn.execute("ROLLBACK", prepare=False)
