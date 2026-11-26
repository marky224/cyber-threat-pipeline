"""The analyst's runner against Postgres, as a test login in analyst_ro.

Each query here is sent straight to the runner, past the guard, to prove the
runner's own walls: the extended protocol (one statement), the timeout, the
READ ONLY transaction, the session check and the cap + 1 stream read. The test
login and the probe table and sequence are test doubles made in the throwaway
database; the module drops all three when it ends.

DB-integration (gated on NEON_DATABASE_URL, see conftest.py).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from psycopg.pq import TransactionStatus

from cyber_threat_pipeline.analyst import runner
from cyber_threat_pipeline.analyst.guard import ROW_CAP

_LOGIN = "analyst_test_login"
_PASSWORD = "analyst-test-only"
_PROBE = "marts.analyst_runner_probe"
_PROBE_SEQ = "marts.analyst_runner_probe_seq"


@pytest.fixture(scope="module")
def login_url(_pg_session: psycopg.Connection, pg_url: str) -> Iterator[str]:
    """A LOGIN role in analyst_ro, and probes it may write outside a READ ONLY transaction."""
    cur = _pg_session.cursor()
    cur.execute(f"drop role if exists {_LOGIN}")
    cur.execute(f"create role {_LOGIN} login password '{_PASSWORD}' in role analyst_ro")
    cur.execute(f"create table {_PROBE} (x int)")
    cur.execute(f"create sequence {_PROBE_SEQ}")
    cur.execute(f"grant select, insert, update on {_PROBE} to analyst_ro")
    cur.execute(f"grant usage, update on sequence {_PROBE_SEQ} to analyst_ro")
    try:
        yield make_conninfo(pg_url, user=_LOGIN, password=_PASSWORD)
    finally:
        cur.execute(f"drop table if exists {_PROBE}")
        cur.execute(f"drop sequence if exists {_PROBE_SEQ}")
        cur.execute(f"drop role if exists {_LOGIN}")


@pytest.fixture()
def login(login_url: str) -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    conn = runner.connect(login_url)
    try:
        yield conn
    finally:
        conn.close()


def _usable(conn: psycopg.Connection[tuple[Any, ...]]) -> None:
    assert conn.info.transaction_status is TransactionStatus.IDLE
    assert runner.run(conn, "select 1").rows == [(1,)]


def test_login_session_passes_the_check(login: psycopg.Connection[tuple[Any, ...]]) -> None:
    runner.check_session(login)


def test_owner_session_is_refused_before_any_query(pg_url: str) -> None:
    with runner.connect(pg_url) as conn, pytest.raises(runner.SessionRefused, match="raw"):
        runner.check_session(conn)


def test_two_statements_fail_at_the_server(login: psycopg.Connection[tuple[Any, ...]]) -> None:
    with pytest.raises(runner.QueryFailed) as failed:
        runner.run(login, "select 1; select 2")
    assert failed.value.sqlstate == "42601"
    _usable(login)


def test_pg_sleep_past_the_timeout_is_cancelled(
    monkeypatch: pytest.MonkeyPatch, login: psycopg.Connection[tuple[Any, ...]]
) -> None:
    monkeypatch.setattr(runner, "STATEMENT_TIMEOUT", "200ms")
    with pytest.raises(runner.QueryFailed) as failed:
        runner.run(login, "select pg_sleep(2)")
    assert failed.value.timed_out
    _usable(login)


@pytest.mark.parametrize(
    "sql",
    [
        pytest.param(f"insert into {_PROBE} values (1)", id="write"),
        pytest.param("create temp table analyst_runner_tmp (x int)", id="ddl"),
        pytest.param(f"select x from {_PROBE} for update", id="for-update"),
        pytest.param(f"select nextval('{_PROBE_SEQ}')", id="nextval"),
    ],
)
def test_write_fails_in_the_read_only_transaction(
    login: psycopg.Connection[tuple[Any, ...]], sql: str
) -> None:
    with pytest.raises(runner.QueryFailed) as failed:
        runner.run(login, sql)
    assert failed.value.sqlstate == "25006"  # read_only_sql_transaction
    _usable(login)


def test_a_rendering_with_no_limit_yields_cap_plus_one_rows_and_a_cut_flag(
    login: psycopg.Connection[tuple[Any, ...]],
) -> None:
    result = runner.run(login, "select g from generate_series(1, 5000) g")
    assert result.columns == ("g",)
    assert len(result.rows) == ROW_CAP + 1
    assert result.rows[-1] == (ROW_CAP + 1,)
    assert result.cut
    _usable(login)


def test_a_result_within_the_cap_is_not_cut(login: psycopg.Connection[tuple[Any, ...]]) -> None:
    result = runner.run(login, f"select g from generate_series(1, {ROW_CAP}) g")
    assert (len(result.rows), result.cut) == (ROW_CAP, False)
    empty = runner.run(login, "select 1 as x where false")
    assert (empty.columns, empty.rows, empty.cut) == ((), [], False)


@pytest.mark.parametrize(
    ("repeatable_read", "isolation"), [(False, "read committed"), (True, "repeatable read")]
)
def test_the_transaction_is_read_only_with_its_local_limits(
    login: psycopg.Connection[tuple[Any, ...]], repeatable_read: bool, isolation: str
) -> None:
    result = runner.run(
        login,
        "select current_setting('transaction_isolation'), current_setting('transaction_read_only'),"
        " current_setting('statement_timeout'), current_setting('search_path'),"
        " current_setting('standard_conforming_strings')",
        repeatable_read=repeatable_read,
    )
    assert result.rows == [(isolation, "on", "5s", "pg_catalog", "on")]
    # SET LOCAL ends with the rollback.
    row = login.execute("select current_setting('statement_timeout')").fetchone()
    assert row == ("0",)
