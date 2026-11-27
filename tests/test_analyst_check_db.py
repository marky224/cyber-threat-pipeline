"""cyber_threat_pipeline.analyst.check against Postgres: the parts the test database can show.

The test database has the schemas and roles (conftest applies sql/) but no dbt
build, so the 11 marts are missing here; ``make analyst-check`` after
``dbt build`` is the full check. A probe table in ``marts`` is a test double
made and dropped by the test that uses it.

DB-integration (gated on NEON_DATABASE_URL, see conftest.py).
"""

from __future__ import annotations

from collections.abc import Iterator
from decimal import Decimal
from typing import Any

import psycopg
import pytest

from cyber_threat_pipeline.analyst import check, runner
from cyber_threat_pipeline.analyst.evaluate import GoldQuestion

_PROBE = "analyst_check_probe"


@pytest.fixture()
def conn(pg_url: str) -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    connection = runner.connect(pg_url)
    try:
        yield connection
    finally:
        connection.close()


def test_a_column_grant_outside_the_marts_is_a_failure(
    _pg_session: psycopg.Connection, conn: psycopg.Connection[tuple[Any, ...]]
) -> None:
    cur = _pg_session.cursor()
    cur.execute(f"drop table if exists marts.{_PROBE}")
    cur.execute(f"create table marts.{_PROBE} (a int, b int)")
    try:
        # A column grant: has_table_privilege says no, yet the role can read column a.
        cur.execute(f"grant select (a) on marts.{_PROBE} to analyst_ro")
        assert f"analyst_ro can read marts.{_PROBE}" in check._role(conn)
    finally:
        cur.execute(f"drop table if exists marts.{_PROBE}")


def test_a_mart_readable_by_some_columns_only_is_a_failure(
    _pg_session: psycopg.Connection, conn: psycopg.Connection[tuple[Any, ...]]
) -> None:
    # A probe table named like a mart (the test database has no dbt build). The schema
    # card offers the model every column, so a mart must be readable whole. Plain
    # `create` fails if a real mart is there, and then nothing is dropped.
    cur = _pg_session.cursor()
    cur.execute("create table marts.mart_threat_tags (tag text, pulse_count bigint, x bigint)")
    try:
        cur.execute("grant select (tag, pulse_count) on marts.mart_threat_tags to analyst_ro")
        failures = check._role(conn)
        assert "analyst_ro cannot read marts.mart_threat_tags" in failures
        assert "mart missing from marts: mart_threat_tags" not in failures
    finally:
        cur.execute("drop table marts.mart_threat_tags")


def test_a_gold_text_cut_at_the_row_cap_is_not_read_twice(
    conn: psycopg.Connection[tuple[Any, ...]],
) -> None:
    # Big enough that psycopg's cancel lands while the query still runs, which aborts
    # the transaction: a second read in it would fail with 25P02.
    big = GoldQuestion(
        id="q99",
        question="Every number to 200,000?",
        marts=(),
        kind="single",
        difficulty="easy",
        ordered=False,
        tolerance=Decimal(0),
        sql="select g from generate_series(1, 200000) g",
        checkable="A test double.",
    )
    assert check._renderings(conn, [big]) == ["q99: a result is cut at the row cap"]
