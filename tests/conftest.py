"""Shared fixtures.

DB-integration tests gate on ``NEON_DATABASE_URL`` (set locally to a docker
postgres:15, set in CI by the postgres service). Tests requesting ``pg_conn``
are skipped if the URL isn't set.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest

SQL_DIR = Path(__file__).resolve().parent.parent / "sql"
SQL_FILES = ("00_schemas.sql", "10_raw.sql", "20_pipeline.sql", "30_grafana_role.sql")


def _apply_sql(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        for name in SQL_FILES:
            cur.execute((SQL_DIR / name).read_text())


def _truncate(conn: psycopg.Connection) -> None:
    """Wipe raw + pipeline.runs and re-seed pipeline.state singleton."""
    with conn.cursor() as cur:
        # CASCADE on pipeline.runs also truncates pipeline.state
        # (state.updated_by_run_id references runs.id), so we re-seed below.
        cur.execute("TRUNCATE raw.indicators, raw.pulses, pipeline.runs RESTART IDENTITY CASCADE;")
        cur.execute(
            "INSERT INTO pipeline.state (singleton, modified_since) "
            "VALUES (true, NULL) "
            "ON CONFLICT (singleton) DO UPDATE "
            "SET modified_since = NULL, updated_by_run_id = NULL;"
        )


@pytest.fixture(scope="session")
def pg_url() -> str:
    url = os.environ.get("NEON_DATABASE_URL")
    if not url:
        pytest.skip("NEON_DATABASE_URL not set; integration tests require a Postgres instance")
    return url


@pytest.fixture(scope="session")
def _pg_session(pg_url: str) -> Iterator[psycopg.Connection]:
    conn = psycopg.connect(pg_url)
    conn.autocommit = True
    _apply_sql(conn)
    yield conn
    conn.close()


@pytest.fixture()
def pg_conn(_pg_session: psycopg.Connection) -> Iterator[psycopg.Connection]:
    _truncate(_pg_session)
    yield _pg_session
