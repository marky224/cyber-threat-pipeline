"""Integration tests for sweep_stale + run() context manager + RunHandle.

Requires NEON_DATABASE_URL pointing at a postgres:15 with sql/ applied
(handled by tests/conftest.py)."""

from __future__ import annotations

import psycopg
import pytest

from cyber_threat_pipeline.core.runs import RunHandle, run, sweep_stale


def _insert_stale_running(conn: psycopg.Connection, minutes_old: int) -> int:
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO pipeline.runs (status, trigger, started_at)
            VALUES ('running', 'test', now() - (%s || ' minutes')::interval)
            RETURNING id;
            """,
            (str(minutes_old),),
        )
        row = cur.fetchone()
        assert row is not None
    return int(row[0])


def _status(conn: psycopg.Connection, run_id: int) -> tuple[str, str | None, int | None]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT status, error_message, duration_seconds FROM pipeline.runs WHERE id = %s;",
            (run_id,),
        )
        row = cur.fetchone()
        assert row is not None
    return row[0], row[1], row[2]


def test_sweep_stale_orphans_old_running_rows(pg_conn: psycopg.Connection) -> None:
    old = _insert_stale_running(pg_conn, minutes_old=120)
    fresh = _insert_stale_running(pg_conn, minutes_old=5)

    swept = sweep_stale(pg_conn, threshold_minutes=60)
    assert swept == 1

    old_status, old_err, old_dur = _status(pg_conn, old)
    assert old_status == "orphaned"
    assert old_err == "stale-running sweep"
    assert old_dur is not None and old_dur > 0

    fresh_status, _, _ = _status(pg_conn, fresh)
    assert fresh_status == "running"


def test_sweep_stale_returns_zero_when_nothing_to_sweep(pg_conn: psycopg.Connection) -> None:
    assert sweep_stale(pg_conn, threshold_minutes=60) == 0


def test_run_context_marks_success_on_clean_exit(pg_conn: psycopg.Connection) -> None:
    with run(pg_conn, trigger="local", git_sha="abc123", notes={"k": "v"}) as handle:
        assert isinstance(handle, RunHandle)
        assert handle.status == "running"
        run_id = handle.id

    status, err, duration = _status(pg_conn, run_id)
    assert status == "success"
    assert err is None
    assert duration is not None and duration >= 0


def test_run_context_marks_failed_on_exception(pg_conn: psycopg.Connection) -> None:
    with (
        pytest.raises(RuntimeError, match="boom"),
        run(pg_conn, trigger="local", git_sha=None) as handle,
    ):
        run_id = handle.id
        raise RuntimeError("boom")

    status, err, _ = _status(pg_conn, run_id)
    assert status == "failed"
    assert err is not None and "boom" in err


def test_run_handle_set_and_flush(pg_conn: psycopg.Connection) -> None:
    with run(pg_conn, trigger="local", git_sha=None) as handle:
        handle.set(pulses_fetched=10, pulses_upserted=10, pulses_inserted=7)
        handle.flush()

    with pg_conn.cursor() as cur:
        cur.execute(
            "SELECT pulses_fetched, pulses_upserted, pulses_inserted "
            "FROM pipeline.runs WHERE id = %s;",
            (handle.id,),
        )
        row = cur.fetchone()
    assert row == (10, 10, 7)


def test_run_handle_error_message_truncated_to_2048(pg_conn: psycopg.Connection) -> None:
    long_msg = "x" * 5000
    with (
        pytest.raises(RuntimeError),
        run(pg_conn, trigger="local", git_sha=None) as handle,
    ):
        run_id = handle.id
        raise RuntimeError(long_msg)
    _, err, _ = _status(pg_conn, run_id)
    assert err is not None
    assert len(err) == 2048
