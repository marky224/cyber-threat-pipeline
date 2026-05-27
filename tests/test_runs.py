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


# ---------------------------------------------------------------------------
# Phase 7 helpers: latest_run_id + record_dbt_results
# ---------------------------------------------------------------------------


def test_latest_run_id_returns_id_of_most_recent_row(
    pg_conn: psycopg.Connection,
) -> None:
    from cyber_threat_pipeline.core.runs import latest_run_id

    expected_id = _insert_stale_running(pg_conn, minutes_old=1)
    assert latest_run_id(pg_conn) == expected_id


def test_latest_run_id_returns_none_when_table_empty(
    pg_conn: psycopg.Connection,
) -> None:
    from cyber_threat_pipeline.core.runs import latest_run_id

    assert latest_run_id(pg_conn) is None


def test_latest_run_id_status_agnostic(
    pg_conn: psycopg.Connection,
) -> None:
    """The most-recent row wins even if it's already closed to status='success'.

    Real-world case: ingest's run() context manager closes the row to
    'success' on clean exit, so by the time record_dbt_results runs the
    row is no longer 'running'. The helper must still find it.
    """
    from cyber_threat_pipeline.core.runs import latest_run_id

    with pg_conn.transaction(), pg_conn.cursor() as cur:
        cur.execute(
            "INSERT INTO pipeline.runs (status, trigger, finished_at) "
            "VALUES ('success', 'test', now()) "
            "RETURNING id;"
        )
        row = cur.fetchone()
        assert row is not None
        expected_id = int(row[0])
    assert latest_run_id(pg_conn) == expected_id


def test_latest_run_id_picks_most_recent_when_multiple(
    pg_conn: psycopg.Connection,
) -> None:
    from cyber_threat_pipeline.core.runs import latest_run_id

    _insert_stale_running(pg_conn, minutes_old=30)
    newer_id = _insert_stale_running(pg_conn, minutes_old=1)
    assert latest_run_id(pg_conn) == newer_id


def test_record_dbt_results_writes_counts_to_run_row(
    pg_conn: psycopg.Connection,
    tmp_path: object,
) -> None:
    import json
    from pathlib import Path

    from cyber_threat_pipeline.core.runs import record_dbt_results

    run_id = _insert_stale_running(pg_conn, minutes_old=1)

    # Minimal run_results.json shape — only the fields the helper reads.
    results = {
        "results": [
            {"unique_id": "test.foo.not_null_x", "status": "pass"},
            {"unique_id": "test.foo.unique_x", "status": "pass"},
            {"unique_id": "test.foo.accepted_y", "status": "fail"},
            {"unique_id": "test.foo.compile_err", "status": "error"},
            {"unique_id": "test.foo.skipped_z", "status": "skipped"},
            # Non-test nodes (models) are ignored.
            {"unique_id": "model.foo.mart_x", "status": "success"},
        ]
    }
    p = Path(str(tmp_path)) / "run_results.json"
    p.write_text(json.dumps(results), encoding="utf-8")

    passed, failed, skipped = record_dbt_results(pg_conn, run_id=run_id, results_path=str(p))
    assert (passed, failed, skipped) == (2, 2, 1)

    with pg_conn.cursor() as cur:
        cur.execute(
            "SELECT dbt_tests_passed, dbt_tests_failed, dbt_tests_skipped "
            "FROM pipeline.runs WHERE id = %s;",
            (run_id,),
        )
        row = cur.fetchone()
    assert row == (2, 2, 1)


def test_record_dbt_results_handles_empty_results(
    pg_conn: psycopg.Connection,
    tmp_path: object,
) -> None:
    import json
    from pathlib import Path

    from cyber_threat_pipeline.core.runs import record_dbt_results

    run_id = _insert_stale_running(pg_conn, minutes_old=1)
    p = Path(str(tmp_path)) / "run_results.json"
    p.write_text(json.dumps({"results": []}), encoding="utf-8")

    assert record_dbt_results(pg_conn, run_id=run_id, results_path=str(p)) == (0, 0, 0)
