"""pipeline.runs lifecycle: stale sweep + run() context manager + RunHandle.

Spec: _private/specs/02-ingestion.md §8.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg

logger = logging.getLogger(__name__)


def sweep_stale(conn: psycopg.Connection, *, threshold_minutes: int) -> int:
    """Mark any 'running' rows older than threshold as 'orphaned'. Returns count swept."""
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            """
            UPDATE pipeline.runs
               SET status        = 'orphaned',
                   finished_at   = now(),
                   error_message = COALESCE(error_message, 'stale-running sweep'),
                   duration_seconds = EXTRACT(EPOCH FROM (now() - started_at))::int
             WHERE status = 'running'
               AND started_at < now() - (%s || ' minutes')::interval
            RETURNING id;
            """,
            (str(threshold_minutes),),
        )
        swept = cur.fetchall()
    if swept:
        logger.warning("Swept %d orphaned run rows: %s", len(swept), [r[0] for r in swept])
    return len(swept)


@contextmanager
def run(
    conn: psycopg.Connection,
    *,
    trigger: str,
    git_sha: str | None,
    notes: dict[str, object] | None = None,
) -> Iterator[RunHandle]:
    """Insert pipeline.runs with status='running'; yield a handle; close with terminal status."""
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO pipeline.runs (status, trigger, git_sha, notes)
            VALUES ('running', %s, %s, %s::jsonb)
            RETURNING id, started_at;
            """,
            (trigger, git_sha, _json(notes)),
        )
        row = cur.fetchone()
        assert row is not None
        run_id, started_at = row
    logger.info("Run %d started (trigger=%s, git_sha=%s)", run_id, trigger, git_sha)

    handle = RunHandle(conn, run_id, started_at)
    try:
        yield handle
    except Exception as e:
        handle.fail(str(e))
        raise
    else:
        if handle.status == "running":
            handle.finish("success")


class RunHandle:
    """Mutable handle for the open pipeline.runs row."""

    def __init__(self, conn: psycopg.Connection, run_id: int, started_at: dt.datetime) -> None:
        self.conn = conn
        self.id = run_id
        self.started_at = started_at
        self.status = "running"
        self._fields: dict[str, object] = {}

    def set(self, **fields: object) -> None:
        """Stage column updates; flushed on the next ``flush()`` or terminal call."""
        self._fields.update(fields)

    def flush(self) -> None:
        if not self._fields:
            return
        cols = ", ".join(f"{k} = %s" for k in self._fields)
        sql = f"UPDATE pipeline.runs SET {cols} WHERE id = %s;"
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute(sql, (*self._fields.values(), self.id))
        self._fields.clear()

    def finish(self, status: str, *, error_message: str | None = None) -> None:
        assert status in {"success", "failed", "partial"}, status
        now = dt.datetime.now(dt.UTC)
        self.set(
            status=status,
            finished_at=now,
            duration_seconds=int((now - self.started_at).total_seconds()),
        )
        if error_message is not None:
            self.set(error_message=error_message[:2048])
        self.flush()
        self.status = status

    def fail(self, error_message: str) -> None:
        self.finish("failed", error_message=error_message)


def latest_run_id(conn: psycopg.Connection) -> int | None:
    """Return the id of the most-recent pipeline.runs row by started_at.

    Spec: 07-orchestration.md §3. Used by the orchestrator's post-dbt-build
    step to find the run row to write dbt_tests_* counters into.

    Status-agnostic on purpose: the ingest stage's run() context manager
    closes the row to status='success' on clean exit (spec 02 §8), so by
    the time dbt has run, that row is already 'success' — not 'running' as
    spec 07 §3 originally envisioned. pipeline.runs is append-only and
    each weekly cron writes exactly one new row, so "most recent" is
    unambiguously the current run.

    Returns None if pipeline.runs is empty (only happens on a clean
    project before its first ingest — caller should bail with a clear
    error in that case).
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id FROM pipeline.runs
             ORDER BY started_at DESC
             LIMIT 1;
            """
        )
        row = cur.fetchone()
    return int(row[0]) if row else None


def record_dbt_results(
    conn: psycopg.Connection,
    *,
    run_id: int,
    results_path: str,
) -> tuple[int, int, int]:
    """Parse dbt's target/run_results.json and write the test counts into pipeline.runs.

    Spec: 07-orchestration.md §3 + 03-dbt-transform.md §9. Counts nodes whose
    unique_id starts with "test." (data tests + custom singular tests); each
    is counted in exactly one of passed / failed / skipped buckets:
       - pass    → passed
       - fail    → failed
       - error   → failed (compilation / runtime error — treat as test failure)
       - skipped → skipped

    Returns (passed, failed, skipped) so callers can log the totals.
    """
    import pathlib

    results = json.loads(pathlib.Path(results_path).read_text(encoding="utf-8"))
    test_nodes = [
        r for r in results.get("results", []) if r.get("unique_id", "").startswith("test.")
    ]
    passed = sum(1 for r in test_nodes if r.get("status") == "pass")
    failed = sum(1 for r in test_nodes if r.get("status") in ("fail", "error"))
    skipped = sum(1 for r in test_nodes if r.get("status") == "skipped")

    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            """
            UPDATE pipeline.runs SET
              dbt_tests_passed  = %s,
              dbt_tests_failed  = %s,
              dbt_tests_skipped = %s
             WHERE id = %s;
            """,
            (passed, failed, skipped, run_id),
        )

    logger.info(
        "Recorded dbt test results for run %d: passed=%d failed=%d skipped=%d",
        run_id,
        passed,
        failed,
        skipped,
    )
    return passed, failed, skipped


def detect_git_sha() -> str | None:
    """Prefer GITHUB_SHA (CI); fall back to git rev-parse; None if neither works."""
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _json(obj: object) -> str | None:
    if obj is None:
        return None
    return json.dumps(obj)
