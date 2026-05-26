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
