"""pipeline.state watermark read / write / force-cold-start.

Spec: _private/specs/02-ingestion.md §7.
"""

from __future__ import annotations

import datetime as dt
import logging

import psycopg

logger = logging.getLogger(__name__)


def read(conn: psycopg.Connection) -> dt.datetime | None:
    """Return the current modified_since watermark, or None on cold start."""
    with conn.cursor() as cur:
        cur.execute("SELECT modified_since FROM pipeline.state WHERE singleton = true;")
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("pipeline.state is uninitialized; run sql/20_pipeline.sql.")
    value: dt.datetime | None = row[0]
    return value


def write(
    conn: psycopg.Connection,
    *,
    modified_since: dt.datetime | str | None,
    run_id: int,
) -> None:
    """Advance pipeline.state.modified_since. Called only on load success."""
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            """
            UPDATE pipeline.state
               SET modified_since   = %s,
                   updated_at       = now(),
                   updated_by_run_id= %s
             WHERE singleton = true;
            """,
            (modified_since, run_id),
        )
    logger.info("Watermark advanced: modified_since=%s (run %d)", modified_since, run_id)


def force_cold_start(conn: psycopg.Connection, *, run_id: int) -> None:
    """Used by FORCE_FULL_BACKFILL — wipes the watermark to NULL before the run reads it."""
    write(conn, modified_since=None, run_id=run_id)
