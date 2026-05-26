"""Postgres connection helper.

Spec: _private/specs/02-ingestion.md §1 lists this module; the batched-upsert
machinery lives in ``ingestion/load.py`` where it's used.
"""

from __future__ import annotations

import psycopg

from cyber_threat_pipeline.core.config import Settings


def connect(settings: Settings) -> psycopg.Connection:
    """Open a psycopg v3 connection to the Neon pooled URL.

    Autocommit is enabled so each ``with conn.transaction():`` block opens
    a real BEGIN/COMMIT (rather than nesting as a savepoint under an
    implicit outer transaction that would never commit). Bare SELECTs
    outside an explicit transaction also commit immediately, which is what
    we want for read-only helpers like ``watermark.read``.
    """
    conn = psycopg.connect(str(settings.neon_database_url))
    conn.autocommit = True
    return conn
