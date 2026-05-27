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

    TCP keepalives are enabled because the ingestion lifecycle inserts
    the pipeline.runs row up front, then holds the connection across the
    multi-minute OTX extract before the load. Neon's pooler closes idle
    server-side connections; keepalive packets keep the TCP path warm so
    the post-extract flush + load doesn't hit "SSL connection closed
    unexpectedly".
    """
    conn = psycopg.connect(
        str(settings.neon_database_url),
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=10,
        keepalives_count=5,
    )
    conn.autocommit = True
    return conn
