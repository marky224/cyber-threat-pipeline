"""Batched idempotent upsert into raw.pulses + raw.indicators.

Spec: _private/specs/02-ingestion.md §6.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from typing import Any

import psycopg

logger = logging.getLogger(__name__)


# Column order MUST match transform.PULSE_COLUMNS / INDICATOR_COLUMNS.
# first_seen_at is deliberately NOT in the UPDATE list — write-once (Q2).
_PULSE_UPSERT = """
INSERT INTO raw.pulses (
    id, name, description, author_name, public, revision, adversary,
    industries, tlp, tags, created, modified, "references", targeted_countries,
    first_seen_at, synced_at
) VALUES (
    %s, %s, %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s, %s, %s,
    now(), now()
)
ON CONFLICT (id) DO UPDATE SET
    name              = EXCLUDED.name,
    description       = EXCLUDED.description,
    author_name       = EXCLUDED.author_name,
    public            = EXCLUDED.public,
    revision          = EXCLUDED.revision,
    adversary         = EXCLUDED.adversary,
    industries        = EXCLUDED.industries,
    tlp               = EXCLUDED.tlp,
    tags              = EXCLUDED.tags,
    created           = EXCLUDED.created,
    modified          = EXCLUDED.modified,
    "references"      = EXCLUDED."references",
    targeted_countries= EXCLUDED.targeted_countries,
    synced_at         = now()
RETURNING (xmax = 0) AS inserted;
"""

_INDICATOR_UPSERT = """
INSERT INTO raw.indicators (
    id, pulse_id, indicator, type, title, description, access_reason,
    created, is_active, access_type, content, role, expiration,
    access_groups, observations,
    first_seen_at, synced_at
) VALUES (
    %s, %s, %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s, %s,
    %s, %s,
    now(), now()
)
ON CONFLICT (id) DO UPDATE SET
    pulse_id      = EXCLUDED.pulse_id,
    indicator     = EXCLUDED.indicator,
    type          = EXCLUDED.type,
    title         = EXCLUDED.title,
    description   = EXCLUDED.description,
    access_reason = EXCLUDED.access_reason,
    created       = EXCLUDED.created,
    is_active     = EXCLUDED.is_active,
    access_type   = EXCLUDED.access_type,
    content       = EXCLUDED.content,
    role          = EXCLUDED.role,
    expiration    = EXCLUDED.expiration,
    access_groups = EXCLUDED.access_groups,
    observations  = EXCLUDED.observations,
    synced_at     = now()
RETURNING (xmax = 0) AS inserted;
"""


def load(
    conn: psycopg.Connection,
    pulse_rows: Sequence[tuple[Any, ...]],
    indicator_rows: Sequence[tuple[Any, ...]],
    batch_size: int = 500,
) -> tuple[int, int, int, int]:
    """Upsert pulses then indicators in a single transaction.

    Returns ``(pulses_upserted, pulses_inserted, indicators_upserted, indicators_inserted)``.

    The ``inserted`` count comes from PostgreSQL's ``xmax=0`` trick on RETURNING:
    a freshly-inserted row has xmax=0, an updated row's xmax is non-zero.
    """
    pulses_upserted = 0
    pulses_inserted = 0
    indicators_upserted = 0
    indicators_inserted = 0

    with conn.transaction(), conn.cursor() as cur:
        for batch in _batched(pulse_rows, batch_size):
            cur.executemany(_PULSE_UPSERT, batch, returning=True)
            while True:
                for (inserted,) in cur.fetchall():
                    pulses_upserted += 1
                    if inserted:
                        pulses_inserted += 1
                if not cur.nextset():
                    break

        for batch in _batched(indicator_rows, batch_size):
            cur.executemany(_INDICATOR_UPSERT, batch, returning=True)
            while True:
                for (inserted,) in cur.fetchall():
                    indicators_upserted += 1
                    if inserted:
                        indicators_inserted += 1
                if not cur.nextset():
                    break

    logger.info(
        "Load: pulses=%d (new=%d), indicators=%d (new=%d)",
        pulses_upserted,
        pulses_inserted,
        indicators_upserted,
        indicators_inserted,
    )
    return pulses_upserted, pulses_inserted, indicators_upserted, indicators_inserted


def _batched(rows: Sequence[tuple[Any, ...]], n: int) -> Iterable[list[tuple[Any, ...]]]:
    for i in range(0, len(rows), n):
        yield list(rows[i : i + n])
