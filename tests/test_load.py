"""Integration tests for the batched upsert.

Pins the §11 acceptance criteria that can be verified locally:
 - inserts vs updates counted via xmax=0
 - first_seen_at write-once on re-upsert (§11.9)
 - synced_at rewritten on every upsert (§7 cross-spec invariant)
 - re-running ingest with no changes is idempotent
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from cyber_threat_pipeline.ingestion.load import load
from cyber_threat_pipeline.ingestion.transform import transform


def _pulse(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "p-1",
        "name": "p one",
        "description": "d",
        "author_name": "alice",
        "public": 1,
        "revision": 1,
        "adversary": "",
        "industries": [],
        "tlp": "white",
        "tags": [],
        "created": "2026-05-01T00:00:00",
        "modified": "2026-05-10T00:00:00",
        "references": [],
        "targeted_countries": [],
        "indicators": [],
    }
    base.update(overrides)
    return base


def _ind(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": 1,
        "indicator": "1.1.1.1",
        "type": "IPv4",
        "title": "",
        "description": "",
        "access_reason": "",
        "created": "2026-05-01T00:00:00",
        "is_active": 1,
        "access_type": "public",
        "content": "",
        "role": "",
        "expiration": None,
        "access_groups": [],
        "observations": 0,
    }
    base.update(overrides)
    return base


def _counts(conn: psycopg.Connection) -> tuple[int, int]:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM raw.pulses;")
        p_row = cur.fetchone()
        assert p_row is not None
        cur.execute("SELECT count(*) FROM raw.indicators;")
        i_row = cur.fetchone()
        assert i_row is not None
    return int(p_row[0]), int(i_row[0])


def test_first_load_counts_all_as_inserts(pg_conn: psycopg.Connection) -> None:
    pulses = [_pulse(indicators=[_ind(id=1), _ind(id=2, indicator="2.2.2.2")])]
    p_rows, i_rows = transform(pulses)

    p_up, p_ins, i_up, i_ins = load(pg_conn, p_rows, i_rows)
    assert (p_up, p_ins, i_up, i_ins) == (1, 1, 2, 2)
    assert _counts(pg_conn) == (1, 2)


def test_reupsert_is_idempotent_with_zero_inserts(pg_conn: psycopg.Connection) -> None:
    pulses = [_pulse(indicators=[_ind(id=1)])]
    p_rows, i_rows = transform(pulses)
    load(pg_conn, p_rows, i_rows)

    p_up, p_ins, i_up, i_ins = load(pg_conn, p_rows, i_rows)
    assert (p_up, p_ins, i_up, i_ins) == (1, 0, 1, 0)
    assert _counts(pg_conn) == (1, 1)


def test_first_seen_at_is_write_once(pg_conn: psycopg.Connection) -> None:
    """§11.9 regression canary: first_seen_at must not change on re-upsert."""
    pulses = [_pulse(indicators=[_ind(id=1)])]
    p_rows, i_rows = transform(pulses)
    load(pg_conn, p_rows, i_rows)

    with pg_conn.cursor() as cur:
        cur.execute("SELECT first_seen_at FROM raw.pulses WHERE id = 'p-1';")
        p_first = cur.fetchone()
        cur.execute("SELECT first_seen_at FROM raw.indicators WHERE id = 1;")
        i_first = cur.fetchone()
    assert p_first is not None and i_first is not None

    mutated = [_pulse(name="renamed", indicators=[_ind(id=1, indicator="9.9.9.9")])]
    p_rows2, i_rows2 = transform(mutated)
    load(pg_conn, p_rows2, i_rows2)

    with pg_conn.cursor() as cur:
        cur.execute("SELECT first_seen_at, name FROM raw.pulses WHERE id = 'p-1';")
        p_after = cur.fetchone()
        cur.execute("SELECT first_seen_at, indicator FROM raw.indicators WHERE id = 1;")
        i_after = cur.fetchone()
    assert p_after is not None and i_after is not None
    assert p_after[0] == p_first[0]
    assert i_after[0] == i_first[0]
    assert p_after[1] == "renamed"
    assert i_after[1] == "9.9.9.9"


def test_synced_at_advances_on_reupsert(pg_conn: psycopg.Connection) -> None:
    pulses = [_pulse(indicators=[_ind(id=1)])]
    p_rows, i_rows = transform(pulses)
    load(pg_conn, p_rows, i_rows)

    with pg_conn.cursor() as cur:
        cur.execute("SELECT synced_at FROM raw.pulses WHERE id = 'p-1';")
        before_row = cur.fetchone()
    assert before_row is not None
    before = before_row[0]

    with pg_conn.cursor() as cur:
        cur.execute("SELECT pg_sleep(0.05);")

    load(pg_conn, p_rows, i_rows)

    with pg_conn.cursor() as cur:
        cur.execute("SELECT synced_at FROM raw.pulses WHERE id = 'p-1';")
        after_row = cur.fetchone()
    assert after_row is not None
    after = after_row[0]
    assert after > before


def test_jsonb_columns_round_trip(pg_conn: psycopg.Connection) -> None:
    pulses = [
        _pulse(
            tags=["t1", "t2"],
            industries=["finance"],
            references=["https://example.com"],
            targeted_countries=["US", "CA"],
        )
    ]
    p_rows, _ = transform(pulses)
    load(pg_conn, p_rows, [])

    with pg_conn.cursor() as cur:
        cur.execute(
            'SELECT tags, industries, "references", targeted_countries '
            "FROM raw.pulses WHERE id = 'p-1';"
        )
        row = cur.fetchone()
    assert row == (["t1", "t2"], ["finance"], ["https://example.com"], ["US", "CA"])


def test_batching_does_not_lose_counts(pg_conn: psycopg.Connection) -> None:
    """3 batches x 4 rows = 12 with batch_size=4."""
    pulses = [_pulse(id=f"p-{n}", indicators=[_ind(id=n)]) for n in range(1, 13)]
    p_rows, i_rows = transform(pulses)
    p_up, p_ins, i_up, i_ins = load(pg_conn, p_rows, i_rows, batch_size=4)
    assert (p_up, p_ins, i_up, i_ins) == (12, 12, 12, 12)
    assert _counts(pg_conn) == (12, 12)


def test_tlp_check_constraint_satisfied_by_default(pg_conn: psycopg.Connection) -> None:
    """§11.10: transform output should never violate CHECK constraints."""
    pulses = [_pulse(tlp=None)]  # transform should normalize None → 'white'
    p_rows, _ = transform(pulses)
    load(pg_conn, p_rows, [])  # would raise psycopg.errors.CheckViolation if broken


def test_fk_holds_indicators_to_pulses(pg_conn: psycopg.Connection) -> None:
    """A dangling indicator without its parent pulse should violate FK."""
    _, i_rows = transform([_pulse(id="ghost", indicators=[_ind(id=99)])])
    # don't load the pulse — indicator-only insert must fail
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        load(pg_conn, [], i_rows)


def test_indicator_id_handles_bigint_range(pg_conn: psycopg.Connection) -> None:
    """data-model.md §3: indicator ids exceed 32-bit; column is bigint."""
    big_id = 5_000_000_000  # > 2^32
    pulses = [_pulse(indicators=[_ind(id=big_id)])]
    p_rows, i_rows = transform(pulses)
    load(pg_conn, p_rows, i_rows)
    with pg_conn.cursor() as cur:
        cur.execute("SELECT id FROM raw.indicators WHERE pulse_id = 'p-1';")
        row = cur.fetchone()
    assert row == (big_id,)
