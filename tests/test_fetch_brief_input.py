"""DB-integration test for ``fetch_brief_input``.

Gated on ``NEON_DATABASE_URL`` via the ``pg_conn`` fixture (see conftest.py).
We don't invoke dbt here — the dbt env is isolated under ``transform/`` and
shelling out to it from a pytest test isn't worth the complexity. Instead we
hand-craft a ``marts.brief_input`` row in the exact JSONB shape the dbt mart
produces (spec 03 §7.9), then assert ``fetch_brief_input`` reads it back.
"""

from __future__ import annotations

import json

import psycopg
import pytest

from cyber_threat_pipeline.analysis.prompt import fetch_brief_input


def _create_brief_input_table(conn: psycopg.Connection) -> None:
    """Create marts.brief_input with the same column shape as the dbt mart."""
    with conn.cursor() as cur:
        cur.execute("CREATE SCHEMA IF NOT EXISTS marts;")
        cur.execute("DROP TABLE IF EXISTS marts.brief_input;")
        cur.execute(
            """
            CREATE TABLE marts.brief_input (
                generated_at            timestamptz NOT NULL,
                corpus_header           jsonb       NOT NULL,
                top_types               jsonb,
                top_countries           jsonb,
                top_tags                jsonb,
                top_industries          jsonb,
                emerging_pulses_7d      jsonb,
                emerging_indicators_7d  jsonb
            );
            """
        )


def _insert_fixture_row(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO marts.brief_input (
                generated_at, corpus_header, top_types, top_countries,
                top_tags, top_industries, emerging_pulses_7d, emerging_indicators_7d
            )
            VALUES (now(), %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)
            """,
            (
                json.dumps(
                    {
                        "total_pulses": 100,
                        "total_indicators": 1000,
                        "active_indicators": 800,
                        "expired_indicators": 200,
                    }
                ),
                json.dumps([{"type": "domain", "count": 500}]),
                json.dumps([{"country": "United States", "pulse_count": 40}]),
                json.dumps([{"tag": "phishing", "pulse_count": 30}]),
                json.dumps([{"industry": "Finance", "pulse_count": 20}]),
                json.dumps(
                    [
                        {
                            "id": "PULSE-X",
                            "name": "Emerging Pulse X",
                            "description": "",
                            "tlp": "amber",
                            "tags": ["malware"],
                            "targeted_countries": ["DE"],
                            "first_seen_at": "2026-05-26T01:00:00+00:00",
                            "indicator_count": 7,
                        }
                    ]
                ),
                json.dumps([{"type": "IPv4", "count": 3}]),
            ),
        )


def test_fetch_brief_input_returns_all_eight_fields(
    pg_conn: psycopg.Connection,
) -> None:
    _create_brief_input_table(pg_conn)
    _insert_fixture_row(pg_conn)

    brief = fetch_brief_input(pg_conn)

    expected_keys = {
        "generated_at",
        "corpus_header",
        "top_types",
        "top_countries",
        "top_tags",
        "top_industries",
        "emerging_pulses_7d",
        "emerging_indicators_7d",
    }
    assert set(brief.keys()) == expected_keys
    # Every field non-null in this fixture (the fixture is the happy path).
    for k, v in brief.items():
        assert v is not None, f"{k} should not be None"


def test_fetch_brief_input_jsonb_decodes_to_python(
    pg_conn: psycopg.Connection,
) -> None:
    _create_brief_input_table(pg_conn)
    _insert_fixture_row(pg_conn)

    brief = fetch_brief_input(pg_conn)

    assert brief["corpus_header"]["total_pulses"] == 100
    assert brief["corpus_header"]["active_indicators"] == 800
    assert brief["top_types"][0]["type"] == "domain"
    assert brief["emerging_pulses_7d"][0]["id"] == "PULSE-X"
    assert brief["emerging_pulses_7d"][0]["tags"] == ["malware"]


def test_fetch_brief_input_empty_table_raises(pg_conn: psycopg.Connection) -> None:
    _create_brief_input_table(pg_conn)
    # Don't insert any rows.

    with pytest.raises(RuntimeError, match="brief_input is empty"):
        fetch_brief_input(pg_conn)
