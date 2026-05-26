"""Seed a synthetic OTX corpus into raw.* + one successful pipeline.runs row.

Used by:
  - local `dbt build` verify (spec 03 §10 acceptance criteria)
  - the CI `dbt build · test` job

No OTX hit; we hand-craft rows that go through cyber_threat_pipeline.ingestion.load
so the raw schema is populated exactly as production ingestion would shape it.

The corpus is deliberately small but diverse — enough rows that every mart's
GROUP BY returns more than one bucket: multiple TLPs, indicator types,
countries, tags, industries, and a mix of expirations (past / soon / far / null).

A single "dropped" indicator is created by backdating one indicator's
synced_at after the initial load, so the canonical is_active / is_dropped
logic (data-model.md §6) has a non-trivial true case to assert on.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg

from cyber_threat_pipeline.core import runs
from cyber_threat_pipeline.ingestion.load import load

logger = logging.getLogger(__name__)


def _pulse(
    pulse_id: str,
    name: str,
    *,
    tlp: str = "white",
    author: str = "AlienVault",
    tags: list[str] | None = None,
    countries: list[str] | None = None,
    industries: list[str] | None = None,
    modified: datetime | None = None,
    indicators: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    created = datetime(2026, 1, 1, tzinfo=UTC)
    return {
        "id": pulse_id,
        "name": name,
        "description": f"Synthetic pulse {pulse_id}",
        "author_name": author,
        "public": 1,
        "revision": 1,
        "adversary": "",
        "industries": industries or [],
        "tlp": tlp,
        "tags": tags or [],
        "created": created,
        "modified": modified or created,
        "references": [],
        "targeted_countries": countries or [],
        "indicators": indicators or [],
    }


def _indicator(
    indicator_id: int,
    value: str,
    type_: str,
    *,
    expiration: datetime | None,
    is_active: bool = True,
) -> dict[str, Any]:
    return {
        "id": indicator_id,
        "indicator": value,
        "type": type_,
        "title": "",
        "description": "",
        "access_reason": "",
        "created": datetime(2026, 1, 1, tzinfo=UTC),
        "is_active": is_active,
        "access_type": "public",
        "content": "",
        "role": "",
        "expiration": expiration,
        "access_groups": [],
        "observations": 0,
    }


def _build_corpus() -> list[dict[str, Any]]:
    now = datetime.now(UTC)
    far_future = now + timedelta(days=180)
    soon = now + timedelta(days=15)
    past = now - timedelta(days=30)

    # ID counter for indicators — well above 32-bit signed int boundary,
    # matching the real-world OTX ID range that justified BIGINT.
    base = 5_000_000_000

    pulses = [
        _pulse(
            "PULSE-APT-CN-001",
            "APT actor targeting finance — China-linked",
            tlp="amber",
            tags=["apt", "phishing"],
            countries=["China", "United States"],
            industries=["Finance", "Government"],
            modified=now - timedelta(days=2),
            indicators=[
                _indicator(base + 1, "1.2.3.4", "IPv4", expiration=far_future),
                _indicator(base + 2, "evil.example.com", "domain", expiration=far_future),
                _indicator(base + 3, "a" * 64, "FileHash-SHA256", expiration=soon),
                _indicator(base + 4, "b" * 40, "FileHash-SHA1", expiration=past, is_active=False),
                _indicator(base + 5, "https://evil.example/x", "URL", expiration=None),
            ],
        ),
        _pulse(
            "PULSE-RU-PHISH-002",
            "Phishing infrastructure — Russia-nexus",
            tlp="green",
            tags=["phishing", "credential-theft"],
            countries=["Russia", "Ukraine"],
            industries=["Energy"],
            modified=now - timedelta(days=4),
            indicators=[
                _indicator(base + 11, "5.6.7.8", "IPv4", expiration=far_future),
                _indicator(base + 12, "phish.example.net", "domain", expiration=soon),
                _indicator(base + 13, "c" * 32, "FileHash-MD5", expiration=past, is_active=False),
                _indicator(base + 14, "10.0.0.0/24", "CIDR", expiration=far_future),
            ],
        ),
        _pulse(
            "PULSE-RANSOM-003",
            "Ransomware campaign — multi-region",
            tlp="white",
            tags=["ransomware", "malware"],
            countries=["United States", "Germany", "Brazil"],
            industries=["Healthcare", "Finance"],
            modified=now - timedelta(days=1),
            indicators=[
                _indicator(base + 21, "host.example.org", "hostname", expiration=far_future),
                _indicator(base + 22, "attacker@example.com", "email", expiration=far_future),
                _indicator(base + 23, "d" * 64, "FileHash-SHA256", expiration=far_future),
                _indicator(base + 24, "CVE-2026-12345", "CVE", expiration=None),
            ],
        ),
        _pulse(
            "PULSE-EMERGING-004",
            "Emerging campaign — first seen this week",
            tlp="red",
            author="OTX Community",
            tags=["zero-day", "exploit"],
            countries=["United States"],
            industries=["Technology"],
            modified=now - timedelta(hours=12),
            indicators=[
                _indicator(base + 31, "9.9.9.9", "IPv4", expiration=far_future),
                _indicator(base + 32, "zero-day.example.io", "domain", expiration=soon),
                _indicator(base + 33, "e" * 64, "FileHash-SHA256", expiration=far_future),
            ],
        ),
        _pulse(
            "PULSE-IPV6-005",
            "IPv6 botnet — observational",
            tlp="green",
            tags=["botnet"],
            countries=["Brazil", "Argentina"],
            industries=["Telecommunications"],
            modified=now - timedelta(days=6),
            indicators=[
                _indicator(base + 41, "2001:db8::1", "IPv6", expiration=far_future),
                _indicator(base + 42, "2001:db8::cafe", "IPv6", expiration=far_future),
                _indicator(base + 43, "botnet@example.org", "email", expiration=None),
            ],
        ),
    ]
    return pulses


def _transform(
    pulses: list[dict[str, Any]],
) -> tuple[
    list[tuple[Any, ...]],
    list[tuple[Any, ...]],
]:
    """Shape pulses into the row tuples load.load() expects.

    Mirrors cyber_threat_pipeline.ingestion.transform.transform but keeps the
    seed script self-contained (so a future rename of the production transform
    signature doesn't silently change the fixture).
    """
    pulse_rows: list[tuple[Any, ...]] = []
    indicator_rows: list[tuple[Any, ...]] = []
    for p in pulses:
        pulse_rows.append(
            (
                p["id"],
                p["name"],
                p["description"],
                p["author_name"],
                bool(p["public"]),
                p["revision"],
                p["adversary"],
                json.dumps(p["industries"]),
                p["tlp"],
                json.dumps(p["tags"]),
                p["created"],
                p["modified"],
                json.dumps(p["references"]),
                json.dumps(p["targeted_countries"]),
            )
        )
        for i in p["indicators"]:
            indicator_rows.append(
                (
                    int(i["id"]),
                    p["id"],
                    i["indicator"],
                    i["type"],
                    i["title"],
                    i["description"],
                    i["access_reason"],
                    i["created"],
                    bool(i["is_active"]),
                    i["access_type"],
                    i["content"],
                    i["role"],
                    i["expiration"],
                    json.dumps(i["access_groups"]),
                    i["observations"],
                )
            )
    return pulse_rows, indicator_rows


def _backdate_one_indicator(conn: psycopg.Connection) -> int:
    """Backdate one indicator's synced_at to simulate the canonical drop-out case.

    Picks an indicator on PULSE-APT-CN-001 (which has 5 indicators) and pushes
    its synced_at to 2020-01-01. The other 4 indicators retain their fresh
    synced_at, so the pulse's `pulse_latest_synced_at` stays current — and the
    dbt staging layer should mark the backdated row is_dropped=true.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE raw.indicators
               SET synced_at = '2020-01-01 00:00:00+00'::timestamptz
             WHERE pulse_id = 'PULSE-APT-CN-001'
               AND type     = 'URL'
            RETURNING id;
            """
        )
        rows = cur.fetchall()
    return len(rows)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    url = os.environ.get("NEON_DATABASE_URL")
    if not url:
        print("NEON_DATABASE_URL is not set", file=sys.stderr)
        return 2

    pulses = _build_corpus()
    pulse_rows, indicator_rows = _transform(pulses)

    with psycopg.connect(url) as conn:
        conn.autocommit = True

        with runs.run(conn, trigger="fixture-seed", git_sha=runs.detect_git_sha()) as handle:
            pulses_upserted, pulses_inserted, indicators_upserted, indicators_inserted = load(
                conn, pulse_rows, indicator_rows
            )
            handle.set(
                pulses_fetched=len(pulse_rows),
                pulses_upserted=pulses_upserted,
                pulses_inserted=pulses_inserted,
                indicators_fetched=len(indicator_rows),
                indicators_upserted=indicators_upserted,
                indicators_inserted=indicators_inserted,
                watermark_after=max(p["modified"] for p in pulses),
            )
            handle.flush()

        dropped = _backdate_one_indicator(conn)
        logger.info("Backdated %d indicator(s) to seed the drop-out scenario", dropped)

    logger.info(
        "Seeded corpus: %d pulses, %d indicators (drop-out: %d)",
        pulses_upserted,
        indicators_upserted,
        dropped,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
