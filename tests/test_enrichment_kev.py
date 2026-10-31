"""Tests for cyber_threat_pipeline.enrichment.kev: what a KEV download must be.

tests/fixtures/kev_epss/kev_catalog.json is the CISA KEV JSON feed fetched
2026-10-30 from www.cisa.gov (catalogVersion 2026.10.29), trimmed to 12
verbatim entries with ``count`` set to match. Each rejection case mutates it.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from cyber_threat_pipeline.enrichment import FeedInvalid
from cyber_threat_pipeline.enrichment.kev import check_shrink, parse

FIXTURE = Path(__file__).parent / "fixtures" / "kev_epss" / "kev_catalog.json"
RECORDED: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))


def _mutated(change: Callable[[dict[str, Any]], object]) -> bytes:
    catalog = copy.deepcopy(RECORDED)
    change(catalog)
    return json.dumps(catalog).encode()


def _entry(catalog: dict[str, Any], i: int = 0) -> dict[str, Any]:
    entry: dict[str, Any] = catalog["vulnerabilities"][i]
    return entry


def test_the_recorded_catalog_parses_in_full() -> None:
    catalog = parse(FIXTURE.read_bytes())
    assert catalog.catalog_version == "2026.10.29"
    assert catalog.released_at == datetime(2026, 10, 29, 19, 9, 34, 400300, tzinfo=UTC)
    assert catalog.count == len(catalog.entries) == 12
    first = catalog.entries[0]
    assert first.cve_id == "CVE-2026-97229"
    assert first.date_added == date(2026, 10, 29)
    assert first.vendor_project == "GitLab"
    assert first.known_ransomware_campaign_use == "Unknown"
    assert {e.known_ransomware_campaign_use for e in catalog.entries} == {"Known", "Unknown"}
    assert "CVE-2026-111497" in {e.cve_id for e in catalog.entries}


def test_keys_the_pipeline_does_not_store_are_ignored() -> None:
    def add(c: dict[str, Any]) -> None:
        c["somethingNew"] = {"nested": [1, 2]}
        _entry(c)["anotherNewField"] = "x" * 10_000

    catalog = parse(_mutated(add))
    assert len(catalog.entries) == 12


def test_optional_fields_may_be_missing() -> None:
    def drop(c: dict[str, Any]) -> None:
        for key in ("vendorProject", "product", "vulnerabilityName", "knownRansomwareCampaignUse"):
            del _entry(c)[key]

    first = parse(_mutated(drop)).entries[0]
    assert (first.vendor_project, first.product, first.vulnerability_name) == (None, None, None)
    assert first.known_ransomware_campaign_use is None


def test_control_characters_are_flattened_before_the_length_check() -> None:
    def dirty(c: dict[str, Any]) -> None:
        _entry(c)["vendorProject"] = "Git\x00Lab\r\n\u0085 Inc.\t"
        _entry(c)["product"] = " " * 600 + "Edition"

    first = parse(_mutated(dirty)).entries[0]
    assert first.vendor_project == "Git Lab Inc."
    assert first.product == "Edition"


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda c: c.update(count=13), "count is 13 but 12 entries arrived"),
        (lambda c: c.update(count=0, vulnerabilities=[]), "greater than or equal to 1"),
        (lambda c: c.update(count="12"), "count"),
        (lambda c: c.update(catalogVersion=""), "catalogVersion"),
        (lambda c: c.update(catalogVersion="v" * 33), "catalogVersion"),
        (lambda c: c.update(dateReleased="2026-10-29T19:09:34"), "dateReleased"),
        (lambda c: c.pop("vulnerabilities"), "vulnerabilities"),
        (lambda c: c.update(vulnerabilities={"CVE-2026-97229": {}}), "vulnerabilities"),
        (lambda c: _entry(c, 1).update(cveID=_entry(c, 0)["cveID"]), "1 duplicate cveID"),
        (lambda c: _entry(c).update(cveID="CVE-26-1234"), "cveID"),
        (lambda c: _entry(c).update(cveID="cve-2026-97229"), "cveID"),
        (lambda c: _entry(c).update(cveID="<script>alert(1)</script>"), "cveID"),
        (lambda c: _entry(c).update(cveID="CVE-2026-" + "9" * 16), "cveID"),
        (lambda c: _entry(c).update(cveID=None), "cveID"),
        (lambda c: _entry(c).pop("cveID"), "cveID"),
        (lambda c: _entry(c).update(dateAdded="29/10/2026"), "dateAdded"),
        (lambda c: _entry(c).pop("dateAdded"), "dateAdded"),
        (lambda c: _entry(c).update(vendorProject="x" * 501), "vendorProject"),
        (lambda c: _entry(c).update(vulnerabilityName=12), "vulnerabilityName"),
        (lambda c: _entry(c).update(knownRansomwareCampaignUse="K" * 33), "knownRansomware"),
    ],
)
def test_a_broken_catalog_is_rejected_whole(
    change: Callable[[dict[str, Any]], object], problem: str
) -> None:
    with pytest.raises(FeedInvalid, match="KEV catalog rejected") as e:
        parse(_mutated(change))
    assert problem in str(e.value)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"<!DOCTYPE html><html><body>Access Denied</body></html>",
        b"[]",
        b'{"count": 1',
        b"null",
        b"[" * 100_000,
    ],
)
def test_a_body_that_is_not_a_catalog_object_is_rejected(body: bytes) -> None:
    with pytest.raises(FeedInvalid, match="KEV catalog rejected"):
        parse(body)


def test_control_characters_in_the_catalog_version_are_flattened() -> None:
    # Postgres can't store a NUL: it must never get past parse.
    catalog = parse(_mutated(lambda c: c.update(catalogVersion="2026.10.29\u0000")))
    assert catalog.catalog_version == "2026.10.29"


def test_a_release_time_postgres_cannot_store_is_rejected() -> None:
    # Year 1 at +23:00 is before year 1 in UTC: Postgres rejects it.
    with pytest.raises(FeedInvalid, match="dateReleased"):
        parse(_mutated(lambda c: c.update(dateReleased="0001-01-01T00:00:00+23:00")))


def test_the_release_time_is_kept_in_utc() -> None:
    catalog = parse(_mutated(lambda c: c.update(dateReleased="2026-10-29T19:09:34+20:00")))
    assert catalog.released_at == datetime(2026, 10, 28, 23, 9, 34, tzinfo=UTC)
    assert catalog.released_at.tzinfo is UTC


def test_rejection_messages_never_quote_the_feed() -> None:
    marker = "INJECTED-FEED-TEXT"
    with pytest.raises(FeedInvalid) as e:
        parse(_mutated(lambda c: _entry(c).update(vendorProject=marker * 100)))
    assert marker not in str(e.value)


def test_the_shrink_guard_allows_growth_and_small_losses() -> None:
    catalog = parse(FIXTURE.read_bytes())  # 12 entries
    for stored in (0, 1, 12, 13):
        check_shrink(catalog, stored)


def test_the_shrink_guard_refuses_a_catalog_that_lost_over_ten_percent() -> None:
    catalog = parse(FIXTURE.read_bytes())  # 12 entries; 12 < 0.9 * 14
    with pytest.raises(FeedInvalid, match="12 entries, under 90% of the 14 stored"):
        check_shrink(catalog, 14)
