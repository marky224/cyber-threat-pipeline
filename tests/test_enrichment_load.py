"""Tests for cyber_threat_pipeline.enrichment.load: inputs and snapshot writes.

DB-integration (gated on NEON_DATABASE_URL, see conftest.py).
"""

from __future__ import annotations

from decimal import Decimal

import psycopg

from cyber_threat_pipeline.enrichment import epss, kev, load
from tests.fake_http import epss_body, kev_body


def add_indicator(
    conn: psycopg.Connection, ind_id: int, value: str, first_seen: str, type_: str = "CVE"
) -> None:
    """One raw.indicators row with no pulse; enough for the enrichment reads."""
    with conn.cursor() as cur:
        cur.execute(
            "insert into raw.indicators (id, indicator, type, first_seen_at) values (%s, %s, %s, %s)",
            (ind_id, value, type_, first_seen),
        )


def _kev_rows(conn: psycopg.Connection) -> list[tuple[object, ...]]:
    with conn.cursor() as cur:
        cur.execute(
            "select cve_id, vulnerability_name, catalog_version, fetched_at"
            " from raw.kev_vulnerabilities order by cve_id"
        )
        return cur.fetchall()


def test_inputs_normalize_dedupe_and_put_the_newest_first(pg_conn: psycopg.Connection) -> None:
    add_indicator(pg_conn, 1, " cve-2026-0001 ", "2026-10-01")
    add_indicator(pg_conn, 2, "CVE-2026-0001", "2026-10-20")
    add_indicator(pg_conn, 3, "CVE-2026-0002", "2026-10-25")
    add_indicator(pg_conn, 4, "CVE-2026-0003", "2026-10-10")
    add_indicator(pg_conn, 5, "not-a-cve", "2026-10-29")
    add_indicator(pg_conn, 6, "CVE-2026-" + "9" * 16, "2026-10-29")  # longer than 24 characters
    add_indicator(pg_conn, 7, "CVE-2026-0004", "2026-10-29", type_="domain")
    inputs = load.read_inputs(pg_conn, 10)
    assert inputs.cve_ids == ["CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0003"]
    assert inputs.cve_ids_total == 3
    assert inputs.kev_entries == 0


def test_inputs_cap_the_ids_but_count_them_all(pg_conn: psycopg.Connection) -> None:
    for n in range(1, 4):
        add_indicator(pg_conn, n, f"CVE-2026-000{n}", f"2026-10-0{n}")
    inputs = load.read_inputs(pg_conn, 2)
    assert inputs.cve_ids == ["CVE-2026-0003", "CVE-2026-0002"]
    assert inputs.cve_ids_total == 3


def test_an_empty_database_gives_empty_inputs(pg_conn: psycopg.Connection) -> None:
    assert load.read_inputs(pg_conn, 10) == load.Inputs(cve_ids=[], cve_ids_total=0, kev_entries=0)


def test_one_fetch_shares_one_fetched_at_and_a_dropped_entry_keeps_its_own(
    pg_conn: psycopg.Connection,
) -> None:
    first = kev.parse(kev_body(["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]))
    second = kev.parse(
        kev_body(["CVE-2026-0001", "CVE-2026-0002"], version="2026.10.30", name="v2")
    )
    assert load.write_kev(pg_conn, first) == 3
    assert load.write_kev(pg_conn, second) == 2

    rows = {r[0]: r for r in _kev_rows(pg_conn)}
    assert rows["CVE-2026-0001"][1:3] == ("CVE-2026-0001 v2", "2026.10.30")
    assert rows["CVE-2026-0001"][3] == rows["CVE-2026-0002"][3]
    assert rows["CVE-2026-0003"][1:3] == ("CVE-2026-0003 name", "2026.10.29")
    assert rows["CVE-2026-0003"][3] < rows["CVE-2026-0001"][3]  # type: ignore[operator]
    assert load.read_inputs(pg_conn, 10).kev_entries == 2


def test_every_stored_field_round_trips(pg_conn: psycopg.Connection) -> None:
    load.write_kev(pg_conn, kev.parse(kev_body(["CVE-2026-0001"])))
    with pg_conn.cursor() as cur:
        cur.execute(
            "select vendor_project, product, date_added::text, known_ransomware_campaign_use,"
            " catalog_released_at = '2026-10-29T19:09:34.4003Z'::timestamptz"
            " from raw.kev_vulnerabilities"
        )
        assert cur.fetchone() == ("Vendor", "Product", "2026-10-01", "Unknown", True)


def test_every_score_parse_accepts_fits_the_table(pg_conn: psycopg.Connection) -> None:
    requested = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    body = epss_body(
        {"CVE-2026-0001": "0E-1000000", "CVE-2026-0002": "1", "CVE-2026-0003": "0.000000001"}
    )
    assert load.write_epss(pg_conn, epss.parse(body, requested)) == 3
    with pg_conn.cursor() as cur:
        cur.execute("select epss::text from raw.epss_scores order by cve_id")
        assert [r[0] for r in cur.fetchall()] == ["0.000000000", "1.000000000", "0.000000001"]


def test_epss_scores_update_in_place(pg_conn: psycopg.Connection) -> None:
    requested = ["CVE-2026-0001", "CVE-2026-0002"]
    load.write_epss(pg_conn, epss.parse(epss_body(dict.fromkeys(requested, "0.1")), requested))
    load.write_epss(pg_conn, epss.parse(epss_body({"CVE-2026-0001": "0.97"}), requested))
    with pg_conn.cursor() as cur:
        cur.execute("select cve_id, epss, fetched_at from raw.epss_scores order by cve_id")
        (one, epss_one, at_one), (two, epss_two, at_two) = cur.fetchall()
    assert (one, epss_one, two, epss_two) == (
        "CVE-2026-0001",
        Decimal("0.970000000"),
        "CVE-2026-0002",
        Decimal("0.100000000"),
    )
    assert at_two < at_one
