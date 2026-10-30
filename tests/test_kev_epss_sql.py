"""sql/32_kev_epss.sql: the KEV and EPSS raw tables' constraints and privileges.

DB-integration (gated on NEON_DATABASE_URL, see conftest.py).
"""

from __future__ import annotations

import psycopg
import pytest

_KEV_INSERT = (
    "insert into raw.kev_vulnerabilities (cve_id, date_added, catalog_version, catalog_released_at)"
    " values (%s, '2026-10-29', '2026.10.29', now())"
)
_EPSS_INSERT = (
    "insert into raw.epss_scores (cve_id, epss, percentile, score_date)"
    " values (%s, %s, %s, '2026-10-29')"
)


def test_valid_rows_insert(pg_conn: psycopg.Connection) -> None:
    with pg_conn.cursor() as cur:
        cur.execute(_KEV_INSERT, ("CVE-2026-111497",))
        cur.execute(_EPSS_INSERT, ("CVE-2026-111497", "0.18427", "0.97229"))
        cur.execute(
            "select count(*) from raw.kev_vulnerabilities join raw.epss_scores using (cve_id)"
        )
        assert cur.fetchone() == (1,)


@pytest.mark.parametrize("cve_id", ["CVE-26-1234", "cve-2026-1234", "CVE-2026-123", "<script>"])
def test_bad_cve_ids_are_rejected(pg_conn: psycopg.Connection, cve_id: str) -> None:
    with pg_conn.cursor() as cur:
        with pytest.raises(psycopg.errors.CheckViolation):
            cur.execute(_KEV_INSERT, (cve_id,))
        with pytest.raises(psycopg.errors.CheckViolation):
            cur.execute(_EPSS_INSERT, (cve_id, "0.1", "0.5"))


@pytest.mark.parametrize(("epss", "percentile"), [("1.5", "0.5"), ("-0.1", "0.5"), ("0.5", "1.01")])
def test_scores_outside_zero_to_one_are_rejected(
    pg_conn: psycopg.Connection, epss: str, percentile: str
) -> None:
    with pg_conn.cursor() as cur, pytest.raises(psycopg.errors.CheckViolation):
        cur.execute(_EPSS_INSERT, ("CVE-2026-0001", epss, percentile))


@pytest.mark.parametrize("table", ["raw.kev_vulnerabilities", "raw.epss_scores"])
def test_grafana_ro_cannot_read_the_feed_tables(pg_conn: psycopg.Connection, table: str) -> None:
    with pg_conn.cursor() as cur:
        # As the owner first: "permission denied for schema raw" fires before any
        # table lookup, so without these a missing or misspelled table would pass.
        cur.execute("select to_regclass(%s) is not null", (table,))
        assert cur.fetchone() == (True,), f"{table} does not exist"
        cur.execute("select has_table_privilege('grafana_ro', %s, 'select')", (table,))
        assert cur.fetchone() == (False,)
        cur.execute("set role grafana_ro")
        try:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute(f"select 1 from {table} limit 1")
        finally:
            cur.execute("reset role")
