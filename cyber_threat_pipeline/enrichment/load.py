"""Read what the enrichment step needs from Neon, and write each feed's snapshot.

Each ``write_*`` upserts one validated feed in one transaction. Every row it
writes gets ``fetched_at = now()``, the transaction's timestamp, so one
snapshot shares one ``fetched_at``. A row the new snapshot lacks keeps its
older value, and dbt staging reads only the newest. Nothing is deleted.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import psycopg

from cyber_threat_pipeline.enrichment import CVE_ID_PATTERN
from cyber_threat_pipeline.enrichment.epss import EpssScore
from cyber_threat_pipeline.enrichment.kev import KevCatalog

# Same normalization as dbt's mart_cve_enrichment: trimmed, upper-cased, and
# only values that are then CVE ids. Newest first, so a cap drops old ids.
_CVE_IDS = """
select cve_id, count(*) over () as total
from (
    select upper(btrim(indicator)) as cve_id, max(first_seen_at) as last_seen
    from raw.indicators
    where type = 'CVE'
    group by 1
) ids
where cve_id ~ %s
order by last_seen desc, cve_id
limit %s
"""

_KEV_ENTRIES = """
select count(*) from raw.kev_vulnerabilities
where fetched_at = (select max(fetched_at) from raw.kev_vulnerabilities)
"""

_KEV_UPSERT = """
insert into raw.kev_vulnerabilities (
    cve_id, vendor_project, product, vulnerability_name, date_added,
    known_ransomware_campaign_use, catalog_version, catalog_released_at, fetched_at
) values (%s, %s, %s, %s, %s, %s, %s, %s, now())
on conflict (cve_id) do update set
    vendor_project                = excluded.vendor_project,
    product                       = excluded.product,
    vulnerability_name            = excluded.vulnerability_name,
    date_added                    = excluded.date_added,
    known_ransomware_campaign_use = excluded.known_ransomware_campaign_use,
    catalog_version               = excluded.catalog_version,
    catalog_released_at           = excluded.catalog_released_at,
    fetched_at                    = excluded.fetched_at
"""

_EPSS_UPSERT = """
insert into raw.epss_scores (cve_id, epss, percentile, score_date, fetched_at)
values (%s, %s, %s, %s, now())
on conflict (cve_id) do update set
    epss       = excluded.epss,
    percentile = excluded.percentile,
    score_date = excluded.score_date,
    fetched_at = excluded.fetched_at
"""


@dataclass(frozen=True)
class Inputs:
    """What the fetches need from the database."""

    cve_ids: list[str]  # newest first, at most the cap passed to read_inputs
    cve_ids_total: int  # all distinct CVE ids the corpus holds
    kev_entries: int  # entries in the stored latest KEV snapshot (0 if none)


def read_inputs(conn: psycopg.Connection, max_cves: int) -> Inputs:
    with conn.cursor() as cur:
        cur.execute(_CVE_IDS, (CVE_ID_PATTERN, max_cves))
        rows = cur.fetchall()
        cur.execute(_KEV_ENTRIES)
        kev_row = cur.fetchone()
    return Inputs(
        cve_ids=[str(r[0]) for r in rows],
        cve_ids_total=int(rows[0][1]) if rows else 0,
        kev_entries=int(kev_row[0]) if kev_row else 0,
    )


def write_kev(conn: psycopg.Connection, catalog: KevCatalog) -> int:
    rows = [
        (
            e.cve_id,
            e.vendor_project,
            e.product,
            e.vulnerability_name,
            e.date_added,
            e.known_ransomware_campaign_use,
            catalog.catalog_version,
            catalog.released_at,
        )
        for e in catalog.entries
    ]
    with conn.transaction(), conn.cursor() as cur:
        cur.executemany(_KEV_UPSERT, rows)
    return len(rows)


def write_epss(conn: psycopg.Connection, scores: Sequence[EpssScore]) -> int:
    rows = [(s.cve_id, s.epss, s.percentile, s.score_date) for s in scores]
    with conn.transaction(), conn.cursor() as cur:
        cur.executemany(_EPSS_UPSERT, rows)
    return len(rows)
