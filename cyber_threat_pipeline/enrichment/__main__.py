"""Enrichment orchestrator: ``make enrich`` (``python -m cyber_threat_pipeline.enrichment``).

1. One short database connection reads the corpus's CVE ids (newest first, at
   most ``epss.MAX_CVES``) and the stored KEV snapshot's size, then closes. No
   connection stays open while the feeds download (Neon's pooler drops idle
   ones).
2. KEV: the cisa.gov catalog, else CISA's GitHub mirror. Each is parsed and held
   to the shrink guard, within one 120 s budget.
3. EPSS: the corpus's ids in batches, within 240 s. Every batch must pass, and
   at least one id must come back scored.
4. A fresh connection writes each feed that passed, each in its own transaction.

A feed problem logs a warning, keeps that feed's stored snapshot and leaves the
other feed alone; the step still exits 0. A feed problem is a ``FetchError``, a
``FeedInvalid``, or rows the database refuses to store (``psycopg.DataError`` /
``IntegrityError``, which roll that feed's transaction back; validation should
already have caught them). Any other database error, such as a lost connection,
or a bug raises (exit 1); pipeline.yml runs the step with ``continue-on-error`` so
even that never blocks the publish. Reads
``NEON_DATABASE_URL`` from the environment, as ``make record-dbt`` does.
"""

from __future__ import annotations

import logging
import os
import sys
from time import monotonic
from urllib.parse import urlsplit

import psycopg
import requests

from cyber_threat_pipeline.core.logging import setup_logging
from cyber_threat_pipeline.enrichment import FeedInvalid, epss, fetch, kev, load
from cyber_threat_pipeline.enrichment.epss import EpssScore
from cyber_threat_pipeline.enrichment.kev import KevCatalog

logger = logging.getLogger(__name__)

KEV_BUDGET = 120.0
EPSS_BUDGET = 240.0

# Errors that mean "the database won't store these rows", not "the database is gone".
_REJECTED = (psycopg.DataError, psycopg.IntegrityError)


def run(database_url: str, session: requests.Session | None = None) -> int:
    """Fetch both feeds and write the ones that passed. Returns the exit code."""
    with session or fetch.new_session() as http:
        with psycopg.connect(database_url, autocommit=True) as conn:
            inputs = load.read_inputs(conn, epss.MAX_CVES)
        catalog = _fetch_kev(http, inputs.kev_entries)
        scores = _fetch_epss(http, inputs)
    if catalog is None and scores is None:
        return 0
    with psycopg.connect(database_url, autocommit=True) as conn:
        if catalog is not None:
            try:
                written = load.write_kev(conn, catalog)
            except _REJECTED as e:
                # The class name only: the message can quote the feed's row.
                logger.warning(
                    "KEV: the database rejected the catalog (%s); the stored snapshot stays",
                    type(e).__name__,
                )
            else:
                logger.info("KEV: stored %d entries (catalog %s)", written, catalog.catalog_version)
        if scores is not None:
            try:
                written = load.write_epss(conn, scores)
            except _REJECTED as e:
                logger.warning(
                    "EPSS: the database rejected the scores (%s); the stored scores stay",
                    type(e).__name__,
                )
            else:
                logger.info("EPSS: stored %d scores", written)
    return 0


def _fetch_kev(http: requests.Session, stored_entries: int) -> KevCatalog | None:
    deadline = monotonic() + KEV_BUDGET
    for url in kev.KEV_URLS:
        host = urlsplit(url).hostname
        try:
            body = fetch.get_bytes(http, url, max_bytes=kev.MAX_BYTES, deadline=deadline)
            catalog = kev.parse(body)
            kev.check_shrink(catalog, stored_entries)
        except (fetch.FetchError, FeedInvalid) as e:
            logger.warning("KEV from %s failed: %s", host, e)
            continue
        logger.info(
            "KEV: catalog %s, %d entries, from %s",
            catalog.catalog_version,
            len(catalog.entries),
            host,
        )
        return catalog
    logger.warning("KEV: no valid catalog from any source; the stored snapshot stays")
    return None


def _fetch_epss(http: requests.Session, inputs: load.Inputs) -> list[EpssScore] | None:
    ids = inputs.cve_ids
    if not ids:
        logger.info("EPSS: the corpus holds no CVE ids; nothing to score")
        return None
    if inputs.cve_ids_total > len(ids):
        logger.warning("EPSS: scoring the newest %d of %d CVE ids", len(ids), inputs.cve_ids_total)
    deadline = monotonic() + EPSS_BUDGET
    calls = epss.batches(ids)
    scores: list[EpssScore] = []
    try:
        for batch in calls:
            body = fetch.get_bytes(
                http,
                epss.EPSS_URL,
                params={"cve": ",".join(batch)},
                max_bytes=epss.MAX_BYTES,
                deadline=deadline,
            )
            scores += epss.parse(body, batch)
    except (fetch.FetchError, FeedInvalid) as e:
        logger.warning("EPSS failed: %s; the stored scores stay", e)
        return None
    if not scores:
        # Nothing to write: the stored scores stay and age (Grafana shows it). Say why.
        logger.warning(
            "EPSS: none of %d CVE ids came back scored; the stored scores stay", len(ids)
        )
        return None
    logger.info("EPSS: %d of %d CVE ids scored, in %d call(s)", len(scores), len(ids), len(calls))
    return scores


def main() -> int:
    setup_logging()
    return run(os.environ["NEON_DATABASE_URL"])


if __name__ == "__main__":
    sys.exit(main())
