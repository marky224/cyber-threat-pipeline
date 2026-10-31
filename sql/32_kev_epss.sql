-- ============================================================
-- raw.kev_vulnerabilities  — CISA Known Exploited Vulnerabilities catalog
-- raw.epss_scores          — FIRST EPSS scores for the corpus's CVE ids
-- ============================================================
-- Written by `make enrich` (cyber_threat_pipeline/enrichment). Each successful
-- fetch of a feed upserts its rows in one transaction with fetched_at = now()
-- (the transaction timestamp), so one snapshot shares one fetched_at. A row a
-- newer snapshot no longer has keeps its older fetched_at; dbt staging reads
-- only the latest snapshot. Nothing is deleted. Forward-only and re-runnable.
-- No grafana_ro grant: grafana_ro never reads raw; feed freshness reaches
-- Grafana through marts.mart_data_quality.

CREATE TABLE IF NOT EXISTS raw.kev_vulnerabilities (
    cve_id                          text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    vendor_project                  text,
    product                         text,
    vulnerability_name              text,
    date_added                      date NOT NULL,
    known_ransomware_campaign_use   text,
    catalog_version                 text NOT NULL,
    catalog_released_at             timestamptz NOT NULL,
    fetched_at                      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  raw.kev_vulnerabilities            IS 'CISA KEV catalog entries, upserted per fetch. Latest snapshot = rows with max(fetched_at).';
COMMENT ON COLUMN raw.kev_vulnerabilities.cve_id     IS 'KEV cveID. Validated against the CVE id pattern before load.';
COMMENT ON COLUMN raw.kev_vulnerabilities.date_added IS 'KEV dateAdded: the day CISA listed the CVE.';
COMMENT ON COLUMN raw.kev_vulnerabilities.known_ransomware_campaign_use IS 'KEV knownRansomwareCampaignUse, as published (Known / Unknown).';
COMMENT ON COLUMN raw.kev_vulnerabilities.catalog_version IS 'KEV catalogVersion of the fetch that last wrote this row.';
COMMENT ON COLUMN raw.kev_vulnerabilities.fetched_at IS 'now() of the fetch that last wrote this row; equal across one snapshot.';

CREATE TABLE IF NOT EXISTS raw.epss_scores (
    cve_id      text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    epss        numeric(10, 9) NOT NULL CHECK (epss BETWEEN 0 AND 1),
    percentile  numeric(10, 9) NOT NULL CHECK (percentile BETWEEN 0 AND 1),
    score_date  date NOT NULL,
    fetched_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  raw.epss_scores            IS 'FIRST EPSS scores for CVE ids in raw.indicators, upserted per fetch. Latest snapshot = rows with max(fetched_at).';
COMMENT ON COLUMN raw.epss_scores.epss       IS 'Probability of exploitation in the next 30 days, 0-1.';
COMMENT ON COLUMN raw.epss_scores.percentile IS 'Rank of epss among all CVEs FIRST scores, 0-1. Not a probability.';
COMMENT ON COLUMN raw.epss_scores.score_date IS 'The EPSS date the score was published for.';
COMMENT ON COLUMN raw.epss_scores.fetched_at IS 'now() of the fetch that last wrote this row; equal across one snapshot.';
