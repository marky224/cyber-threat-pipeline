{{ config(materialized='table') }}

-- One row per CVE id the OTX corpus holds as a CVE indicator, with its entry in
-- the latest CISA KEV snapshot and its score in the latest FIRST EPSS snapshot,
-- when they have one. Indicator values are trimmed and upper-cased; values that
-- still aren't CVE ids (the pattern cyber_threat_pipeline.enrichment uses, at
-- most 24 characters) are left out here and counted in
-- mart_data_quality.cve_indicators_malformed.
with cve_indicators as (
    select
        upper(btrim(indicator)) as cve_id,
        pulse_id,
        is_active,
        first_seen_at
    from {{ ref('int_indicator_freshness') }}
    where type = 'CVE'
),
cves as (
    select
        cve_id,
        count(*)                                          as indicator_count,
        count(distinct pulse_id)                          as pulse_count,
        count(*) filter (where is_active)                 as active_indicator_count,
        min(first_seen_at)                                as first_seen_at,
        -- "This week's CVEs": an active CVE indicator first seen in the last
        -- 7 days, the window brief_input.emerging_indicators_7d uses.
        bool_or(is_active and first_seen_at >= now() - interval '7 days') as seen_7d
    from cve_indicators
    where cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,15}$'
    group by cve_id
)
select
    c.cve_id,
    c.indicator_count,
    c.pulse_count,
    c.active_indicator_count,
    c.first_seen_at,
    c.seen_7d,
    k.cve_id is not null                      as in_kev,
    k.date_added                              as kev_date_added,
    k.vendor_project                          as kev_vendor_project,
    k.product                                 as kev_product,
    k.vulnerability_name                      as kev_vulnerability_name,
    coalesce(k.is_known_ransomware, false)    as kev_known_ransomware,
    e.epss,
    e.percentile                              as epss_percentile,
    e.score_date                              as epss_score_date
from cves c
left join {{ ref('stg_cisa__kev_vulnerabilities') }} k on k.cve_id = c.cve_id
left join {{ ref('stg_first__epss_scores') }} e on e.cve_id = c.cve_id
