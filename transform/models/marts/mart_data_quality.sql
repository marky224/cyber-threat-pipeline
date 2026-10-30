{{ config(materialized='table') }}

with run as (
    select id as run_id, started_at, watermark_after
    from {{ source('pipeline', 'runs') }}
    where status = 'success'
    order by started_at desc
    limit 1
),
tlp_dist as (
    select tlp, count(*) as pulse_count
    from {{ ref('stg_otx__pulses') }}
    group by tlp
),
indicator_stats as (
    select
        count(*)                                                       as total_indicators,
        sum(case when is_active     then 1 else 0 end)                 as active_indicators,
        sum(case when is_expired    then 1 else 0 end)                 as expired_indicators,
        sum(case when is_dropped    then 1 else 0 end)                 as dropped_indicators,
        sum(case when pulse_id is null then 1 else 0 end)              as orphan_indicators,
        sum(case when indicator is null then 1 else 0 end)             as null_indicator_value
    from {{ ref('int_indicator_freshness') }}
),
-- Vulnerability feeds: when each was last fetched successfully (Grafana's
-- feed-age panel and alert read these; NULL until the first fetch), and how
-- much of the corpus's CVE indicators they cover.
kev as (
    select max(catalog_version) as kev_catalog_version, max(fetched_at) as kev_fetched_at
    from {{ ref('stg_cisa__kev_vulnerabilities') }}
),
epss as (
    select max(score_date) as epss_score_date, max(fetched_at) as epss_fetched_at
    from {{ ref('stg_first__epss_scores') }}
),
cve_stats as (
    select
        count(*)                                  as cve_ids,
        count(*) filter (where in_kev)            as cve_ids_in_kev,
        count(*) filter (where epss is not null)  as cve_ids_with_epss
    from {{ ref('mart_cve_enrichment') }}
),
cve_malformed as (
    -- CVE indicators mart_cve_enrichment leaves out: not a CVE id after trimming
    -- and upper-casing, or longer than 24 characters.
    select count(*) as cve_indicators_malformed
    from {{ ref('int_indicator_freshness') }}
    where type = 'CVE'
      and upper(btrim(indicator)) !~ '^CVE-[0-9]{4}-[0-9]{4,15}$'
)
select
    r.run_id,
    r.started_at,
    r.watermark_after,
    (select coalesce(jsonb_object_agg(tlp, pulse_count), '{}'::jsonb) from tlp_dist) as tlp_distribution,
    s.total_indicators,
    s.active_indicators,
    s.expired_indicators,
    s.dropped_indicators,
    s.orphan_indicators,
    s.null_indicator_value,
    case when s.total_indicators > 0
         then round(100.0 * s.active_indicators / s.total_indicators, 2)
         else 0 end                                                    as pct_active,
    (select max(modified) from {{ ref('stg_otx__pulses') }})           as max_pulse_modified,
    k.kev_catalog_version,
    k.kev_fetched_at,
    e.epss_score_date,
    e.epss_fetched_at,
    c.cve_ids,
    c.cve_ids_in_kev,
    c.cve_ids_with_epss,
    m.cve_indicators_malformed
from run r
cross join indicator_stats s
cross join kev k
cross join epss e
cross join cve_stats c
cross join cve_malformed m
