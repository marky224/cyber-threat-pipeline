{{ config(materialized='table') }}

with corpus_totals as (
    select
        (select count(*) from {{ ref('stg_otx__pulses') }})                                   as total_pulses,
        (select count(*) from {{ ref('int_indicator_freshness') }})                                as total_indicators,
        (select count(*) from {{ ref('int_indicator_freshness') }} where is_active)                as active_indicators,
        (select count(*) from {{ ref('int_indicator_freshness') }} where is_expired)               as expired_indicators
),
top_types as (
    select coalesce(
        jsonb_agg(jsonb_build_object('type', type, 'count', indicator_count) order by indicator_count desc),
        '[]'::jsonb
    ) as top_types
    from (
        select type, indicator_count
        from {{ ref('mart_indicator_types') }}
        order by indicator_count desc
        limit 5
    ) t
),
top_countries as (
    select coalesce(
        jsonb_agg(jsonb_build_object('country', country, 'pulse_count', pulse_count) order by pulse_count desc),
        '[]'::jsonb
    ) as top_countries
    from (
        select country, pulse_count
        from {{ ref('mart_targeted_countries') }}
        order by pulse_count desc
        limit 5
    ) t
),
top_tags as (
    select coalesce(
        jsonb_agg(jsonb_build_object('tag', tag, 'pulse_count', pulse_count) order by pulse_count desc),
        '[]'::jsonb
    ) as top_tags
    from (
        select tag, pulse_count
        from {{ ref('mart_threat_tags') }}
        order by pulse_count desc
        limit 5
    ) t
),
top_industries as (
    select coalesce(
        jsonb_agg(jsonb_build_object('industry', industry, 'pulse_count', pulse_count) order by pulse_count desc),
        '[]'::jsonb
    ) as top_industries
    from (
        select industry, pulse_count
        from {{ ref('mart_top_industries') }}
        order by pulse_count desc
        limit 5
    ) t
),
emerging_pulses_7d as (
    select coalesce(
        jsonb_agg(jsonb_build_object(
            'id',                 p.id,
            'name',               p.name,
            'description',        p.description,
            'tlp',                p.tlp,
            'tags',               p.tags,
            'targeted_countries', p.targeted_countries,
            'first_seen_at',      p.first_seen_at,
            'indicator_count',    tp.indicator_count
        ) order by p.first_seen_at desc),
        '[]'::jsonb
    ) as emerging_pulses_7d
    from {{ ref('stg_otx__pulses') }} p
    join {{ ref('mart_top_pulses') }} tp on tp.id = p.id
    where p.first_seen_at >= now() - interval '7 days'
),
emerging_indicators_7d as (
    select coalesce(
        jsonb_agg(jsonb_build_object('type', type, 'count', cnt) order by cnt desc),
        '[]'::jsonb
    ) as emerging_indicators_7d
    from (
        select type, count(*) as cnt
        from {{ ref('int_indicator_freshness') }}
        where first_seen_at >= now() - interval '7 days' and is_active
        group by type
    ) t
),
-- The EPSS threshold and the cap on listed KEV ids, written only here: the
-- prompt, the eval and the /cves page read them from this row.
cve_params as (
    select 0.1::numeric as epss_threshold, 15 as kev_cves_cap
),
-- loaded is false until a feed's first successful fetch. Its counts are then
-- NULL, never 0, so the brief can't say "0 in KEV" for a feed it never read.
kev_snapshot as (
    select
        count(*) > 0                                        as loaded,
        (max(catalog_released_at) at time zone 'UTC')::date as catalog_date
    from {{ ref('stg_cisa__kev_vulnerabilities') }}
),
epss_snapshot as (
    select count(*) > 0 as loaded, max(score_date) as score_date
    from {{ ref('stg_first__epss_scores') }}
),
-- This week's CVEs: the same 7-day window as emerging_indicators_7d.
week_cves as (
    select cve_id, in_kev, epss
    from {{ ref('mart_cve_enrichment') }}
    where seen_7d
),
kev_ranked as (
    select cve_id, row_number() over (order by epss desc nulls last, cve_id) as rn
    from week_cves
    where in_kev
),
-- Only counts, the threshold, CVE ids and ISO dates: no KEV free text (vendor,
-- product, name, catalogVersion) reaches the prompt.
cve_exploitation_7d as (
    select jsonb_build_object(
        'cves',                 (select count(*) from week_cves),
        'in_kev',               case when k.loaded then
                                    (select count(*) from week_cves where in_kev) end,
        'epss_high',            case when e.loaded then
                                    (select count(*) from week_cves where epss >= p.epss_threshold) end,
        'epss_high_not_in_kev', case when k.loaded and e.loaded then
                                    (select count(*) from week_cves
                                     where epss >= p.epss_threshold and not in_kev) end,
        'epss_threshold',       p.epss_threshold,
        'kev_cves',             coalesce((select jsonb_agg(cve_id order by rn) from kev_ranked
                                          where rn <= p.kev_cves_cap), '[]'::jsonb),
        'kev_cves_cap',         p.kev_cves_cap,
        'kev_catalog_date',     k.catalog_date,
        'epss_score_date',      e.score_date
    ) as cve_exploitation_7d
    from cve_params p
    cross join kev_snapshot k
    cross join epss_snapshot e
)
select
    now()                                                  as generated_at,
    (select to_jsonb(c.*) from corpus_totals c)            as corpus_header,
    (select top_types from top_types)                      as top_types,
    (select top_countries from top_countries)              as top_countries,
    (select top_tags from top_tags)                        as top_tags,
    (select top_industries from top_industries)            as top_industries,
    (select emerging_pulses_7d from emerging_pulses_7d)    as emerging_pulses_7d,
    (select emerging_indicators_7d from emerging_indicators_7d) as emerging_indicators_7d,
    (select cve_exploitation_7d from cve_exploitation_7d)  as cve_exploitation_7d
