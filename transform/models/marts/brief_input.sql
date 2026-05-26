{{ config(materialized='table') }}

with corpus_totals as (
    select
        (select count(*) from {{ ref('stg_otx__pulses') }})                                   as total_pulses,
        (select count(*) from {{ ref('stg_otx__indicators') }})                                as total_indicators,
        (select count(*) from {{ ref('stg_otx__indicators') }} where is_active)                as active_indicators,
        (select count(*) from {{ ref('stg_otx__indicators') }} where is_expired)               as expired_indicators
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
        from {{ ref('stg_otx__indicators') }}
        where first_seen_at >= now() - interval '7 days' and is_active
        group by type
    ) t
)
select
    now()                                                  as generated_at,
    (select to_jsonb(c.*) from corpus_totals c)            as corpus_header,
    (select top_types from top_types)                      as top_types,
    (select top_countries from top_countries)              as top_countries,
    (select top_tags from top_tags)                        as top_tags,
    (select top_industries from top_industries)            as top_industries,
    (select emerging_pulses_7d from emerging_pulses_7d)    as emerging_pulses_7d,
    (select emerging_indicators_7d from emerging_indicators_7d) as emerging_indicators_7d
