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
    from {{ ref('stg_otx__indicators') }}
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
    (select max(modified) from {{ ref('stg_otx__pulses') }})           as max_pulse_modified
from run r
cross join indicator_stats s
