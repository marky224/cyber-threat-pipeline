{{ config(materialized='table') }}

with bucketed as (
    select
        type,
        case
            when expiration is null                       then 'no_expiration'
            when is_expired                                then 'expired'
            when expiration <= now() + interval '30 days'  then 'expiring_le_30d'
            else                                                'active_gt_30d'
        end as freshness_bucket
    from {{ ref('stg_otx__indicators') }}
)
select type, freshness_bucket, count(*) as indicator_count
from bucketed
group by type, freshness_bucket
order by type, freshness_bucket
