{{ config(materialized='table') }}

select
    type,
    count(*)                                       as indicator_count,
    sum(case when is_active  then 1 else 0 end)    as active_count,
    sum(case when is_expired then 1 else 0 end)    as expired_count,
    sum(case when is_dropped then 1 else 0 end)    as dropped_count
from {{ ref('stg_otx__indicators') }}
group by type
order by indicator_count desc
