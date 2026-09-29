{{ config(materialized='table') }}

select
    c.country,
    count(distinct c.pulse_id)                       as pulse_count,
    count(i.id)                                      as indicator_count,
    sum(case when i.is_active then 1 else 0 end)     as active_indicator_count
from {{ ref('int_pulse_country') }} c
left join {{ ref('int_indicator_freshness') }} i on i.pulse_id = c.pulse_id
group by c.country
order by pulse_count desc
