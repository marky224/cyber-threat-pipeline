{{ config(materialized='table') }}

select
    t.tag,
    count(distinct t.pulse_id)                       as pulse_count,
    count(i.id)                                      as indicator_count
from {{ ref('int_pulse_tag') }} t
left join {{ ref('stg_otx__indicators') }} i on i.pulse_id = t.pulse_id
group by t.tag
order by pulse_count desc
