{{ config(materialized='table') }}

select
    p.id,
    p.name,
    p.author_name,
    p.created,
    p.modified,
    count(i.id)                                       as indicator_count,
    count(distinct i.type)                            as type_count,
    sum(case when i.is_active then 1 else 0 end)      as active_indicator_count
from {{ ref('stg_otx__pulses') }} p
left join {{ ref('stg_otx__indicators') }} i on i.pulse_id = p.id
group by p.id, p.name, p.author_name, p.created, p.modified
order by indicator_count desc
