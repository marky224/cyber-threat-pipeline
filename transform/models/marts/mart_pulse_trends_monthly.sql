{{ config(materialized='table') }}

select
    date_trunc('month', p.created)::date              as month,
    count(distinct p.id)                              as pulse_count,
    count(i.id)                                       as indicator_count,
    count(distinct p.id) filter
        (where p.first_seen_at >= date_trunc('month', p.first_seen_at))
                                                      as pulses_first_seen_this_month
from {{ ref('stg_otx__pulses') }} p
left join {{ ref('stg_otx__indicators') }} i on i.pulse_id = p.id
group by 1
order by 1 desc
