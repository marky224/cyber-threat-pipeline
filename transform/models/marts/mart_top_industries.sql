{{ config(materialized='table') }}

select
    i.industry,
    count(distinct i.pulse_id)                       as pulse_count
from {{ ref('int_pulse_industry') }} i
group by i.industry
order by pulse_count desc
