{{ config(materialized='view') }}

select
    p.id as pulse_id,
    tag
from {{ ref('stg_otx__pulses') }} p,
     lateral jsonb_array_elements_text(p.tags) as tag
where p.tags is not null
