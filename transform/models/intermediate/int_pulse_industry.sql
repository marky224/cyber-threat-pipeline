{{ config(materialized='view') }}

select
    p.id as pulse_id,
    industry
from {{ ref('stg_otx__pulses') }} p,
     lateral jsonb_array_elements_text(p.industries) as industry
where p.industries is not null
