{{ config(materialized='view') }}

select
    p.id as pulse_id,
    country
from {{ ref('stg_otx__pulses') }} p,
     lateral jsonb_array_elements_text(p.targeted_countries) as country
where p.targeted_countries is not null
