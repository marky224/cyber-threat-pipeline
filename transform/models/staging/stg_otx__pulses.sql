{{ config(materialized='view') }}

select
    id,
    name,
    description,
    author_name,
    public,
    revision,
    adversary,
    industries,
    tlp,
    tags,
    created,
    modified,
    "references"        as refs,
    targeted_countries,
    first_seen_at,
    synced_at
from {{ source('raw', 'pulses') }}
