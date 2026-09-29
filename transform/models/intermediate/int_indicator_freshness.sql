{{ config(materialized='view') }}

-- Live Q6 freshness flags. stg_otx__indicators is incremental, so its flags
-- are frozen at each row's last sync; recompute them here against the current
-- clock and the current per-pulse max(synced_at). Marts read flags from here.
with pulse_sync as (
    select
        pulse_id,
        max(synced_at) as pulse_latest_synced_at
    from {{ ref('stg_otx__indicators') }}
    group by pulse_id
)
select
    s.id,
    s.pulse_id,
    s.indicator,
    s.type,
    s.title,
    s.description,
    s.access_reason,
    s.created,
    s.is_active_otx,
    s.access_type,
    s.content,
    s.role,
    s.expiration,
    s.access_groups,
    s.observations,
    s.first_seen_at,
    s.synced_at,
    case when s.expiration is null or s.expiration > now() then false else true end as is_expired,
    case when s.synced_at < p.pulse_latest_synced_at        then true  else false end as is_dropped,
    case
        when (s.expiration is null or s.expiration > now())
         and s.synced_at >= p.pulse_latest_synced_at
        then true
        else false
    end as is_active
from {{ ref('stg_otx__indicators') }} s
left join pulse_sync p on s.pulse_id = p.pulse_id
