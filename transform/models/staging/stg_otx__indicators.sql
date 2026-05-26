{{
    config(
        materialized='incremental',
        incremental_strategy='merge',
        unique_key='id',
        on_schema_change='append_new_columns'
    )
}}

with src as (
    select * from {{ source('raw', 'indicators') }}
    {% if is_incremental() %}
        where synced_at > (select coalesce(max(synced_at), '-infinity'::timestamptz) from {{ this }})
    {% endif %}
),
pulse_sync as (
    -- Latest synced_at of indicators in each pulse, used for drop-out detection (Q6).
    -- Reads the FULL raw table, not src — a drop-out is detected by comparing to
    -- indicators *not* in the incremental window.
    select
        pulse_id,
        max(synced_at) as pulse_latest_synced_at
    from {{ source('raw', 'indicators') }}
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
    s.is_active                     as is_active_otx,
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
from src s
left join pulse_sync p on s.pulse_id = p.pulse_id
