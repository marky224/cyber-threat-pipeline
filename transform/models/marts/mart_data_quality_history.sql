{{
    config(
        materialized='incremental',
        incremental_strategy='merge',
        unique_key='run_id',
        full_refresh=false
    )
}}

-- One row per successful run, appended from the one-row mart_data_quality
-- snapshot on every build. full_refresh=false: --full-refresh never wipes it.
select
    run_id,
    started_at,
    watermark_after,
    total_indicators,
    active_indicators,
    expired_indicators,
    dropped_indicators,
    orphan_indicators,
    null_indicator_value,
    pct_active,
    max_pulse_modified,
    now() as recorded_at
from {{ ref('mart_data_quality') }}
