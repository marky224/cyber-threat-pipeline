-- Single-row snapshot from the most recent successful run; the freshness
-- page renders the scalar columns directly and unpacks tlp_distribution
-- (jsonb) into a bar chart via tlp_distribution.sql.
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
    pct_active
from marts.mart_data_quality;
