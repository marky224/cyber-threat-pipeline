-- Single-row snapshot from the most recent successful run; the freshness
-- page renders the scalar columns directly and unpacks tlp_distribution
-- (jsonb) into a bar chart via tlp_distribution.sql.
--
-- pct_active in mart_data_quality is a 0-100 percentage (kept that way
-- because the Grafana data-quality panel reads it as a percent-unit
-- numeric). Evidence's `0.00%` format multiplies by 100 at render time,
-- so we divide by 100 here — otherwise the page renders "10000.00%"
-- instead of "100.00%". The mart value is unchanged.
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
    pct_active / 100.0 as pct_active
from marts.mart_data_quality;
