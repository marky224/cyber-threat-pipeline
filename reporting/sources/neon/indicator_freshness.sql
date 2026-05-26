select
    type,
    freshness_bucket,
    indicator_count
from marts.mart_indicator_freshness
order by type, freshness_bucket;
