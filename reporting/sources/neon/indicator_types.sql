select
    type,
    indicator_count,
    active_count,
    expired_count,
    dropped_count
from marts.mart_indicator_types
order by indicator_count desc;
