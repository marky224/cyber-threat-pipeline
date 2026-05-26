select
    id,
    name,
    author_name,
    created,
    modified,
    indicator_count,
    type_count,
    active_indicator_count
from marts.mart_top_pulses
order by indicator_count desc
limit 10;
