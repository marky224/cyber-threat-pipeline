select
    tag,
    pulse_count,
    indicator_count
from marts.mart_threat_tags
order by pulse_count desc
limit 10;
