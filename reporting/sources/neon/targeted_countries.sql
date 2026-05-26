select
    country,
    pulse_count,
    indicator_count,
    active_indicator_count
from marts.mart_targeted_countries
order by pulse_count desc
limit 10;
