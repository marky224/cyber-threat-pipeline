select
    industry,
    pulse_count
from marts.mart_top_industries
order by pulse_count desc
limit 10;
