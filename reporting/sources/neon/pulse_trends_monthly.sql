-- Last 12 calendar months; ordered ascending for charting.
select
    month,
    pulse_count,
    indicator_count,
    pulses_first_seen_this_month
from marts.mart_pulse_trends_monthly
where month >= (date_trunc('month', now()) - interval '11 months')::date
order by month asc;
