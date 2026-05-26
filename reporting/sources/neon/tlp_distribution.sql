-- Unpack mart_data_quality.tlp_distribution (jsonb) into a (tlp, pulse_count)
-- shape suitable for a bar chart. Spec 05 §A6.2.
select
    key   as tlp,
    value::int as pulse_count
from marts.mart_data_quality,
     jsonb_each_text(tlp_distribution)
order by pulse_count desc;
