-- One-row corpus snapshot. The dbt mart stores headline counts inside a
-- JSONB ``corpus_header`` blob (so the prompt-builder can pass it as one
-- payload); Evidence components expect flat columns, so unpack here.
select
    generated_at,
    (corpus_header->>'total_pulses')::bigint      as total_pulses,
    (corpus_header->>'total_indicators')::bigint  as total_indicators,
    (corpus_header->>'active_indicators')::bigint as active_indicators,
    (corpus_header->>'expired_indicators')::bigint as expired_indicators
from marts.brief_input;
