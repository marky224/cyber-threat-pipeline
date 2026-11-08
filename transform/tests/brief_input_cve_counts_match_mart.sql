-- brief_input.cve_exploitation_7d must agree with mart_cve_enrichment, the
-- unit-tested mart it summarizes. Returns one row per broken rule. A mismatch
-- is a bug in brief_input, not a feed quirk, so this runs at error severity.
-- A feed with no snapshot leaves its counts NULL (spec B9), so each expected
-- count is NULL too unless that feed's staging view has a row: the first run,
-- with both feed tables empty, must pass. The threshold and the cap are read
-- from the row, the one place brief_input writes them.
with brief as (
    select cve_exploitation_7d as x from {{ ref('brief_input') }}
),
week as (
    select cve_id, in_kev, epss
    from {{ ref('mart_cve_enrichment') }}
    where seen_7d
),
loaded as (
    select
        exists (select 1 from {{ ref('stg_cisa__kev_vulnerabilities') }}) as kev,
        exists (select 1 from {{ ref('stg_first__epss_scores') }})        as epss
),
actual as (
    select
        (x->>'cves')::bigint                 as cves,
        (x->>'in_kev')::bigint               as in_kev,
        (x->>'epss_high')::bigint            as epss_high,
        (x->>'epss_high_not_in_kev')::bigint as epss_high_not_in_kev,
        (x->>'epss_threshold')::numeric      as epss_threshold,
        jsonb_array_length(x->'kev_cves')    as kev_cves_listed,
        (x->>'kev_cves_cap')::int            as kev_cves_cap
    from brief
),
expected as (
    select
        (select count(*) from week) as cves,
        case when l.kev then (select count(*) from week where in_kev) end as in_kev,
        case when l.epss then
            (select count(*) from week where epss >= a.epss_threshold) end as epss_high,
        case when l.kev and l.epss then
            (select count(*) from week where epss >= a.epss_threshold and not in_kev)
        end as epss_high_not_in_kev
    from loaded l
    cross join actual a
),
-- The KEV-listed ids in the order the brief must list them.
kev_rank as (
    select cve_id, row_number() over (order by epss desc nulls last, cve_id) as rn
    from week
    where in_kev
),
listed as (
    select l.cve_id, l.pos
    from brief b
    cross join jsonb_array_elements_text(b.x->'kev_cves') with ordinality as l(cve_id, pos)
)
select 'cves' as broken_rule
from actual a cross join expected e
where a.cves is distinct from e.cves
union all
select 'in_kev'
from actual a cross join expected e
where a.in_kev is distinct from e.in_kev
union all
select 'epss_high'
from actual a cross join expected e
where a.epss_high is distinct from e.epss_high
union all
select 'epss_high_not_in_kev'
from actual a cross join expected e
where a.epss_high_not_in_kev is distinct from e.epss_high_not_in_kev
union all
-- Every KEV-listed id of the week, up to the cap: never more, never fewer.
select 'kev_cves length'
from actual a cross join expected e
where a.kev_cves_cap is null
   or a.kev_cves_listed is distinct from least(coalesce(e.in_kev, 0), a.kev_cves_cap)
union all
select 'kev_cves holds an id that is not this week''s and in KEV: ' || l.cve_id
from listed l
left join kev_rank r on r.cve_id = l.cve_id
where r.cve_id is null
union all
select 'kev_cves out of order at ' || l.cve_id
from listed l
join kev_rank r on r.cve_id = l.cve_id
where r.rn <> l.pos
