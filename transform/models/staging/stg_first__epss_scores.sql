-- The latest FIRST EPSS snapshot. `make enrich` upserts every score of a fetch
-- with one fetched_at; an id that fetch didn't score keeps an older one and
-- falls out here, so it reads as unscored rather than as a stale score.
select
    cve_id,
    epss,
    percentile,
    score_date,
    fetched_at
from {{ source('raw', 'epss_scores') }}
where fetched_at = (select max(fetched_at) from {{ source('raw', 'epss_scores') }})
