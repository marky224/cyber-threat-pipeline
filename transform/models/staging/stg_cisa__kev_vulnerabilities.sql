-- The latest CISA KEV snapshot. `make enrich` upserts every entry of a fetched
-- catalog with one fetched_at (its transaction's now()); an entry CISA dropped
-- keeps an older fetched_at and falls out here.
select
    cve_id,
    vendor_project,
    product,
    vulnerability_name,
    date_added,
    coalesce(known_ransomware_campaign_use = 'Known', false) as is_known_ransomware,
    catalog_version,
    catalog_released_at,
    fetched_at
from {{ source('raw', 'kev_vulnerabilities') }}
where fetched_at = (select max(fetched_at) from {{ source('raw', 'kev_vulnerabilities') }})
