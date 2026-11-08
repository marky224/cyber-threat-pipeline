-- Every CVE id in the corpus (marts.mart_cve_enrichment) with its CISA KEV
-- entry and FIRST EPSS score, KEV-listed first, then by EPSS. The KEV vendor,
-- product and name are feed text: the /cves page shows them only as plain
-- (escaped) text. epss_threshold is brief_input's, so the page and the brief
-- share one threshold.
select
    cve_id,
    in_kev,
    kev_date_added,
    kev_vendor_project,
    kev_product,
    kev_vulnerability_name,
    kev_known_ransomware,
    epss,
    epss_percentile,
    epss_score_date,
    pulse_count,
    seen_7d,
    (select (cve_exploitation_7d->>'epss_threshold')::numeric from marts.brief_input) as epss_threshold
from marts.mart_cve_enrichment
order by in_kev desc, epss desc nulls last, cve_id;
