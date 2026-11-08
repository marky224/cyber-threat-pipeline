---
title: Exploited CVEs
description: "The corpus's CVE indicators against CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS scores."
---

```sql cve_enrichment
select * from neon.cve_enrichment
order by in_kev desc, epss desc nulls last, cve_id
```

```sql cve_kpis
select
    count(*)                                                as cve_ids,
    count(*) filter (where in_kev)                          as in_kev,
    count(*) filter (where in_kev and kev_known_ransomware) as in_kev_ransomware,
    count(*) filter (where epss >= epss_threshold)          as epss_high,
    max(epss_threshold)                                     as epss_threshold
from neon.cve_enrichment
```

```sql feeds
select kev_catalog_version, kev_fetched_at, epss_score_date
from neon.data_quality
```

# Exploited CVEs

Which of the CVE ids in the corpus are being exploited, and how likely
exploitation is. **Known exploited** means the id is in the latest CISA
Known Exploited Vulnerabilities (KEV) catalog. **EPSS** is FIRST's
probability that a CVE is exploited in the next 30 days; its percentile
ranks it among all scored CVEs. A CVE id counts here when the corpus holds
it as a CVE indicator; ids that appear only in pulse names or tags don't.

{#if feeds[0]?.kev_fetched_at == null}

**KEV data isn't available yet**: the KEV catalog hasn't been fetched, so
this page can't say which CVEs are known exploited.

{/if}

## Headline

<BigValue data={cve_kpis} value=cve_ids title="CVE ids in the corpus" fmt='#,##0' />
{#if feeds[0]?.kev_fetched_at != null}
<BigValue data={cve_kpis} value=in_kev title="In CISA KEV" fmt='#,##0' />
<BigValue data={cve_kpis} value=in_kev_ransomware title="In KEV, known ransomware use" fmt='#,##0' />
{/if}
{#if feeds[0]?.epss_score_date != null}
<BigValue data={cve_kpis} value=epss_high title="EPSS at or above the threshold" fmt='#,##0' />
{/if}

The EPSS threshold is <Value data={cve_kpis} column=epss_threshold />, the
one the [Analyst Brief](/analyst-brief) uses.

## Every CVE in the corpus

KEV-listed CVEs first, then by EPSS score. An id FIRST doesn't score has no
EPSS value.

<DataTable data={cve_enrichment} search=true rows=25>
    <Column id=cve_id title="CVE" />
    <Column id=in_kev title="In KEV" />
    <Column id=kev_date_added title="Added to KEV" fmt='yyyy-mm-dd' />
    <Column id=kev_vendor_project title="Vendor" />
    <Column id=kev_product title="Product" />
    <Column id=kev_vulnerability_name title="KEV name" />
    <Column id=kev_known_ransomware title="Ransomware use" />
    <Column id=epss title="EPSS" fmt='0.0%' />
    <Column id=epss_percentile title="EPSS percentile" fmt='0.0%' />
    <Column id=pulse_count title="Pulses" fmt='#,##0' />
    <Column id=seen_7d title="New this week" />
</DataTable>

## Sources

As of this build: KEV catalog version <Value data={feeds} column=kev_catalog_version />,
fetched <Value data={feeds} column=kev_fetched_at fmt='yyyy-mm-dd' />; EPSS scores of
<Value data={feeds} column=epss_score_date fmt='yyyy-mm-dd' />. Both feeds are
fetched weekly, before the site is built.

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (CC0).
- [FIRST Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/).
