---
title: Freshness & Data Quality
description: "Analytical freshness of the corpus — active vs expired, per-type freshness, TLP distribution, and data-quality counts."
---

```sql indicator_freshness
select * from neon.indicator_freshness
```

```sql tlp_distribution
select * from neon.tlp_distribution
```

```sql data_quality
select * from neon.data_quality
```

```sql brief_input
select * from neon.brief_input
```

# Freshness & Data Quality

This page is the *analytical* view of corpus health: what does the
indicator pool look like at this build? **It is not operational
freshness** — Grafana owns "is the pipeline running" and "did the last
run succeed." Here we answer "of the indicators we have, how many are
still useful, and what shape is the data in?"

## Indicator freshness by type

Each bar stacks freshness buckets for one indicator type. `expired` and
`no_expiration` are read directly off the indicator's `expiration`
timestamp; `expiring_le_30d` is anything still active but expiring
within 30 days; `active_gt_30d` is everything else.

<BarChart
    data={indicator_freshness}
    x=type
    y=indicator_count
    series=freshness_bucket
    type=stacked
    title="Indicators by type, by freshness"
    swapXY=true
/>

## TLP distribution

Traffic Light Protocol marking across all pulses in the corpus.

<BarChart
    data={tlp_distribution}
    x=tlp
    y=pulse_count
    title="Pulses by TLP marking"
/>

## Data quality snapshot

One row, snapshotted from the most recent successful run.

<DataTable data={data_quality} rows=1>
    <Column id=started_at title="Run started" fmt='yyyy-mm-dd hh:mm' />
    <Column id=total_indicators title="Total" fmt='#,##0' />
    <Column id=active_indicators title="Active" fmt='#,##0' />
    <Column id=expired_indicators title="Expired" fmt='#,##0' />
    <Column id=dropped_indicators title="Dropped" fmt='#,##0' />
    <Column id=orphan_indicators title="Orphan" fmt='#,##0' />
    <Column id=null_indicator_value title="Null value" fmt='#,##0' />
    <Column id=pct_active title="% active" fmt='0.00%' />
</DataTable>

`dropped` = present in `raw.indicators` but no longer attached to its
parent pulse on the latest sync. `orphan` = indicators whose `pulse_id`
doesn't match any pulse we hold (should be zero — flagged by a dbt
test). `null_indicator_value` likewise should be zero.

## Brief input freshness

The [Analyst Brief](/analyst-brief) is generated from the `brief_input`
mart. Its `generated_at` timestamp is the moment the brief was rendered,
not necessarily the current build time.

<DataTable data={brief_input} rows=1>
    <Column id=generated_at title="Brief generated at" fmt='yyyy-mm-dd hh:mm' />
    <Column id=total_pulses title="Pulses" fmt='#,##0' />
    <Column id=total_indicators title="Indicators" fmt='#,##0' />
    <Column id=active_indicators title="Active" fmt='#,##0' />
    <Column id=expired_indicators title="Expired" fmt='#,##0' />
</DataTable>
