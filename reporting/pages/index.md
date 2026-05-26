---
title: Cyber Threat Pipeline
description: "Weekly snapshot of the AlienVault OTX corpus — pulses, indicators, targeting, and trends."
---

```sql brief_input
select * from neon.brief_input
```

```sql indicator_types
select * from neon.indicator_types
```

```sql top_pulses
select * from neon.top_pulses
```

```sql targeted_countries
select * from neon.targeted_countries
```

```sql threat_tags
select * from neon.threat_tags
```

```sql top_industries
select * from neon.top_industries
```

```sql pulse_trends_monthly
select * from neon.pulse_trends_monthly
```

# Cyber Threat Pipeline

A weekly-baked view of the threat intelligence corpus we ingest from
[AlienVault OTX](https://otx.alienvault.com/). The site is rebuilt every
Monday alongside the pipeline — KPIs, breakdowns, and the
[Analyst Brief](/analyst-brief) all reflect that run.

**This page is the analytical view ("what does the corpus say?"). For
pipeline health and freshness alerts, see Grafana.**

## Headline

<BigValue data={brief_input} value=total_pulses title="Total pulses" fmt='#,##0' />
<BigValue data={brief_input} value=total_indicators title="Total indicators" fmt='#,##0' />
<BigValue data={brief_input} value=active_indicators title="Active indicators" fmt='#,##0' />
<BigValue data={brief_input} value=expired_indicators title="Expired indicators" fmt='#,##0' />

## Indicator type breakdown

How the corpus splits across indicator types (hashes, IPs, domains, URLs,
etc.). Active vs expired is rolled into one bar per type — see the
[Freshness](/freshness) page for the per-bucket detail.

<BarChart
    data={indicator_types}
    x=type
    y=indicator_count
    title="Indicators by type"
    swapXY=true
/>

## Top 10 pulses

Pulses with the most indicators in the current corpus.

<DataTable data={top_pulses} rows=10>
    <Column id=name title="Pulse" />
    <Column id=author_name title="Author" />
    <Column id=indicator_count title="Indicators" fmt='#,##0' />
    <Column id=active_indicator_count title="Active" fmt='#,##0' />
    <Column id=type_count title="Types" />
    <Column id=modified title="Last modified" fmt='yyyy-mm-dd' />
</DataTable>

## Targeting

### Top 10 targeted countries

<BarChart
    data={targeted_countries}
    x=country
    y=pulse_count
    title="Pulses by targeted country"
    swapXY=true
/>

### Top 10 tags

<BarChart
    data={threat_tags}
    x=tag
    y=pulse_count
    title="Pulses by tag"
    swapXY=true
/>

### Top 10 targeted industries

<BarChart
    data={top_industries}
    x=industry
    y=pulse_count
    title="Pulses by targeted industry"
    swapXY=true
/>

## Monthly trend (last 12 months)

<LineChart
    data={pulse_trends_monthly}
    x=month
    y=pulse_count
    title="Pulses created per month"
    yAxisTitle="Pulses"
/>

<LineChart
    data={pulse_trends_monthly}
    x=month
    y=indicator_count
    title="Indicators per month"
    yAxisTitle="Indicators"
/>
