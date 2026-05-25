# cyber-threat-pipeline

An incremental, watermark-driven pipeline that turns the **AlienVault OTX** threat-intelligence feed into a longitudinal dataset, transforms it with tested and documented **dbt** models in **Neon Postgres**, publishes a static **Evidence.dev** analytical site, and instruments the pipeline itself with live **Grafana Cloud** observability and alerting.

This is the modern-data-stack successor to [`Threat-Intel-ETL`](https://github.com/marky224/Threat-Intel-ETL). The legacy Splunk surface is removed; the new shape is **AI / Data / Analytics Engineering**.

## Architecture

```
AlienVault OTX
   │  (incremental pull via modified_since)
   ▼
Python ETL (cyber_threat_pipeline/ingestion)
   │  extract → transform (pandas) → load (idempotent upsert)
   ▼
Neon Postgres ── raw schema ──►  dbt (transform/)  ──► marts schema
   │                                                      │
   │ (read-only role)                                     │ (build-time queries)
   ▼                                                      ▼
Grafana Cloud (monitoring/)                         Evidence.dev (reporting/)
  Pipeline health — LIVE, operational, alerting     Static site → S3 + CloudFront
```

Orchestrated by a single weekly **GitHub Actions** cron (plus manual dispatch); a separate CI workflow runs lint, type-check, and tests on every push.

## The Evidence / Grafana split

These two surfaces are deliberately separated:

- **Evidence.dev — the analysis.** Point-in-time, narrative, "what the threat intel *says*." Queries Postgres at build time, bakes results into a static site. Recruiter-facing.
- **Grafana Cloud — the operations.** Time-series, live, "is the pipeline healthy and can I *trust* the data," with alerting. Backed by a read-only Neon role scoped to `marts` and `pipeline_runs`.

The litmus test: *is this about what the data **means** (→ Evidence) or about the **health** of the pipeline / data asset (→ Grafana)?*

## Stack

| Area | Tool |
|---|---|
| Warehouse | Neon (serverless Postgres, pooled connection) |
| Ingestion | Python 3.12, `uv`, pandas, `OTXv2` SDK |
| Transformation | dbt Core (Postgres adapter) |
| Reporting | Evidence.dev → S3 + CloudFront (us-east-1) |
| Monitoring | Grafana Cloud (free tier) |
| Analyst brief | Grok (xAI) + Claude (Anthropic), side-by-side two-model comparison |
| Orchestration | GitHub Actions (weekly cron + dispatch), `Makefile` as single source of truth |
| Infra | Terraform (S3 + OAC + CloudFront + ACM + Route 53 + GitHub OIDC role) |
| Lint / types / tests | ruff · mypy · pytest · pre-commit |

## Repository layout

```
cyber_threat_pipeline/   Python app package (core/, ingestion/, analysis/)
sql/                     Raw schema + pipeline_runs + pipeline_state + grafana_ro role
transform/               dbt Core project (isolated env)
reporting/               Evidence.dev project (Node)
monitoring/              Grafana dashboards + alert rules as code
infra/                   Terraform (deploy bucket, CDN, DNS, OIDC role)
tests/                   pytest
docs/                    Public assets (architecture diagrams, etc.)
.github/workflows/       ci.yml (push/PR) + pipeline.yml (weekly cron + dispatch)
```

## Status

**Scaffolding phase.** The repository structure, tooling, and CI are in place; the per-phase implementations (`sql/` → `ingestion/` → `transform/` → `analysis/` → `reporting/` + `infra/` → `monitoring/`) land in dedicated build phases. This README is fleshed out as each phase ships.

## Local development

```bash
make install      # uv sync (Python 3.12 dev env)
make lint         # ruff
make typecheck    # mypy
make test         # pytest
```

Stage commands (`make ingest`, `make transform`, `make analysis`, `make report`, `make all`) become operative as each phase lands.

## License

[MIT](LICENSE) © Mark Andrew Marquez
