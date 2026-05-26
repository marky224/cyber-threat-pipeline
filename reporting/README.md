# reporting/ — Evidence.dev analytical site

The public face of the project. Three pages, baked weekly from the marts:

| Page | URL | Source |
|---|---|---|
| Overview / Indicators | `/` | `pages/index.md` |
| Freshness & Data Quality | `/freshness` | `pages/freshness.md` |
| Analyst Brief | `/analyst-brief` | `pages/analyst-brief.md` (written by `cyber_threat_pipeline/analysis` — **do not hand-edit**) |

Spec: `_private/specs/05-reporting-evidence.md`.

## Stack

- **[Evidence](https://evidence.dev/)** v40, Node 20 LTS (pinned in `.nvmrc`).
- **Postgres datasource** (`@evidence-dev/postgres`) — queries the `marts.*` tables on Neon at build time, materializes results into parquet files in `build/data/`. The deployed site is fully static; the browser uses DuckDB-WASM to query the baked parquet.

## Local development

```bash
nvm use                                  # picks up .nvmrc → Node 20
npm install --force                      # initial install (Evidence ships peer-dep conflicts)
EVIDENCE_SOURCE__neon__connectionString="postgresql://<user>:<pw>@<host>:<port>/<db>?sslmode=require" npm run sources
EVIDENCE_SOURCE__neon__connectionString="..." npm run dev   # localhost:3000, live reload
```

`npm install --force` is required because Evidence v40 has internal peer-dep
conflicts (e.g. `svelte2tsx` wants TypeScript ranges that don't perfectly
overlap with `ts-node`'s). `--force` resolves them; the resulting tree works
and is captured in `package-lock.json` for reproducible CI installs (`npm ci`).
`.npmrc` keeps `engine-strict=true` so `nvm use` actually matters.

For a hermetic dry-run against a throwaway database (no Neon needed), see
`_private/handoffs/05-reporting-evidence-build.md` — docker postgres + `sql/`
DDL + `scripts.seed_fixture_corpus` + `make -C transform build` gives you a
populated `marts.*` in seconds.

## Datasource configuration

`sources/neon/connection.yaml` is intentionally empty of options — all
connection details flow in from the environment:

```
EVIDENCE_SOURCE__neon__connectionString=postgresql://<user>:<pw>@<host>:<port>/<db>?sslmode=<mode>
```

Evidence's [env-var override
mechanism](https://docs.evidence.dev/reference/source-environment-variables/)
merges values into the source's options at build time. Using a single
`connectionString` (vs. separate host/port/user/password/ssl env vars) keeps
type-coercion concerns off the table — `pg.Pool` parses the URL natively.

In production the URL is the **pooled** Neon URL (DECISIONS Q9 — many short
parallel queries at build time). The four GitHub Actions secrets the deploy
pipeline expects are `NEON_DATABASE_URL`, `REPORT_BUCKET`,
`CLOUDFRONT_DISTRIBUTION_ID`, and `AWS_DEPLOY_ROLE_ARN` (the last three are
captured from the Terraform stack in `infra/` — see phase 5 Part B).

## SQL sources

`sources/neon/*.sql` — one file per logical query, parameterless. Each file
runs once against Neon at build time and materializes as a DuckDB table at
`neon.<filename>` in the page-side query engine. Pages reference them via
inline `sql` blocks (`select * from neon.<name>`) and feed the results into
Evidence components by name.

| Source | Reads | Used by |
|---|---|---|
| `brief_input.sql` | `marts.brief_input` (with `corpus_header` JSONB flattened) | Overview KPIs, Freshness brief-input footer |
| `indicator_types.sql` | `marts.mart_indicator_types` | Overview bar chart |
| `top_pulses.sql` | `marts.mart_top_pulses` (top 10) | Overview table |
| `targeted_countries.sql` | `marts.mart_targeted_countries` (top 10) | Overview bar chart |
| `threat_tags.sql` | `marts.mart_threat_tags` (top 10) | Overview bar chart |
| `top_industries.sql` | `marts.mart_top_industries` (top 10) | Overview bar chart |
| `pulse_trends_monthly.sql` | `marts.mart_pulse_trends_monthly` (last 12 months) | Overview line charts |
| `indicator_freshness.sql` | `marts.mart_indicator_freshness` | Freshness stacked bar |
| `data_quality.sql` | `marts.mart_data_quality` | Freshness snapshot table |
| `tlp_distribution.sql` | `marts.mart_data_quality.tlp_distribution` (JSONB unpacked) | Freshness bar chart |

## Boundary: `pages/analyst-brief.md` is generated, not hand-edited

`pages/analyst-brief.md` is gitignored. It's regenerated on every `make
analysis` run by `cyber_threat_pipeline.analysis.writer` (phase 4). The
writer owns the page's frontmatter (`title`, `description`) and body
(model briefs in `<Tabs>` or a single block, plus the prompt in a
`<details>` element).

If Evidence ever needs additional frontmatter keys or a different code-block
shape on this page, **amend `cyber_threat_pipeline/analysis/writer.py`,
regenerate, and commit the writer change** — don't edit the markdown. This
is a coordinated spec-04 / spec-05 change; the regeneration policy is
enforced by `.gitignore`.

## Deploy

`make report` (run from the repo root) builds the site and pushes it to S3
+ CloudFront:

```bash
cd reporting && npm ci && npm run build
aws s3 sync reporting/build/ "s3://$REPORT_BUCKET/" --delete
aws cloudfront create-invalidation --distribution-id "$CLOUDFRONT_DISTRIBUTION_ID" --paths "/*"
```

In CI (`.github/workflows/pipeline.yml`) the AWS auth is OIDC — the
`AWS_DEPLOY_ROLE_ARN` role from `infra/` is assumed for the duration of the
job. No static AWS keys.
