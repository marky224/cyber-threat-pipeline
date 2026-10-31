# sql/

Forward-only, idempotent DDL for the cyber-threat-pipeline Neon database.

## Apply order

```bash
psql "$NEON_DATABASE_URL" -v ON_ERROR_STOP=1 \
    -f 00_schemas.sql \
    -f 10_raw.sql \
    -f 20_pipeline.sql \
    -f 21_runs_dbt_tests_warned.sql \
    -f 30_grafana_role.sql \
    -f 31_brief_evals.sql \
    -f 32_kev_epss.sql
```

Re-running is safe and a no-op on tables that already exist. An existing
database needs only the files added since it was last applied (for example
`21_runs_dbt_tests_warned.sql`). `31_brief_evals.sql` comes after
`30_grafana_role.sql` because it grants SELECT to `grafana_ro`.
`32_kev_epss.sql` (the CISA KEV and FIRST EPSS tables `make enrich` writes)
grants nothing: `grafana_ro` never reads `raw`. Apply it before deploying
code that builds the KEV/EPSS dbt models, or `dbt build` fails on the
missing sources.

## Bootstrapping a new Neon database

1. Enable Neon, create a project + database (free tier is fine).
2. Capture the **pooled** connection string and store as `NEON_DATABASE_URL`.
3. Apply this DDL once with the command above.
4. Create the Grafana login user manually:
   ```sql
   CREATE USER grafana_login WITH PASSWORD '<paste-secret>' IN ROLE grafana_ro;
   ```
   Store `grafana_login`'s password in Grafana Cloud's data-source config.
   See `_private/specs/runbook.md` for details.
