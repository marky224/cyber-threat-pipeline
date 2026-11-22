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
    -f 32_kev_epss.sql \
    -f 33_analyst_role.sql
```

Re-running is safe and a no-op on tables that already exist. An existing
database needs only the files added since it was last applied (for example
`21_runs_dbt_tests_warned.sql`). `31_brief_evals.sql` comes after
`30_grafana_role.sql` because it grants SELECT to `grafana_ro`.
`32_kev_epss.sql` (the CISA KEV and FIRST EPSS tables `make enrich` writes)
grants nothing: `grafana_ro` never reads `raw`. Apply it before deploying
code that builds the KEV/EPSS dbt models, or `dbt build` fails on the
missing sources.
`33_analyst_role.sql` creates `analyst_ro`, the threat-data analyst's
read-only role: USAGE on `marts` only, and no USAGE on `raw` or `pipeline`.
Its SELECT on the 11 mart models comes from dbt's `+grants`, never from a
schema-wide or default grant. The file's last two lines clear default grants
on tables to it that the role running the file set, in `marts` and globally,
so run it as the owner dbt builds as. Apply it before deploying a
`transform/dbt_project.yml` that names `analyst_ro` in `+grants`, or
`dbt build` fails on the grant to a missing role.

## Bootstrapping a new Neon database

1. Enable Neon, create a project + database (free tier is fine).
2. Capture the **pooled** connection string and store as `NEON_DATABASE_URL`.
3. Apply this DDL once with the command above.
4. Create the Grafana login user manually:
   ```sql
   CREATE USER grafana_login WITH PASSWORD '<paste-secret>' IN ROLE grafana_ro;
   ```
   Store `grafana_login`'s password in Grafana Cloud's data-source config.
   See the runbook (private) for details.
5. Create the analyst's login through psql on the owner URL, never in Neon's
   SQL editor or on its Roles page. No statement holds the password: psql's
   `\password` prompts for it and sends only a SCRAM verifier, so it never
   reaches a query history or a statement log.
   ```bash
   psql "$NEON_DATABASE_URL" -v ON_ERROR_STOP=1
   ```
   ```sql
   CREATE ROLE analyst_login LOGIN IN ROLE analyst_ro;
   \password analyst_login
   ALTER ROLE analyst_login SET statement_timeout = '5s';
   ALTER ROLE analyst_login SET default_transaction_read_only = on;
   ALTER ROLE analyst_login SET idle_in_transaction_session_timeout = '30s';
   ```
   Then check that the login is a member of `analyst_ro` only and can't use
   `raw`:
   ```sql
   -- lists only analyst_login and analyst_ro
   SELECT r.rolname FROM pg_roles r WHERE pg_has_role('analyst_login', r.oid, 'member');
   -- false
   SELECT has_schema_privilege('analyst_login', 'raw', 'usage');
   ```
