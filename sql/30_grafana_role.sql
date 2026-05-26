-- ============================================================
-- grafana_ro  — read-only role for Grafana Cloud
-- ============================================================
-- The role is created without LOGIN privileges; the actual login
-- user (with password) is created OUT-OF-BAND in Neon's UI (or
-- via `CREATE USER grafana_login WITH PASSWORD '...' IN ROLE grafana_ro;`
-- run manually so the password never lands in this file). See runbook.md.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'grafana_ro') THEN
        CREATE ROLE grafana_ro NOLOGIN;
    END IF;
END$$;

COMMENT ON ROLE grafana_ro IS
    'Read-only role used by Grafana Cloud. SELECT on marts.* + pipeline.runs only. No raw access, no write surface.';

-- Schema USAGE — required to "see into" the schemas at all.
GRANT USAGE ON SCHEMA marts    TO grafana_ro;
GRANT USAGE ON SCHEMA pipeline TO grafana_ro;
-- Deliberately NOT granted: USAGE on raw.

-- SELECT on existing tables/views.
GRANT SELECT ON ALL TABLES    IN SCHEMA marts    TO grafana_ro;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA marts    TO grafana_ro;  -- defensive; marts shouldn't expose sequences.
GRANT SELECT ON pipeline.runs                    TO grafana_ro;

-- SELECT on FUTURE objects in marts — dbt rebuilds drop+recreate tables, so
-- the GRANT-on-CURRENT above won't survive. The dbt `+grants` config (spec 03)
-- re-applies on every build, but ALTER DEFAULT PRIVILEGES is the belt-and-
-- braces fallback for marts created OUTSIDE dbt (e.g., ad-hoc views).
ALTER DEFAULT PRIVILEGES IN SCHEMA marts
    GRANT SELECT ON TABLES TO grafana_ro;

-- Explicitly REVOKE any default access to raw (defensive — no role should
-- inherit it, but state this loudly so a future change can't quietly grant it).
REVOKE ALL ON SCHEMA raw FROM grafana_ro;
