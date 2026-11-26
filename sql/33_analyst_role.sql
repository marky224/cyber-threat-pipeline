-- ============================================================
-- analyst_ro  — read-only role for the threat-data analyst
-- ============================================================
-- NOLOGIN: the login (analyst_login) is created by hand through psql,
-- with its password set by `\password` (sql/README.md), so no password
-- lands in this file. SELECT on the 11 mart models comes from dbt's
-- +grants (transform/dbt_project.yml), re-applied on every build.
--
-- No schema-wide or default GRANT: dbt also builds the staging and
-- intermediate models into marts as the same owner, and the staging
-- views read raw with their owner's rights.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'analyst_ro') THEN
        CREATE ROLE analyst_ro NOLOGIN;
    END IF;
END$$;

COMMENT ON ROLE analyst_ro IS
    'Read-only role for the threat-data analyst: SELECT on the 11 mart models only, granted by dbt +grants. No raw, pipeline, staging or intermediate access.';

-- Schema USAGE on marts only; SELECT on each mart comes from dbt.
GRANT USAGE ON SCHEMA marts TO analyst_ro;

-- Deliberately NOT granted: USAGE on raw or pipeline, and SELECT on any
-- table by schema-wide or default grants.
REVOKE ALL ON SCHEMA raw      FROM analyst_ro;
REVOKE ALL ON SCHEMA pipeline FROM analyst_ro;

-- Re-runnable: these two lines clear default grants on tables to analyst_ro
-- that the role running this file set, in marts and globally (no IN SCHEMA).
-- Run the file as the owner dbt builds as, so they cover the role that
-- creates the marts; they don't touch defaults set by any other role.
-- Default privileges persist (pg_default_acl), so a re-run is what cleans one.
ALTER DEFAULT PRIVILEGES IN SCHEMA marts REVOKE ALL ON TABLES FROM analyst_ro;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM analyst_ro;
