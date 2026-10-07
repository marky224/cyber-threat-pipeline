-- pipeline.runs.dbt_tests_warned — dbt test nodes that ended in `warn`
-- (severity: warn tests that matched rows). Written by `make record-dbt`.
-- Forward-only: 20_pipeline.sql already exists on live databases, so the column
-- arrives through this ALTER. Re-running is a no-op.
ALTER TABLE pipeline.runs ADD COLUMN IF NOT EXISTS dbt_tests_warned integer;
