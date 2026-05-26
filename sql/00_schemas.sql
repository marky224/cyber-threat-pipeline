-- Create the three schemas. Idempotent.
CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS pipeline;
CREATE SCHEMA IF NOT EXISTS marts;

COMMENT ON SCHEMA raw      IS 'Raw OTX feed truth + ingestion audit columns. Read only by dbt sources.';
COMMENT ON SCHEMA pipeline IS 'Operational state: append-only runs audit + single-row watermark.';
COMMENT ON SCHEMA marts    IS 'dbt-built marts. Surface for Evidence (build-time) and Grafana (read-only).';
