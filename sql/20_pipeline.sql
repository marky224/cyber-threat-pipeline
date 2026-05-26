-- ============================================================
-- pipeline.runs  — append-only run audit (insert-at-start, Q4)
-- ============================================================
CREATE TABLE IF NOT EXISTS pipeline.runs (
    id                    bigserial PRIMARY KEY,
    started_at            timestamptz NOT NULL DEFAULT now(),
    finished_at           timestamptz,
    status                text NOT NULL
                          CHECK (status IN ('running','success','failed','partial','orphaned')),
    trigger               text NOT NULL,
    git_sha               text,
    watermark_before      timestamp,
    watermark_after       timestamp,
    pulses_fetched        integer,
    pulses_upserted       integer,
    pulses_inserted       integer,
    indicators_fetched    integer,
    indicators_upserted   integer,
    indicators_inserted   integer,
    dbt_tests_passed      integer,
    dbt_tests_failed      integer,
    dbt_tests_skipped     integer,
    duration_seconds      integer,
    error_message         text,
    notes                 jsonb
);

COMMENT ON TABLE  pipeline.runs IS
    'Append-only run audit. Insert-at-start with status=running; updated as the run progresses; terminal status (success/failed/partial/orphaned) seals the row.';

CREATE INDEX IF NOT EXISTS runs_started_at_idx        ON pipeline.runs (started_at DESC);
CREATE INDEX IF NOT EXISTS runs_status_started_idx    ON pipeline.runs (status, started_at DESC);

-- ============================================================
-- pipeline.state  — single-row watermark (Q1)
-- ============================================================
CREATE TABLE IF NOT EXISTS pipeline.state (
    singleton           boolean PRIMARY KEY DEFAULT true CHECK (singleton = true),
    modified_since      timestamp,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    updated_by_run_id   bigint REFERENCES pipeline.runs(id)
);

COMMENT ON TABLE pipeline.state IS
    'Single-row watermark for OTX incremental ingest. modified_since = the timestamp passed as modified_since to OTXv2.getall() on the next run. NULL = cold start = full backfill (Q1).';

-- Idempotent seed: ensure exactly one row exists with modified_since = NULL on first apply.
-- Subsequent applies are no-ops because the singleton row already exists.
INSERT INTO pipeline.state (singleton, modified_since)
VALUES (true, NULL)
ON CONFLICT (singleton) DO NOTHING;
