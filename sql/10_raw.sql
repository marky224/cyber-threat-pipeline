-- ============================================================
-- raw.pulses
-- ============================================================
CREATE TABLE IF NOT EXISTS raw.pulses (
    id                  varchar(50) PRIMARY KEY,
    name                text NOT NULL,
    description         text,
    author_name         varchar(100),
    public              boolean,
    revision            integer,
    adversary           varchar(100),
    industries          jsonb,
    tlp                 varchar(10) CHECK (tlp IN ('white','green','amber','red')),
    tags                jsonb,
    created             timestamp,
    modified            timestamp,
    "references"        jsonb,
    targeted_countries  jsonb,
    -- Audit columns (Q2, Q3): ownership = ingestion.
    first_seen_at       timestamptz NOT NULL DEFAULT now(),
    synced_at           timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  raw.pulses                    IS 'OTX pulses (top-level threat metadata). Idempotent upsert by ingestion.';
COMMENT ON COLUMN raw.pulses.modified           IS 'OTX-supplied modification timestamp. Drives the pipeline.state watermark (Q1).';
COMMENT ON COLUMN raw.pulses.first_seen_at      IS 'Write-once. Set on INSERT, never updated. Drives new-vs-returning analysis (Q2).';
COMMENT ON COLUMN raw.pulses.synced_at          IS 'Rewritten on every upsert. dbt incremental cursor and drop-out detection (Q3, Q6).';

-- Index supporting watermark + dbt incremental cursor reads.
CREATE INDEX IF NOT EXISTS pulses_modified_idx   ON raw.pulses (modified);
CREATE INDEX IF NOT EXISTS pulses_synced_at_idx  ON raw.pulses (synced_at);

-- ============================================================
-- raw.indicators
-- ============================================================
CREATE TABLE IF NOT EXISTS raw.indicators (
    id              bigint PRIMARY KEY,
    pulse_id        varchar(50) REFERENCES raw.pulses(id) ON DELETE CASCADE,
    indicator       text NOT NULL,
    type            varchar(50),
    title           text,
    description     text,
    access_reason   text,
    created         timestamp,
    is_active       boolean,
    access_type     varchar(20) CHECK (access_type IN ('public','private','redacted')),
    content         text,
    role            text,
    expiration      timestamp,
    access_groups   jsonb,
    observations    integer,
    -- Audit columns (Q2, Q3).
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    synced_at       timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  raw.indicators                IS 'OTX indicators (IoCs). Idempotent upsert by ingestion. Expired indicators are kept (Q6).';
COMMENT ON COLUMN raw.indicators.is_active      IS 'OTX-supplied; NOT canonical. Canonical active = (not expired AND not dropped); computed in dbt (Q6).';
COMMENT ON COLUMN raw.indicators.expiration     IS 'NULL = non-expiring. Otherwise canonical expiry: expiration > now() (Q6).';
COMMENT ON COLUMN raw.indicators.first_seen_at  IS 'Write-once (Q2).';
COMMENT ON COLUMN raw.indicators.synced_at      IS 'Rewritten on every upsert. Drives drop-out detection vs. parent pulse synced_at (Q6).';

-- Indexes supporting common joins + dbt incremental cursor.
CREATE INDEX IF NOT EXISTS indicators_pulse_id_idx    ON raw.indicators (pulse_id);
CREATE INDEX IF NOT EXISTS indicators_synced_at_idx   ON raw.indicators (synced_at);
CREATE INDEX IF NOT EXISTS indicators_type_idx        ON raw.indicators (type);
CREATE INDEX IF NOT EXISTS indicators_expiration_idx  ON raw.indicators (expiration) WHERE expiration IS NOT NULL;
