-- ============================================================
-- pipeline.brief_evals  — grounding scores for the analyst brief
-- ============================================================
-- One row per provider brief scored by `make analysis`
-- (cyber_threat_pipeline/analysis/eval.py). Append-only. Forward-only and
-- re-runnable; numbered after 30_grafana_role.sql because it grants to
-- grafana_ro, which that file creates.
CREATE TABLE IF NOT EXISTS pipeline.brief_evals (
    id                      bigserial PRIMARY KEY,
    run_id                  bigint REFERENCES pipeline.runs(id),
    evaluated_at            timestamptz NOT NULL DEFAULT now(),
    brief_generated_at      timestamptz NOT NULL,
    provider                text NOT NULL,
    model                   text NOT NULL,
    words                   integer NOT NULL,
    facts_total             integer NOT NULL,
    facts_verified          integer NOT NULL,
    findings                jsonb NOT NULL,
    judge_model             text,
    judge_claims_total      integer,
    judge_claims_supported  integer
);

COMMENT ON TABLE pipeline.brief_evals IS
    'Grounding checks on each analyst brief: facts_verified/facts_total from the deterministic checks, findings as [{check, text, detail}], optional judge claim counts. run_id = latest pipeline.runs row at analysis time (in pipeline.yml, the run that just ingested; NULL only when pipeline.runs is empty).';

CREATE INDEX IF NOT EXISTS brief_evals_evaluated_at_idx ON pipeline.brief_evals (evaluated_at DESC);

GRANT SELECT ON pipeline.brief_evals TO grafana_ro;
