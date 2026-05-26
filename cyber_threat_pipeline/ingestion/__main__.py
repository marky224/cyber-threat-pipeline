"""Orchestrator — composes config + run lifecycle + extract + transform + load.

Spec: _private/specs/02-ingestion.md §9.
Entrypoint: ``python -m cyber_threat_pipeline.ingestion``  (wired via Makefile ``ingest``).
"""

from __future__ import annotations

import logging
import sys

from cyber_threat_pipeline.core import db
from cyber_threat_pipeline.core.config import Settings
from cyber_threat_pipeline.core.logging import setup_logging
from cyber_threat_pipeline.core.runs import detect_git_sha, run, sweep_stale
from cyber_threat_pipeline.ingestion import extract, load, transform, watermark


def main() -> int:
    setup_logging()
    logger = logging.getLogger(__name__)

    settings = Settings()
    conn = db.connect(settings)

    try:
        sweep_stale(conn, threshold_minutes=settings.stale_running_threshold_minutes)

        with run(
            conn,
            trigger=settings.trigger,
            git_sha=detect_git_sha(),
            notes={"force_full_backfill": settings.force_full_backfill},
        ) as handle:
            if settings.force_full_backfill:
                logger.warning("FORCE_FULL_BACKFILL set — wiping watermark")
                watermark.force_cold_start(conn, run_id=handle.id)

            modified_since = watermark.read(conn)
            handle.set(watermark_before=modified_since)
            handle.flush()

            pulses = extract.extract_pulses(
                api_key=settings.otx_api_key.get_secret_value(),
                modified_since=modified_since,
            )
            handle.set(
                pulses_fetched=len(pulses),
                indicators_fetched=sum(len(p.get("indicators", [])) for p in pulses),
            )
            handle.flush()

            if not pulses:
                logger.info("No pulses returned; no-op success.")
                handle.set(
                    pulses_upserted=0,
                    indicators_upserted=0,
                    pulses_inserted=0,
                    indicators_inserted=0,
                )
                return 0

            pulse_rows, indicator_rows = transform.transform(pulses)
            new_watermark = transform.max_modified(pulses)

            p_up, p_ins, i_up, i_ins = load.load(
                conn,
                pulse_rows,
                indicator_rows,
                batch_size=settings.upsert_batch_size,
            )
            handle.set(
                pulses_upserted=p_up,
                pulses_inserted=p_ins,
                indicators_upserted=i_up,
                indicators_inserted=i_ins,
            )

            watermark.write(conn, modified_since=new_watermark, run_id=handle.id)
            handle.set(watermark_after=new_watermark)

    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
