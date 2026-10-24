"""Analyst-brief orchestrator: prompt → providers → markdown.

Spec: _private/specs/04-analysis-llm.md §6, extended to N swappable providers.

Steps:
  1. Resolve the configured provider list from Settings.provider_slots()
     (``ANALYSIS_PROVIDERS`` comma-separated list, or legacy
     ``ANALYSIS_PRIMARY_PROVIDER`` / ``ANALYSIS_SECONDARY_PROVIDER``).
  2. Fail fast if any selected slot needs a credential we don't have —
     that's a config error, not a runtime one (spec §8.4).
  3. Fetch ``marts.brief_input`` and build the prompt deterministically.
  4. Run each provider; per-provider exceptions render a visible-failure
     placeholder so the page is degraded, not silently fictional (§4.3 / §8.5).
  5. Score each brief with the deterministic grounding checks (``eval.py``)
     and, if ``ANALYSIS_JUDGE`` is set, the optional LLM judge (``judge.py``).
     Warn-only: a crash in either drops the score, never the page.
  6. Write ``reporting/pages/analyst-brief.md``.
  7. Store the scores in ``pipeline.brief_evals`` (``sql/31_brief_evals.sql``),
     linked to the latest ``pipeline.runs`` row. Also warn-only.

The model id sent to each cloud provider is pinned in code (claude.py
``DEFAULT_MODEL`` and grok.py ``DEFAULT_MODEL``) and forwarded to the
provider's API in the request body — Anthropic and xAI do NOT auto-select
a model on the backend; the field is required and the API would return
HTTP 400 if it were omitted. Operators can override via ``CLAUDE_MODEL``
/ ``GROK_MODEL`` / ``LOCAL_MODEL`` env vars; the model that was actually
used is logged on each call below so the run audit trail records it.

This step does NOT open or update a ``pipeline.runs`` row. The orchestration
phase (spec 07) wraps ingest → transform → analysis in one run row; the
scores only reference it.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import asdict, replace
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb
from pydantic import SecretStr

from cyber_threat_pipeline.analysis import eval as eval_mod
from cyber_threat_pipeline.analysis import judge as judge_mod
from cyber_threat_pipeline.analysis import prompt as prompt_mod
from cyber_threat_pipeline.analysis import providers as providers_mod
from cyber_threat_pipeline.analysis import writer
from cyber_threat_pipeline.analysis.providers import Provider
from cyber_threat_pipeline.core import db, runs
from cyber_threat_pipeline.core.config import Settings
from cyber_threat_pipeline.core.logging import setup_logging

logger = logging.getLogger(__name__)


def _resolve_credential(provider: Provider, cfg: Settings) -> str:
    """Return the credential string (api key or base url) for a provider.

    Raises ``RuntimeError`` if the slot picks a provider whose required key
    isn't in the environment — a config error, surfaced before any LLM call.
    """
    value = getattr(cfg, provider.credential_attr)
    if provider.credential_kind == "api_key":
        if value is None:
            raise RuntimeError(
                f"Provider {provider.name!r} requires {provider.credential_attr.upper()}"
                " but it isn't set"
            )
        # SecretStr from Settings — extract.
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        return str(value)
    # base_url — plain string, always present (Settings default applies).
    return str(value)


def _run_provider(provider: Provider, credential: str, prompt_str: str) -> writer.ProviderResult:
    """Call one provider; render a placeholder on failure (per §4.3)."""
    logger.info(
        "Provider %s: sending prompt to model %r (no backend auto-selection)",
        provider.name,
        provider.default_model,
    )
    failed = False
    try:
        if provider.credential_kind == "api_key":
            text = provider.query(prompt_str, api_key=credential)
        else:
            text = provider.query(prompt_str, base_url=credential)
    except Exception as e:
        logger.exception("Provider %s failed", provider.name)
        text = f"_{provider.display_label} brief unavailable: {type(e).__name__}: {e}_"
        failed = True
    return writer.ProviderResult(
        name=provider.name,
        label=provider.display_label,
        model=provider.default_model,
        text=text,
        failed=failed,
    )


def _evaluate(result: writer.ProviderResult, brief: dict[str, Any]) -> eval_mod.EvalResult | None:
    """Score one brief; never raises (a broken check must not block the page)."""
    if result.failed:
        return None
    try:
        scored = eval_mod.evaluate(result.text, brief)
    except Exception:
        logger.warning(
            "Grounding checks failed for %s; page keeps no score", result.name, exc_info=True
        )
        return None
    logger.info(
        "Grounding for %s: %d/%d facts verified, %d findings",
        result.name,
        scored.facts_verified,
        scored.facts_total,
        len(scored.findings),
    )
    for f in scored.findings:
        logger.warning("Grounding %s [%s]: %s | %s", result.name, f.check, f.detail, f.text)
    return scored


def _judge(
    result: writer.ProviderResult, prompt_str: str, cfg: Settings
) -> judge_mod.JudgeScore | None:
    """Optional judge score; never raises."""
    try:
        return judge_mod.judge(prompt_str, result.text, cfg)
    except Exception:
        logger.warning("Brief judge crashed for %s; no judge score", result.name, exc_info=True)
        return None


def _grounding_line(ev: eval_mod.EvalResult, js: judge_mod.JudgeScore | None) -> str:
    extra = f"Judge: {js.supported}/{js.total} claims supported ({js.model})." if js else None
    return ev.grounding_line(extra)


def _store_scores(
    cfg: Settings,
    brief: dict[str, Any],
    scored: list[
        tuple[writer.ProviderResult, eval_mod.EvalResult | None, judge_mod.JudgeScore | None]
    ],
) -> None:
    """Insert one pipeline.brief_evals row per scored brief; never raises.

    Runs after the page is written, on a fresh connection: the one that read
    ``brief_input`` sat idle through the LLM calls, and the Neon pooler may
    have closed it. A missing table (sql/31 not applied yet) or any other DB
    error only costs the rows, never the publish.
    """
    rows = [(r, ev, js) for r, ev, js in scored if ev is not None]
    if not rows:
        return
    try:
        with db.connect(cfg) as conn, conn.transaction(), conn.cursor() as cur:
            run_id = runs.latest_run_id(conn)
            for r, ev, js in rows:
                cur.execute(
                    """
                    INSERT INTO pipeline.brief_evals
                        (run_id, brief_generated_at, provider, model, words,
                         facts_total, facts_verified, findings,
                         judge_model, judge_claims_total, judge_claims_supported)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        run_id,
                        brief["generated_at"],
                        r.name,
                        r.model,
                        ev.words,
                        ev.facts_total,
                        ev.facts_verified,
                        Jsonb([asdict(f) for f in ev.findings]),
                        js.model if js else None,
                        js.total if js else None,
                        js.supported if js else None,
                    ),
                )
        logger.info("Stored %d grounding score(s) for run %s", len(rows), run_id)
    except Exception:
        logger.warning("Could not store grounding scores; page unaffected", exc_info=True)


def run(cfg: Settings | None = None) -> int:
    """Build and write the analyst brief. Returns a process exit code."""
    cfg = cfg or Settings()

    slot_names = cfg.provider_slots()
    slots = [providers_mod.resolve(name) for name in slot_names]
    logger.info(
        "Analyst-brief slots: %s",
        ", ".join(f"{p.name}({p.default_model})" for p in slots),
    )

    # Resolve credentials BEFORE opening any connection or hitting any API.
    # If a selected slot is misconfigured, we surface it as a clear startup
    # error rather than a half-built page.
    creds: dict[str, str] = {}
    for p in slots:
        if p.name not in creds:
            creds[p.name] = _resolve_credential(p, cfg)

    conn = psycopg.connect(str(cfg.neon_database_url))
    try:
        brief = prompt_mod.fetch_brief_input(conn)
        prompt_str = prompt_mod.build_prompt(brief)

        results = writer.dedupe([_run_provider(p, creds[p.name], prompt_str) for p in slots])
        scored = []
        for r in results:
            ev = _evaluate(r, brief)
            scored.append((r, ev, _judge(r, prompt_str, cfg) if ev else None))
        results = [
            replace(r, grounding=_grounding_line(ev, js)) if ev else r for r, ev, js in scored
        ]

        path = writer.write_brief(
            generated_at=datetime.now(UTC),
            prompt=prompt_str,
            results=results,
        )
        logger.info("Wrote analyst brief to %s", path)
        _store_scores(cfg, brief, scored)
    finally:
        conn.close()
    return 0


def main() -> int:
    setup_logging()
    return run()


if __name__ == "__main__":
    sys.exit(main())
