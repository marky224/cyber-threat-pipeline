"""Analyst-brief orchestrator: prompt → providers → markdown.

Spec: _private/specs/04-analysis-llm.md §6, extended to N swappable providers.

Steps:
  1. Resolve the two configured provider slots from Settings
     (``ANALYSIS_PRIMARY_PROVIDER`` / ``ANALYSIS_SECONDARY_PROVIDER``).
  2. Fail fast if a selected slot needs a credential we don't have — that's
     a config error, not a runtime one (spec §8.4).
  3. Fetch ``marts.brief_input`` and build the prompt deterministically.
  4. Run each provider; per-provider exceptions render a visible-failure
     placeholder so the page is degraded, not silently fictional (§4.3 / §8.5).
  5. Write ``reporting/pages/analyst-brief.md``.

This step does NOT open its own ``pipeline.runs`` row in v1. The orchestration
phase (spec 07) wraps ingest → transform → analysis in one run row.
"""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime

import psycopg
from pydantic import SecretStr

from cyber_threat_pipeline.analysis import prompt as prompt_mod
from cyber_threat_pipeline.analysis import providers as providers_mod
from cyber_threat_pipeline.analysis import writer
from cyber_threat_pipeline.analysis.providers import Provider
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
    try:
        if provider.credential_kind == "api_key":
            text = provider.query(prompt_str, api_key=credential)
        else:
            text = provider.query(prompt_str, base_url=credential)
    except Exception as e:
        logger.exception("Provider %s failed", provider.name)
        text = f"_{provider.display_label} brief unavailable: {type(e).__name__}: {e}_"
    return writer.ProviderResult(
        name=provider.name,
        label=provider.display_label,
        model=provider.default_model,
        text=text,
    )


def run(cfg: Settings | None = None) -> int:
    """Build and write the analyst brief. Returns a process exit code."""
    cfg = cfg or Settings()

    primary = providers_mod.resolve(cfg.analysis_primary_provider)
    secondary = providers_mod.resolve(cfg.analysis_secondary_provider)

    # Resolve credentials BEFORE opening any connection or hitting any API.
    # If a selected slot is misconfigured, we surface it as a clear startup
    # error rather than a half-built page.
    creds: dict[str, str] = {}
    for p in (primary, secondary):
        if p.name not in creds:
            creds[p.name] = _resolve_credential(p, cfg)

    conn = psycopg.connect(str(cfg.neon_database_url))
    try:
        brief = prompt_mod.fetch_brief_input(conn)
        prompt_str = prompt_mod.build_prompt(brief)

        results = [
            _run_provider(primary, creds[primary.name], prompt_str),
            _run_provider(secondary, creds[secondary.name], prompt_str),
        ]

        path = writer.write_brief(
            generated_at=datetime.now(UTC),
            prompt=prompt_str,
            results=results,
        )
        logger.info("Wrote analyst brief to %s", path)
    finally:
        conn.close()
    return 0


def main() -> int:
    setup_logging()
    return run()


if __name__ == "__main__":
    sys.exit(main())
