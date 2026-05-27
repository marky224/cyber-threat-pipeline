"""Orchestrator tests for cyber_threat_pipeline.analysis.__main__.

Everything network-touching is monkeypatched: no LLM HTTP, no Postgres.
The provider registry's ``query`` callables are replaced; the DB connection
returned by ``psycopg.connect`` is a stub that yields a fixture brief row.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from cyber_threat_pipeline.analysis import __main__ as orchestrator
from cyber_threat_pipeline.analysis import providers as providers_mod


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop every env var that Settings reads so each test sets its own.

    Also override Settings.model_config to set ``env_file=None`` so that
    a developer's local .env doesn't leak into the test environment.
    PYDANTIC_SETTINGS_DISABLE_DOTENV is not a real pydantic-settings env
    var; the model_config override is the supported way to bypass the
    .env source.
    """
    for key in (
        "ANALYSIS_PROVIDERS",
        "ANALYSIS_PRIMARY_PROVIDER",
        "ANALYSIS_SECONDARY_PROVIDER",
        "ANTHROPIC_API_KEY",
        "XAI_API_KEY",
        "OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "OLLAMA_BASE_URL",
        "CLAUDE_MODEL",
        "GROK_MODEL",
        "LOCAL_MODEL",
        "LOCAL_NUM_CTX",
        "OTX_API_KEY",
        "NEON_DATABASE_URL",
    ):
        monkeypatch.delenv(key, raising=False)
    # Disable Pydantic-Settings' .env file reader at the class-config level.
    from pydantic_settings import SettingsConfigDict

    from cyber_threat_pipeline.core.config import Settings

    monkeypatch.setattr(
        Settings,
        "model_config",
        SettingsConfigDict(env_file=None, env_file_encoding="utf-8", extra="ignore"),
    )


@pytest.fixture()
def stub_brief() -> dict[str, Any]:
    from datetime import UTC, datetime

    return {
        "generated_at": datetime(2026, 5, 26, tzinfo=UTC),
        "corpus_header": {
            "total_pulses": 10,
            "total_indicators": 20,
            "active_indicators": 15,
            "expired_indicators": 5,
        },
        "top_types": [{"type": "domain", "count": 5}],
        "top_countries": [{"country": "US", "pulse_count": 4}],
        "top_tags": [{"tag": "phishing", "pulse_count": 3}],
        "top_industries": [{"industry": "Finance", "pulse_count": 2}],
        "emerging_pulses_7d": [],
        "emerging_indicators_7d": [],
    }


@pytest.fixture()
def patch_db_and_prompt(monkeypatch: pytest.MonkeyPatch, stub_brief: dict[str, Any]) -> None:
    """Swap psycopg.connect + fetch_brief_input so no DB is touched."""
    fake_conn = MagicMock()
    monkeypatch.setattr(
        "cyber_threat_pipeline.analysis.__main__.psycopg.connect",
        lambda _url: fake_conn,
    )
    monkeypatch.setattr(
        "cyber_threat_pipeline.analysis.prompt.fetch_brief_input",
        lambda _conn: stub_brief,
    )


@pytest.fixture()
def output_page(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    """Redirect the writer's PAGE_PATH to a tmp file."""
    target = tmp_path / "pages" / "analyst-brief.md"
    monkeypatch.setattr("cyber_threat_pipeline.analysis.writer.PAGE_PATH", target)
    yield target


def _settings(**overrides: Any) -> Any:
    """Construct Settings with safe defaults so we don't need the real env."""
    from cyber_threat_pipeline.core.config import Settings

    base = {
        "NEON_DATABASE_URL": "postgresql://u:p@localhost:5432/db",
        "OTX_API_KEY": "fake-otx",
    }
    base.update({k: v for k, v in overrides.items()})
    return Settings.model_validate(base)


def _patch_provider_query(monkeypatch: pytest.MonkeyPatch, name: str, fn: Any) -> None:
    """Replace one provider's query callable for the duration of a test."""
    original = providers_mod.PROVIDERS[name]  # type: ignore[index]
    patched = providers_mod.Provider(
        name=original.name,
        query=fn,
        default_model=original.default_model,
        credential_kind=original.credential_kind,
        credential_attr=original.credential_attr,
        display_label=original.display_label,
    )
    new_registry = dict(providers_mod.PROVIDERS)
    new_registry[name] = patched  # type: ignore[index]
    monkeypatch.setattr(providers_mod, "PROVIDERS", new_registry)


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_default_two_local_slots_collapse_to_single_block(
    monkeypatch: pytest.MonkeyPatch,
    patch_db_and_prompt: None,
    output_page: Path,
) -> None:
    """Default config: both slots 'local' → writer renders one block."""
    captured: list[str] = []

    def fake_local(prompt: str, **_kw: Any) -> str:
        captured.append(prompt)
        return "local brief body"

    _patch_provider_query(monkeypatch, "local", fake_local)

    rc = orchestrator.run(cfg=_settings())
    assert rc == 0

    content = output_page.read_text(encoding="utf-8")
    assert "<Tabs>" not in content
    assert "local brief body" in content
    # The same prompt was sent to each slot — both slots resolve to 'local'.
    assert len(captured) == 2
    assert captured[0] == captured[1]


def test_two_distinct_providers_render_stacked(
    monkeypatch: pytest.MonkeyPatch,
    patch_db_and_prompt: None,
    output_page: Path,
) -> None:
    """N>1 providers render as a vertical stack with `---` between blocks
    (NOT Evidence <Tabs> — Evidence's Svelte markdown preprocessor doesn't
    nest multi-paragraph markdown reliably inside Tab components)."""
    _patch_provider_query(monkeypatch, "claude", lambda _p, **_kw: "claude body")
    _patch_provider_query(monkeypatch, "grok", lambda _p, **_kw: "grok body")

    rc = orchestrator.run(
        cfg=_settings(
            ANALYSIS_PRIMARY_PROVIDER="claude",
            ANALYSIS_SECONDARY_PROVIDER="grok",
            ANTHROPIC_API_KEY="sk-ant-test",
            XAI_API_KEY="xai-test",
        )
    )
    assert rc == 0

    content = output_page.read_text(encoding="utf-8")
    assert "<Tabs>" not in content
    assert "claude body" in content
    assert "grok body" in content
    assert "\n\n---\n\n" in content


def test_prompt_is_round_tripped_in_details(
    monkeypatch: pytest.MonkeyPatch,
    patch_db_and_prompt: None,
    output_page: Path,
) -> None:
    seen: list[str] = []

    def fake_local(prompt: str, **_kw: Any) -> str:
        seen.append(prompt)
        return "body"

    _patch_provider_query(monkeypatch, "local", fake_local)
    orchestrator.run(cfg=_settings())

    content = output_page.read_text(encoding="utf-8")
    assert "<details>" in content
    # The prompt the model received is the same one rendered in the details
    # block (byte-identical). The opening fence is tagged ```code so the
    # block isn't parsed as a SQL query by Evidence's preprocessor.
    sent = seen[0]
    open_fence = "```code\n"
    fence_start = content.index(open_fence, content.index("<details>"))
    fence_end = content.index("```", fence_start + len(open_fence))
    rendered = content[fence_start + len(open_fence) : fence_end].strip("\n")
    assert rendered == sent.strip("\n")


# ---------------------------------------------------------------------------
# Partial-failure path — §8.5
# ---------------------------------------------------------------------------


def test_one_provider_failure_renders_visible_placeholder(
    monkeypatch: pytest.MonkeyPatch,
    patch_db_and_prompt: None,
    output_page: Path,
) -> None:
    """Claude 503s; Grok works. Page renders both — Claude as a placeholder."""

    def failing_claude(_prompt: str, **_kw: Any) -> str:
        raise RuntimeError("upstream 503 from anthropic")

    _patch_provider_query(monkeypatch, "claude", failing_claude)
    _patch_provider_query(monkeypatch, "grok", lambda _p, **_kw: "grok body")

    rc = orchestrator.run(
        cfg=_settings(
            ANALYSIS_PRIMARY_PROVIDER="claude",
            ANALYSIS_SECONDARY_PROVIDER="grok",
            ANTHROPIC_API_KEY="sk-ant-test",
            XAI_API_KEY="xai-test",
        )
    )
    # Per spec §4.3, the surrounding run is NOT failed by a per-provider error.
    assert rc == 0

    content = output_page.read_text(encoding="utf-8")
    assert (
        "_Claude (Anthropic) brief unavailable: RuntimeError: upstream 503 from anthropic_"
        in content
    )
    assert "grok body" in content


def test_both_providers_failing_still_renders_page(
    monkeypatch: pytest.MonkeyPatch,
    patch_db_and_prompt: None,
    output_page: Path,
) -> None:
    def boom(_prompt: str, **_kw: Any) -> str:
        raise ValueError("network unreachable")

    _patch_provider_query(monkeypatch, "claude", boom)
    _patch_provider_query(monkeypatch, "grok", boom)

    rc = orchestrator.run(
        cfg=_settings(
            ANALYSIS_PRIMARY_PROVIDER="claude",
            ANALYSIS_SECONDARY_PROVIDER="grok",
            ANTHROPIC_API_KEY="sk-ant-test",
            XAI_API_KEY="xai-test",
        )
    )
    assert rc == 0

    content = output_page.read_text(encoding="utf-8")
    assert "Claude (Anthropic) brief unavailable" in content
    assert "Grok (xAI) brief unavailable" in content


# ---------------------------------------------------------------------------
# Fail-fast on missing credentials — §8.4 (adapted to swappable design)
# ---------------------------------------------------------------------------


def test_missing_api_key_for_selected_cloud_provider_fails_fast(
    monkeypatch: pytest.MonkeyPatch,
    patch_db_and_prompt: None,
    output_page: Path,
) -> None:
    """If a slot picks 'claude' but ANTHROPIC_API_KEY is unset, raise before any LLM call."""
    called = False

    def should_not_run(_prompt: str, **_kw: Any) -> str:
        nonlocal called
        called = True
        return "should never get here"

    _patch_provider_query(monkeypatch, "claude", should_not_run)
    _patch_provider_query(monkeypatch, "grok", should_not_run)

    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        orchestrator.run(
            cfg=_settings(
                ANALYSIS_PRIMARY_PROVIDER="claude",
                ANALYSIS_SECONDARY_PROVIDER="grok",
                # ANTHROPIC_API_KEY deliberately omitted.
                XAI_API_KEY="xai-test",
            )
        )
    assert called is False
    assert not output_page.exists()


def test_unknown_provider_name_raises(patch_db_and_prompt: None, output_page: Path) -> None:
    with pytest.raises(ValueError, match="Unknown analysis provider"):
        orchestrator.run(
            cfg=_settings(
                ANALYSIS_PRIMARY_PROVIDER="not-a-real-provider",
                ANALYSIS_SECONDARY_PROVIDER="local",
            )
        )
    assert not output_page.exists()


# ---------------------------------------------------------------------------
# Settings: cloud keys are OPTIONAL at construction
# ---------------------------------------------------------------------------


def test_settings_construct_without_any_cloud_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """The handoff is explicit: Settings should NOT require cloud keys at boot
    so dev-without-keys + phase-2 tests both work. Failure moves to the
    orchestrator when a slot selects a missing-key provider.
    """
    monkeypatch.setenv("NEON_DATABASE_URL", "postgresql://u:p@localhost:5432/db")
    monkeypatch.setenv("OTX_API_KEY", "fake")
    # No cloud keys in env.
    from cyber_threat_pipeline.core.config import Settings

    cfg = Settings()
    assert cfg.anthropic_api_key is None
    assert cfg.xai_api_key is None
    assert cfg.openai_api_key is None
    assert cfg.google_api_key is None
    assert cfg.analysis_primary_provider == "local"
    assert cfg.analysis_secondary_provider == "local"
    assert cfg.ollama_base_url.startswith("http://")
    # Sanity: real env files don't leak into test
    assert "ANTHROPIC_API_KEY" not in os.environ
