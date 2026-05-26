"""Pure-function tests for cyber_threat_pipeline.analysis.writer."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cyber_threat_pipeline.analysis.writer import (
    ProviderResult,
    render_markdown,
    write_brief,
)

_GENERATED_AT = datetime(2026, 5, 26, 13, 0, tzinfo=UTC)
_PROMPT = "You are a threat-intelligence analyst.\nProduce a brief.\n"


def _result(name: str, model: str, text: str = "BRIEF BODY") -> ProviderResult:
    return ProviderResult(name=name, label=f"{name.title()} (lab)", model=model, text=text)


def test_render_single_result_collapses_to_plain_block() -> None:
    md = render_markdown(
        generated_at=_GENERATED_AT,
        prompt=_PROMPT,
        results=[_result("local", "llama3.1", "single-block body")],
    )
    assert "<Tabs>" not in md
    assert "single-block body" in md
    assert "Local (lab) — `llama3.1`" in md


def test_render_two_distinct_results_emit_tabs() -> None:
    md = render_markdown(
        generated_at=_GENERATED_AT,
        prompt=_PROMPT,
        results=[
            _result("claude", "claude-sonnet-4-6", "claude body"),
            _result("grok", "grok-4", "grok body"),
        ],
    )
    assert "<Tabs>" in md
    assert "</Tabs>" in md
    assert 'label="Claude (lab) — claude-sonnet-4-6"' in md
    assert 'label="Grok (lab) — grok-4"' in md
    assert "claude body" in md
    assert "grok body" in md


def test_render_dedupes_same_provider_and_model() -> None:
    # Both slots point at the same local model — collapse to one block.
    md = render_markdown(
        generated_at=_GENERATED_AT,
        prompt=_PROMPT,
        results=[
            _result("local", "llama3.1", "first body"),
            _result("local", "llama3.1", "second body — should be dropped"),
        ],
    )
    assert "<Tabs>" not in md
    assert "first body" in md
    assert "second body — should be dropped" not in md


def test_render_dedupes_keeps_different_models_of_same_provider() -> None:
    md = render_markdown(
        generated_at=_GENERATED_AT,
        prompt=_PROMPT,
        results=[
            _result("local", "llama3.1", "llama body"),
            _result("local", "qwen2.5", "qwen body"),
        ],
    )
    assert "<Tabs>" in md
    assert "llama body" in md
    assert "qwen body" in md


def test_render_includes_frontmatter() -> None:
    md = render_markdown(
        generated_at=_GENERATED_AT,
        prompt=_PROMPT,
        results=[_result("local", "llama3.1")],
    )
    assert md.startswith("---\n")
    assert "title: Analyst Brief" in md
    assert "description:" in md
    # The body is pure narrative — no `queries:` frontmatter (Evidence v40's
    # external-queries syntax accepts .sql file paths only, not raw SQL).
    assert "queries:" not in md


def test_render_round_trips_prompt_byte_for_byte_in_details() -> None:
    prompt = "## section 1\nfirst line\n\nsecond line ## with hash\n"
    md = render_markdown(
        generated_at=_GENERATED_AT,
        prompt=prompt,
        results=[_result("local", "llama3.1")],
    )
    # The prompt sits between fenced backticks inside a <details> block.
    # The opening fence is tagged ```code so Evidence's preprocessor renders
    # it as a generic code block (the `code` lang is in Evidence's
    # supportedLangs list — see preprocess/utils/supportedLanguages.cjs)
    # rather than trying to parse the prompt as a SQL query.
    assert "<details>" in md
    assert "</details>" in md
    open_fence = "```code\n"
    fence_start = md.index(open_fence, md.index("<details>"))
    fence_end = md.index("```", fence_start + len(open_fence))
    body = md[fence_start + len(open_fence) : fence_end].strip("\n")
    assert body == prompt.strip("\n")


def test_render_is_deterministic_for_same_inputs() -> None:
    results = [_result("local", "llama3.1", "body")]
    a = render_markdown(generated_at=_GENERATED_AT, prompt=_PROMPT, results=results)
    b = render_markdown(generated_at=_GENERATED_AT, prompt=_PROMPT, results=results)
    assert a == b


def test_render_includes_generated_at_date() -> None:
    md = render_markdown(
        generated_at=_GENERATED_AT,
        prompt=_PROMPT,
        results=[_result("local", "llama3.1")],
    )
    assert "Analyst Brief — 2026-05-26" in md


def test_render_failure_placeholder_passes_through() -> None:
    placeholder = "_Claude (Anthropic) brief unavailable: APIError: 503_"
    md = render_markdown(
        generated_at=_GENERATED_AT,
        prompt=_PROMPT,
        results=[
            _result("claude", "claude-sonnet-4-6", placeholder),
            _result("grok", "grok-4", "grok body"),
        ],
    )
    assert placeholder in md
    assert "grok body" in md


def test_render_empty_results_raises() -> None:
    with pytest.raises(ValueError):
        render_markdown(generated_at=_GENERATED_AT, prompt=_PROMPT, results=[])


def test_write_brief_writes_file(tmp_path: Path) -> None:
    target = tmp_path / "pages" / "analyst-brief.md"
    out = write_brief(
        generated_at=_GENERATED_AT,
        prompt=_PROMPT,
        results=[_result("local", "llama3.1", "body")],
        path=target,
    )
    assert out == target
    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert "body" in content
    assert content.endswith("\n")
