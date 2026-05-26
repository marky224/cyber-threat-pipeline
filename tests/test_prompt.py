"""Pure-function tests for cyber_threat_pipeline.analysis.prompt.build_prompt.

No DB, no network — these exercise the deterministic prompt-rendering path
end-to-end on synthetic ``brief_input`` dicts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cyber_threat_pipeline.analysis.prompt import build_prompt


def _fixture_brief(*, emerging_pulses: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return a realistic brief_input dict in the shape fetch_brief_input emits."""
    return {
        "generated_at": datetime(2026, 5, 26, 13, 0, tzinfo=UTC),
        "corpus_header": {
            "total_pulses": 7128,
            "total_indicators": 412985,
            "active_indicators": 380110,
            "expired_indicators": 32875,
        },
        "top_types": [
            {"type": "FileHash-SHA256", "count": 180_000},
            {"type": "domain", "count": 90_000},
        ],
        "top_countries": [
            {"country": "United States", "pulse_count": 2400},
            {"country": "China", "pulse_count": 900},
        ],
        "top_tags": [{"tag": "phishing", "pulse_count": 1200}],
        "top_industries": [{"industry": "Finance", "pulse_count": 800}],
        "emerging_pulses_7d": emerging_pulses
        if emerging_pulses is not None
        else [
            {
                "id": "PULSE-EMERGING-004",
                "name": "Emerging campaign — first seen this week",
                "tlp": "red",
                "tags": ["zero-day", "exploit"],
                "targeted_countries": ["United States"],
                "first_seen_at": "2026-05-26T01:00:00Z",
                "indicator_count": 3,
            }
        ],
        "emerging_indicators_7d": [
            {"type": "FileHash-SHA256", "count": 1},
            {"type": "IPv4", "count": 1},
        ],
    }


def test_build_prompt_includes_corpus_header_numbers() -> None:
    prompt = build_prompt(_fixture_brief())
    assert "Total pulses:                 7,128" in prompt
    assert "Total indicators:             412,985" in prompt
    assert "Active indicators:            380,110" in prompt
    assert "Expired indicators:           32,875" in prompt


def test_build_prompt_includes_top_n_labels_and_counts() -> None:
    prompt = build_prompt(_fixture_brief())
    assert "FileHash-SHA256: 180000" in prompt
    assert "United States: 2400" in prompt
    assert "phishing: 1200" in prompt
    assert "Finance: 800" in prompt


def test_build_prompt_includes_emerging_pulse_details() -> None:
    prompt = build_prompt(_fixture_brief())
    assert "[RED] Emerging campaign — first seen this week" in prompt
    assert "id=PULSE-EMERGING-004" in prompt
    assert "indicators=3" in prompt
    assert "zero-day" in prompt
    assert "United States" in prompt


def test_build_prompt_empty_emerging_pulses_renders_fallback() -> None:
    prompt = build_prompt(_fixture_brief(emerging_pulses=[]))
    assert "(no new pulses in the last 7 days)" in prompt
    # Sanity: the corpus header still renders normally.
    assert "Total pulses:                 7,128" in prompt


def test_build_prompt_footer_warns_against_invention() -> None:
    prompt = build_prompt(_fixture_brief())
    assert "Do not invent indicators, pulse names, or numbers" in prompt


def test_build_prompt_includes_structure_directives() -> None:
    prompt = build_prompt(_fixture_brief())
    # All four required sections of the brief are named explicitly so the
    # two models produce roughly comparable shapes.
    assert "**Headline**" in prompt
    assert "**Emerging threats**" in prompt
    assert "**Corpus-level shifts**" in prompt
    assert "**Analyst caveats**" in prompt


def test_build_prompt_is_deterministic() -> None:
    brief = _fixture_brief()
    a = build_prompt(brief)
    b = build_prompt(brief)
    assert a == b


def test_build_prompt_handles_null_top_lists() -> None:
    brief = _fixture_brief()
    brief["top_types"] = None
    brief["top_countries"] = None
    brief["top_tags"] = None
    brief["top_industries"] = None
    brief["emerging_indicators_7d"] = None
    prompt = build_prompt(brief)
    # All four "(none)" placeholders should appear.
    assert prompt.count("(none)") >= 4
