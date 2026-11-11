"""Tests for cyber_threat_pipeline.analysis.claude: the limit it sends and the stop reason it logs.

The Anthropic client is a fake (``_FakeAnthropic``) that returns a real
``anthropic.types.Message``. No network, no API key.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import pytest
from anthropic.types import Message, StopReason, TextBlock, Usage

from cyber_threat_pipeline.analysis import claude
from tests.conftest import check_create_kwargs

_LOGGER = "cyber_threat_pipeline.analysis.claude"


class _FakeAnthropic:
    """Stands in for ``anthropic.Anthropic`` in claude.py; ``requests`` records each call."""

    def __init__(self, message: Message) -> None:
        self.message = message
        self.requests: list[dict[str, Any]] = []
        self.messages = self

    def __call__(self, **_kwargs: Any) -> _FakeAnthropic:
        return self

    def create(self, **kwargs: Any) -> Message:
        check_create_kwargs(kwargs)
        self.requests.append(kwargs)
        return self.message


def _install(
    monkeypatch: pytest.MonkeyPatch, text: str, stop_reason: StopReason, output_tokens: int
) -> _FakeAnthropic:
    fake = _FakeAnthropic(
        Message(
            id="msg_test",
            type="message",
            role="assistant",
            model="claude-sonnet-4-6",
            content=[TextBlock(type="text", text=text)],
            stop_reason=stop_reason,
            stop_sequence=None,
            usage=Usage(input_tokens=2000, output_tokens=output_tokens),
        )
    )
    monkeypatch.setattr("cyber_threat_pipeline.analysis.claude.anthropic.Anthropic", fake)
    return fake


def test_claude_default_output_limit_has_room_for_the_brief(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # At 1200 the 2026-11-09 brief stopped mid-sentence: a 400-word brief with
    # its (id=...) citations is about that size.
    if os.environ.get("CLAUDE_MAX_TOKENS"):
        pytest.skip("CLAUDE_MAX_TOKENS overrides the default")
    fake = _install(monkeypatch, "## Headline\n\nA week of routers.", "end_turn", 900)
    claude.query_claude("prompt", api_key="k")
    assert fake.requests[0]["max_tokens"] == 4000


def test_claude_logs_its_stop_reason_and_output_tokens(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install(monkeypatch, "## Headline\n\nA week of routers.", "end_turn", 900)
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        claude.query_claude("prompt", api_key="k", max_tokens=4000)
    assert "stop_reason=end_turn: 900 of 4000 output tokens" in caplog.text
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_claude_warns_when_the_brief_stops_at_max_tokens(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    cut = "## Headline\n\nThe lure recurs.\n\n## Contrast with the corpus\n\n- yet it recurs across at least"
    _install(monkeypatch, cut, "max_tokens", 1200)
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        text = claude.query_claude("prompt", api_key="k", max_tokens=1200)
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1, warnings
    assert "max_tokens (1200)" in warnings[0]
    assert text == cut  # published as written: the grounding checks report what it lacks
