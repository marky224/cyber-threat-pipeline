"""complete_claude and complete_grok: the reply's tokens, counted the same way for both.

No network and no key. The Anthropic client is a fake that records its
constructor arguments and returns a real ``anthropic.types.Message``. The xAI
replies are hand-written bodies in the shape xAI's chat-completions reference
documents (read 2026-11-26; see ``grok.py``), a test double kept until recorded
replies replace them.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from anthropic.types import Message, TextBlock, Usage

from cyber_threat_pipeline.analysis import claude, grok, providers
from tests.conftest import check_create_kwargs

# --- Anthropic ---------------------------------------------------------------


class _FakeAnthropic:
    """Stands in for ``anthropic.Anthropic``; records constructor and create() kwargs."""

    def __init__(self, message: Message) -> None:
        self.message = message
        self.client_kwargs: dict[str, Any] = {}
        self.requests: list[dict[str, Any]] = []
        self.messages = self

    def __call__(self, **kwargs: Any) -> _FakeAnthropic:
        self.client_kwargs = kwargs
        return self

    def create(self, **kwargs: Any) -> Message:
        check_create_kwargs(kwargs)
        self.requests.append(kwargs)
        return self.message


def _install_claude(monkeypatch: pytest.MonkeyPatch, usage: Usage) -> _FakeAnthropic:
    fake = _FakeAnthropic(
        Message(
            id="msg_test",
            type="message",
            role="assistant",
            model="claude-haiku-4-5",
            content=[TextBlock(type="text", text=" the answer ")],
            stop_reason="end_turn",
            stop_sequence=None,
            usage=usage,
        )
    )
    monkeypatch.setattr("cyber_threat_pipeline.analysis.claude.anthropic.Anthropic", fake)
    return fake


def test_complete_claude_counts_cache_reads_and_writes_as_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    usage = Usage(
        input_tokens=100,
        output_tokens=20,
        cache_read_input_tokens=30,
        cache_creation_input_tokens=5,
    )
    fake = _install_claude(monkeypatch, usage)
    completion = claude.complete_claude("q", api_key="k", model="claude-haiku-4-5", max_tokens=50)
    assert completion.text == "the answer"
    assert completion.model == "claude-haiku-4-5"
    assert completion.stop_reason == "end_turn"
    assert completion.input_tokens == 135
    assert completion.cached_input_tokens == 30
    assert completion.output_tokens == 20
    assert completion.reasoning_tokens is None
    assert completion.raw["usage"]["input_tokens"] == 100
    (request,) = fake.requests
    assert request["max_tokens"] == 50
    assert not {"temperature", "top_p", "top_k"} & request.keys()


def test_complete_claude_reads_missing_cache_counts_as_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_claude(monkeypatch, Usage(input_tokens=100, output_tokens=20))
    completion = claude.complete_claude("q", api_key="k", model="m", max_tokens=50)
    assert (completion.input_tokens, completion.cached_input_tokens) == (100, 0)


def test_complete_claude_passes_no_none_timeout_or_max_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _install_claude(monkeypatch, Usage(input_tokens=1, output_tokens=1))
    claude.complete_claude("q", api_key="k", model="m", max_tokens=5)
    assert fake.client_kwargs == {"api_key": "k"}
    claude.complete_claude("q", api_key="k", model="m", max_tokens=5, timeout=60, max_retries=0)
    assert fake.client_kwargs == {"api_key": "k", "timeout": 60, "max_retries": 0}


def test_query_claude_logs_its_stop_reason_before_failing_on_a_reply_with_no_text(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The brief's log lines say why the call failed: it stopped at max_tokens.
    fake = _FakeAnthropic(
        Message(
            id="msg_test",
            type="message",
            role="assistant",
            model="claude-sonnet-4-6",
            content=[],
            stop_reason="max_tokens",
            stop_sequence=None,
            usage=Usage(input_tokens=2000, output_tokens=8000),
        )
    )
    monkeypatch.setattr("cyber_threat_pipeline.analysis.claude.anthropic.Anthropic", fake)
    caplog.set_level(logging.INFO, logger=claude.__name__)
    with pytest.raises(RuntimeError, match="no text block"):
        claude.query_claude("q", api_key="k", max_tokens=4000)
    assert [(r.levelname, r.getMessage()) for r in caplog.records if r.name == claude.__name__] == [
        ("INFO", "Claude stop_reason=max_tokens: 8000 of 4000 output tokens"),
        ("WARNING", "Claude stopped at max_tokens (4000): the brief is cut off"),
    ]


# --- xAI ---------------------------------------------------------------------


def _xai_body(
    *,
    prompt: int = 31,
    completion: int = 11,
    total: int | None = 42,
    cached: int = 8,
    reasoning: int = 0,
    finish_reason: str = "stop",
    usage: bool = True,
) -> dict[str, Any]:
    """A chat.completion body in the documented shape."""
    body: dict[str, Any] = {
        "id": "test",
        "object": "chat.completion",
        "created": 1743770624,
        "model": "grok-4.7",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": " the answer ", "refusal": None},
                "finish_reason": finish_reason,
            }
        ],
    }
    if usage:
        body["usage"] = {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": total,
            "prompt_tokens_details": {
                "text_tokens": prompt,
                "audio_tokens": 0,
                "image_tokens": 0,
                "cached_tokens": cached,
            },
            "completion_tokens_details": {
                "reasoning_tokens": reasoning,
                "audio_tokens": 0,
                "accepted_prediction_tokens": 0,
                "rejected_prediction_tokens": 0,
            },
        }
    return body


class _FakeResponse:
    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.body


def _install_xai(monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    def post(url: str, *, json: dict[str, Any], headers: dict[str, str], timeout: int) -> Any:
        sent.append({"url": url, "body": json, "headers": headers, "timeout": timeout})
        return _FakeResponse(body)

    monkeypatch.setattr("cyber_threat_pipeline.analysis.grok.requests.post", post)
    return sent


def _complete_grok(**kwargs: Any) -> Any:
    return grok.complete_grok("q", api_key="k", model="grok-4.7", max_tokens=4000, **kwargs)


def test_complete_grok_bills_completion_when_reasoning_is_inside_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_xai(monkeypatch, _xai_body(prompt=31, completion=111, total=142, reasoning=100))
    completion = _complete_grok(temperature=0)
    assert completion.text == "the answer"
    assert completion.model == "grok-4.7"
    assert completion.stop_reason == "stop"
    assert completion.input_tokens == 31
    assert completion.cached_input_tokens == 8
    assert completion.output_tokens == 111
    assert completion.reasoning_tokens == 100


def test_complete_grok_bills_reasoning_reported_apart(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_xai(monkeypatch, _xai_body(prompt=32, completion=9, total=151, reasoning=110))
    completion = _complete_grok(temperature=0)
    assert (completion.output_tokens, completion.reasoning_tokens) == (119, 110)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(_xai_body(total=999), id="total-adds-up-to-neither"),
        pytest.param(_xai_body(total=None), id="no-total"),
        pytest.param(_xai_body(usage=False), id="no-usage"),
    ],
)
def test_complete_grok_leaves_doubtful_usage_unpriced(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]
) -> None:
    _install_xai(monkeypatch, body)
    completion = _complete_grok(temperature=0)
    assert completion.text == "the answer"
    assert (
        completion.input_tokens,
        completion.cached_input_tokens,
        completion.output_tokens,
        completion.reasoning_tokens,
    ) == (None, None, None, None)


def test_complete_grok_reports_a_length_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_xai(monkeypatch, _xai_body(finish_reason="length"))
    assert _complete_grok(temperature=0).stop_reason == "length"


def test_complete_grok_sends_the_temperature_it_is_given(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _install_xai(monkeypatch, _xai_body())
    _complete_grok(temperature=0)
    (request,) = sent
    assert request["body"] == {
        "model": "grok-4.7",
        "messages": [{"role": "user", "content": "q"}],
        "max_tokens": 4000,
        "temperature": 0,
    }


def test_query_grok_request_body_keeps_temperature_0_3(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _install_xai(monkeypatch, _xai_body())
    assert grok.query_grok("q", api_key="k") == "the answer"
    (request,) = sent
    assert request["body"] == {
        "model": grok.DEFAULT_MODEL,
        "messages": [{"role": "user", "content": "q"}],
        "max_tokens": grok.DEFAULT_MAX_TOKENS,
        "temperature": 0.3,
    }
    assert request["url"] == grok.DEFAULT_ENDPOINT
    assert request["timeout"] == grok.DEFAULT_TIMEOUT_SECONDS


# --- the registry ------------------------------------------------------------


def test_only_claude_and_grok_have_a_complete_call() -> None:
    assert providers.PROVIDERS["claude"].complete is claude.complete_claude
    assert providers.PROVIDERS["grok"].complete is grok.complete_grok
    for name in ("gpt", "gemini", "local"):
        assert providers.PROVIDERS[name].complete is None
