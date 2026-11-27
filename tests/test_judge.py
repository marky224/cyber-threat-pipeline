"""Tests for the optional LLM judge (cyber_threat_pipeline.analysis.judge).

Every provider call is mocked: the Claude judge's Anthropic client is a
FakeJudgeClient (tests/conftest.py) and Ollama's query_local is patched. No
network, no API keys.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from anthropic.types import Message, TextBlock, Usage

from cyber_threat_pipeline.analysis import judge, local
from cyber_threat_pipeline.core.config import Settings
from tests import conftest
from tests.conftest import FakeJudgeClient

_REPLY = '{"claims": [{"claim": "a", "supported": true}, {"claim": "b", "supported": true},'
_REPLY += ' {"claim": "c", "supported": false}]}'

Install = Callable[[str | Exception], FakeJudgeClient]


def _cfg(**env: str) -> Settings:
    base = {"NEON_DATABASE_URL": "postgresql://u:p@localhost:5432/db", "OTX_API_KEY": "x"}
    return Settings.model_validate(base | env)


@pytest.fixture()
def local_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    def fake_local(prompt: str, **kw: Any) -> str:
        seen.append(kw | {"prompt": prompt})
        return _REPLY

    monkeypatch.setattr(local, "query_local", fake_local)
    return seen


def test_judge_is_off_by_default(
    fake_judge_client: Install, local_calls: list[dict[str, Any]]
) -> None:
    fake = fake_judge_client(_REPLY)
    assert judge.judge("prompt", "brief", _cfg()) is None
    assert fake.requests == [] and local_calls == []


def test_claude_judge_uses_haiku_and_counts_supported_claims(fake_judge_client: Install) -> None:
    fake = fake_judge_client(_REPLY)
    score = judge.judge("PROMPT", "BRIEF", _cfg(ANALYSIS_JUDGE="claude", ANTHROPIC_API_KEY="k"))

    assert score == judge.JudgeScore(supported=2, total=3, model="claude-haiku-4-5")
    [request] = fake.requests
    assert request["model"] == "claude-haiku-4-5"
    assert request["max_tokens"] == 4000
    sent = request.keys() | request.get("extra_body", {}).keys()
    assert not {"temperature", "top_p", "top_k"} & sent  # as in test_claude.py
    prompt = request["messages"][0]["content"]
    assert "PROMPT" in prompt and "BRIEF" in prompt


def test_claude_judge_has_its_own_bounded_client(fake_judge_client: Install) -> None:
    # A slow or retrying judge must not run make analysis into pipeline.yml's
    # 30-minute job timeout before the page is written: short timeout, no retries.
    fake = fake_judge_client(_REPLY)
    judge.judge("p", "b", _cfg(ANALYSIS_JUDGE="claude", ANTHROPIC_API_KEY="k"))
    assert fake.inits == [{"api_key": "k", "timeout": 60.0, "max_retries": 0}]


def test_judge_model_can_be_overridden(fake_judge_client: Install) -> None:
    fake = fake_judge_client(_REPLY)
    cfg = _cfg(ANALYSIS_JUDGE="claude", ANTHROPIC_API_KEY="k", JUDGE_MODEL="claude-haiku-5-5")
    score = judge.judge("p", "b", cfg)
    assert score is not None and score.model == "claude-haiku-5-5"
    assert fake.requests[0]["model"] == "claude-haiku-5-5"


def test_local_judge_uses_ollama(local_calls: list[dict[str, Any]]) -> None:
    cfg = _cfg(ANALYSIS_JUDGE="local", OLLAMA_BASE_URL="http://ollama:11434")
    score = judge.judge("p", "b", cfg)

    assert score == judge.JudgeScore(supported=2, total=3, model=local.DEFAULT_MODEL)
    [kw] = local_calls
    assert (kw["base_url"], kw["model"]) == ("http://ollama:11434", local.DEFAULT_MODEL)
    assert kw["max_tokens"] == 4000  # a long claims list must not be cut off


@pytest.mark.parametrize("choice", ["gpt", "gemini", "grok", "openai", "nonsense"])
def test_only_claude_or_local_may_judge(
    choice: str,
    fake_judge_client: Install,
    local_calls: list[dict[str, Any]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = fake_judge_client(_REPLY)
    cfg = _cfg(ANALYSIS_JUDGE=choice, OPENAI_API_KEY="k", GOOGLE_API_KEY="k", XAI_API_KEY="k")
    assert judge.judge("p", "b", cfg) is None
    assert fake.requests == [] and local_calls == []
    assert "judge skipped" in caplog.text


def test_claude_judge_without_a_key_is_skipped(
    fake_judge_client: Install, caplog: pytest.LogCaptureFixture
) -> None:
    fake = fake_judge_client(_REPLY)
    assert judge.judge("p", "b", _cfg(ANALYSIS_JUDGE="claude")) is None
    assert fake.requests == []
    assert "ANTHROPIC_API_KEY" in caplog.text


@pytest.mark.parametrize(
    "reply",
    [
        "I think it is mostly fine.",
        '{"claims": "all good"}',
        '{"claims": [{"claim": "a"}, "b"]}',
        "{not json",
    ],
)
def test_malformed_replies_give_no_score(
    fake_judge_client: Install, reply: str, caplog: pytest.LogCaptureFixture
) -> None:
    fake_judge_client(reply)
    cfg = _cfg(ANALYSIS_JUDGE="claude", ANTHROPIC_API_KEY="k")
    assert judge.judge("p", "b", cfg) is None
    assert "judge" in caplog.text.lower()


def test_json_inside_prose_or_a_fence_is_read(fake_judge_client: Install) -> None:
    fake_judge_client(f"Here:\n```json\n{_REPLY}\n```")
    cfg = _cfg(ANALYSIS_JUDGE="claude", ANTHROPIC_API_KEY="k")
    assert judge.judge("p", "b", cfg) == judge.JudgeScore(2, 3, "claude-haiku-4-5")


def test_a_failing_judge_call_gives_no_score(
    fake_judge_client: Install, caplog: pytest.LogCaptureFixture
) -> None:
    fake_judge_client(TimeoutError("judge timed out"))
    cfg = _cfg(ANALYSIS_JUDGE="claude", ANTHROPIC_API_KEY="k")
    assert judge.judge("p", "b", cfg) is None
    assert "TimeoutError" in caplog.text


# --- judge_answer: the threat-data analyst's judge -----------------------------
# Its Anthropic client is a fake returning a real anthropic.types.Message with
# Usage, as in test_claude.py, since judge_answer reports the call's tokens.


class _FakeAnswerClient:
    """Stands in for ``anthropic.Anthropic`` in claude.py; records the client and requests."""

    def __init__(self, reply: str | Exception, content: list[Any] | None = None) -> None:
        self.reply = reply
        self.content = content
        self.inits: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []
        self.messages = self

    def __call__(self, **kwargs: Any) -> _FakeAnswerClient:
        self.inits.append(kwargs)
        return self

    def create(self, **kwargs: Any) -> Message:
        conftest.check_create_kwargs(kwargs)
        self.requests.append(kwargs)
        if isinstance(self.reply, Exception):
            raise self.reply
        content = (
            self.content if self.content is not None else [TextBlock(type="text", text=self.reply)]
        )
        return Message(
            id="msg_test",
            type="message",
            role="assistant",
            model="claude-haiku-4-5",
            content=content,
            stop_reason="end_turn",
            stop_sequence=None,
            usage=Usage(input_tokens=700, output_tokens=90),
        )


def _answer_client(
    monkeypatch: pytest.MonkeyPatch, reply: str | Exception, content: list[Any] | None = None
) -> _FakeAnswerClient:
    fake = _FakeAnswerClient(reply, content)
    monkeypatch.setattr("cyber_threat_pipeline.analysis.claude.anthropic.Anthropic", fake)
    return fake


def _judge_answer(cfg: Settings) -> judge.AnswerScore | None:
    return judge.judge_answer("QUESTION?", "SELECT 1", "1 rows.\n\nRows:\nn\n7\n", "EXPLAINED", cfg)


def test_answer_judge_grades_on_haiku_with_a_bounded_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _answer_client(monkeypatch, _REPLY)
    score = _judge_answer(_cfg(ANTHROPIC_API_KEY="k"))
    assert score is not None
    assert (score.supported, score.total, score.model) == (2, 3, "claude-haiku-4-5")
    assert (score.completion.input_tokens, score.completion.output_tokens) == (700, 90)
    assert fake.inits == [{"api_key": "k", "timeout": 60.0, "max_retries": 0}]
    [request] = fake.requests
    assert (request["model"], request["max_tokens"]) == ("claude-haiku-4-5", 4000)
    sent = request.keys() | request.get("extra_body", {}).keys()
    assert not {"temperature", "top_p", "top_k"} & sent
    prompt = request["messages"][0]["content"]
    for part in ("QUESTION?", "SELECT 1", "Rows:\nn\n7", "EXPLAINED"):
        assert part in prompt


def test_answer_judge_ignores_the_brief_judge_s_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _answer_client(monkeypatch, _REPLY)
    cfg = _cfg(ANTHROPIC_API_KEY="k", ANALYSIS_JUDGE="local", JUDGE_MODEL="claude-opus-5-5")
    score = _judge_answer(cfg)
    assert score is not None and score.model == "claude-haiku-4-5"
    assert fake.requests[0]["model"] == "claude-haiku-4-5"


def test_answer_judge_without_a_key_is_skipped(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fake = _answer_client(monkeypatch, _REPLY)
    assert _judge_answer(_cfg()) is None
    assert fake.requests == []
    assert "ANTHROPIC_API_KEY" in caplog.text


@pytest.mark.parametrize(
    ("reply", "content"),
    [
        pytest.param(TimeoutError("judge timed out"), None, id="failed-call"),
        pytest.param("I think it is mostly fine.", None, id="no-json"),
        pytest.param('{"claims": [{"claim": "a"}]}', None, id="no-supported-flag"),
        pytest.param("", [], id="no-text-block"),
    ],
)
def test_answer_judge_never_raises(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    reply: str | Exception,
    content: list[Any] | None,
) -> None:
    _answer_client(monkeypatch, reply, content)
    assert _judge_answer(_cfg(ANTHROPIC_API_KEY="k")) is None
    assert "Answer judge failed" in caplog.text
