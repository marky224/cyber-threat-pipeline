"""``python -m cyber_threat_pipeline.analyst``: ask, eval and check from the command line.

``ask``: settings, call order, refusals, escaping and dollars. ``eval`` and
``check``: setup errors, and which model each provider runs. No network and no
database. xAI's replies are hand-written bodies in the shape its
chat-completions reference documents (a test double, as in test_completion.py),
served by a fake ``requests.post``; Anthropic's are real ``Message`` objects
from a fake client. The runner's connect, session check and run are fakes that
record the order of events, and ``evaluate.evaluate`` is a fake in the eval
tests, which only check what the command line passes it.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
import pytest
from anthropic.types import Message, TextBlock, Usage

from cyber_threat_pipeline.analysis.completion import Completion
from cyber_threat_pipeline.analyst import __main__ as cli
from cyber_threat_pipeline.analyst import check, evaluate, runner
from tests.conftest import check_create_kwargs

_REAL_CONNECT = runner.connect
_ANALYST_URL = "postgresql://analyst_login:pw@analyst-host:5432/ctp"
_OWNER_URL = "postgresql://owner:pw@owner-host:5432/ctp"
_ESC = "\x1b[2J\x1b]0;pwned\x07"
_ESCAPED = "\\x1b[2J\\x1b]0;pwned\\x07"


def _xai(content: str) -> dict[str, Any]:
    return {
        "object": "chat.completion",
        "model": "grok-4.7",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
                  "prompt_tokens_details": {"cached_tokens": 0},
                  "completion_tokens_details": {"reasoning_tokens": 0}},
    }  # fmt: skip


class _Response:
    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.body


class _Conn:
    def __enter__(self) -> _Conn:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class _World:
    """The fakes' shared state: replies to serve, the rows to return, what happened."""

    def __init__(self) -> None:
        self.replies: list[str] = []
        self.result = runner.Result(columns=("tag",), rows=[("ransomware",)], cut=False)
        self.failure: runner.QueryFailed | None = None
        self.events: list[str] = []
        self.urls: list[str] = []
        self.ran: list[str] = []
        self.bodies: list[dict[str, Any]] = []


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[_World]:
    monkeypatch.chdir(tmp_path)  # no .env
    for key, value in {
        "NEON_DATABASE_URL": _OWNER_URL,
        "OTX_API_KEY": "otx",
        "ANALYST_DATABASE_URL": _ANALYST_URL,
        "XAI_API_KEY": "xai",
    }.items():
        monkeypatch.setenv(key, value)
    w = _World()

    def post(url: str, *, json: dict[str, Any], headers: Any, timeout: int) -> _Response:
        w.events.append("llm")
        w.bodies.append(json)
        assert json["temperature"] == 0
        return _Response(_xai(w.replies.pop(0)))

    def connect(url: str) -> _Conn:
        w.events.append("connect")
        w.urls.append(url)
        return _Conn()

    def run(conn: Any, sql: str, **_: Any) -> runner.Result:
        w.events.append("run")
        w.ran.append(sql)
        if w.failure is not None:
            raise w.failure
        return w.result

    monkeypatch.setattr("cyber_threat_pipeline.analysis.grok.requests.post", post)
    monkeypatch.setattr(runner, "connect", connect)
    monkeypatch.setattr(runner, "check_session", lambda conn: w.events.append("check"))
    monkeypatch.setattr(runner, "run", run)
    yield w


def _ask(capsys: pytest.CaptureFixture[str], question: str = "Which tags lead?") -> tuple[int, str]:
    code = cli.main(["ask", question])
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def test_an_answer_runs_the_sql_call_before_the_query_and_the_explanation_after(
    world: _World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.replies = ["```sql\nselect tag from mart_threat_tags\n```", "Ransomware leads."]
    code, out = _ask(capsys)
    assert code == 0
    assert world.events == ["connect", "check", "llm", "run", "llm"]
    assert world.ran == ["SELECT tag FROM marts.mart_threat_tags LIMIT 1001"]
    assert "SELECT tag FROM marts.mart_threat_tags LIMIT 1001" in out
    assert "ransomware" in out and "(1 rows)" in out and "Ransomware leads." in out
    assert "sql: grok-4.7, stop stop, tokens in 10 (cached 0), out 5" in out


def test_ask_connects_with_the_analyst_url_never_neon_database_url(
    world: _World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.replies = ["```sql\nselect 1\n```", "One."]
    _ask(capsys)
    assert world.urls == [_ANALYST_URL]


@pytest.mark.parametrize("missing", ["ANALYST_DATABASE_URL", "XAI_API_KEY"])
def test_ask_fails_fast_without_its_url_or_key(
    world: _World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], missing: str
) -> None:
    monkeypatch.delenv(missing)
    code, out = _ask(capsys)
    assert code == 2
    assert f"{missing} is not set" in out
    assert world.events == []


def test_a_refused_reply_makes_no_database_call(
    world: _World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.replies = ["```sql\nselect * from raw.pulses\n```"]
    code, out = _ask(capsys)
    assert code == 1
    assert "Refused: table not allowed: raw.pulses" in out
    assert "select * from raw.pulses" in out
    assert world.events == ["connect", "check", "llm"]


def test_a_reply_with_no_sql_block_is_refused(
    world: _World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.replies = ["select 1"]
    code, out = _ask(capsys)
    assert (code, "run" in world.events) == (1, False)
    assert "Refused: no single SQL block" in out


def test_a_query_error_prints_its_sqlstate(
    world: _World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.replies = ["```sql\nselect 1\n```"]
    world.failure = runner.QueryFailed("42703", "column x does not exist")
    code, out = _ask(capsys)
    assert code == 1
    assert "Query error: 42703: column x does not exist" in out
    assert world.events.count("llm") == 1


def test_a_timeout_says_it_was_cancelled(world: _World, capsys: pytest.CaptureFixture[str]) -> None:
    world.replies = ["```sql\nselect 1\n```"]
    world.failure = runner.QueryFailed(runner.QUERY_CANCELED, "canceling statement")
    code, out = _ask(capsys)
    assert (code, "Query error: cancelled after 5s" in out) == (1, True)


def test_a_malformed_url_never_prints_libpq_s_message(
    world: _World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # libpq's parse error quotes the token it can't read: here, the password.
    monkeypatch.setenv("ANALYST_DATABASE_URL", "postgresql://u:s3cr%zzet@127.0.0.1:1/db")
    monkeypatch.setattr(runner, "connect", _REAL_CONNECT)
    code, out = _ask(capsys)
    assert code == 2
    assert "cannot connect: ANALYST_DATABASE_URL is not a valid connection URL" in out
    assert "s3cr" not in out
    assert world.events == []


def test_a_refused_session_is_a_setup_error(
    world: _World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(conn: Any) -> None:
        raise runner.SessionRefused("owner can use the raw or pipeline schema")

    monkeypatch.setattr(runner, "check_session", refuse)
    code, out = _ask(capsys)
    assert code == 2
    assert "session refused: owner can use the raw or pipeline schema" in out
    assert "llm" not in world.events


def test_cannot_answer_prints_its_reason_escaped(
    world: _World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.replies = [f"CANNOT_ANSWER no prices {_ESC}here"]
    code, out = _ask(capsys)
    assert code == 1
    assert f"Cannot answer: no prices {_ESCAPED}here" in out
    assert "\x1b" not in out and "run" not in world.events


def test_the_sql_values_column_names_and_explanation_are_printed_escaped(
    world: _World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.replies = [f"```sql\nselect '{_ESC}' as s\n```", f"It says {_ESC}."]
    world.result = runner.Result(columns=(f"c{_ESC}",), rows=[(f"v{_ESC}\nnext",)], cut=False)
    code, out = _ask(capsys)
    assert code == 0
    assert "\x1b" not in out and "\x07" not in out
    assert f"SELECT '{_ESCAPED}' AS s LIMIT 1001" in out
    assert f"c{_ESCAPED}" in out
    assert f"v{_ESCAPED}\\x0anext" in out
    assert f"It says {_ESCAPED}." in out


def test_a_refusal_reason_is_printed_escaped(
    world: _World, capsys: pytest.CaptureFixture[str]
) -> None:
    # The guard's reason quotes the model's table name, control characters and all.
    world.replies = [f'```sql\nselect * from "{_ESC}"\n```']
    code, out = _ask(capsys)
    assert code == 1
    assert f'Refused: table not allowed: "{_ESCAPED}"' in out
    assert "\x1b" not in out


def test_sqlglot_command_fallback_warning_is_kept_off_the_terminal(
    world: _World, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    # sqlglot logs the statement's text when it falls back to a generic Command.
    world.replies = [f"```sql\nexplain select '{_ESC}'\n```"]
    code, out = _ask(capsys)
    assert code == 1
    assert "Refused: not a query: Command" in out
    assert not [r for r in caplog.records if r.name.startswith("sqlglot")]
    assert logging.getLogger("sqlglot").getEffectiveLevel() >= logging.ERROR


def test_ask_prints_each_call_s_dollars_and_the_total(
    world: _World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.replies = ["```sql\nselect 1\n```", "One."]
    code, out = _ask(capsys)
    assert code == 0
    # grok-4.7: 10 input tokens at $2 and 5 output tokens at $6, per 1M tokens.
    assert (
        "sql: grok-4.7, stop stop, tokens in 10 (cached 0), out 5 (reasoning 0), $0.000050" in out
    )
    assert "total: $0.0001" in out


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out + captured.err


class _Evaluate:
    """Stands in for ``evaluate.evaluate``: makes one SQL and one explanation call."""

    def __init__(self) -> None:
        self.seen: dict[str, Any] = {}
        self.completions: list[Completion] = []

    def __call__(
        self,
        conn: Any,
        questions: list[Any],
        *,
        provider: str,
        write_sql: Any,
        explain: Any,
        judge: Any,
    ) -> evaluate.EvalRun:
        self.seen = {"provider": provider, "questions": len(questions), "judge": judge is not None}
        self.completions = [write_sql(questions[0]), explain("explain this")]
        at = datetime(2026, 11, 26, 18, 0, tzinfo=UTC)
        return evaluate.EvalRun(provider, "20261126T180000Z", at, at, (None, None), ())


@pytest.fixture()
def fake_evaluate(world: _World, monkeypatch: pytest.MonkeyPatch) -> _Evaluate:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic")
    fake = _Evaluate()
    monkeypatch.setattr(evaluate, "evaluate", fake)
    return fake


def test_eval_runs_grok_at_temperature_0_and_writes_its_reports(
    world: _World, fake_evaluate: _Evaluate, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    world.replies = ["```sql\nselect 1\n```", "One."]
    code, out = _run(capsys, "eval")
    assert code == 0
    assert fake_evaluate.seen == {"provider": "grok", "questions": 30, "judge": True}
    assert [body["model"] for body in world.bodies] == ["grok-4.7", "grok-4.7"]
    assert world.events == ["connect", "check", "llm", "llm"]
    reports = tmp_path / "analyst-evals"
    assert sorted(p.name for p in reports.iterdir()) == [
        "20261126T180000Z-grok.json",
        "20261126T180000Z-grok.md",
        "compare.md",
    ]
    assert "grok: 0/0 (0.0%), meets the 80% bar: no" in out


class _FakeAnthropic:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.messages = self

    def __call__(self, **_kwargs: Any) -> _FakeAnthropic:
        return self

    def create(self, **kwargs: Any) -> Message:
        check_create_kwargs(kwargs)
        self.requests.append(kwargs)
        return Message(
            id="msg_test",
            type="message",
            role="assistant",
            model=kwargs["model"],
            content=[TextBlock(type="text", text="```sql\nselect 1\n```")],
            stop_reason="end_turn",
            stop_sequence=None,
            usage=Usage(input_tokens=10, output_tokens=5),
        )


def test_eval_with_claude_runs_the_registry_s_default_model(
    world: _World,
    fake_evaluate: _Evaluate,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = _FakeAnthropic()
    monkeypatch.setattr("cyber_threat_pipeline.analysis.claude.anthropic.Anthropic", fake)
    code, _ = _run(capsys, "eval", "--provider", "claude", "--record", "1")
    assert code == 0
    assert fake_evaluate.seen["provider"] == "claude"
    assert [r["model"] for r in fake.requests] == ["claude-sonnet-4-6", "claude-sonnet-4-6"]
    assert all(not {"temperature", "top_p", "top_k"} & r.keys() for r in fake.requests)
    assert "llm" not in world.events  # no Grok call


@pytest.mark.parametrize(
    ("argv", "missing"),
    [
        (("eval",), "ANTHROPIC_API_KEY"),
        (("eval", "--provider", "claude"), "ANTHROPIC_API_KEY"),
        (("eval",), "ANALYST_DATABASE_URL"),
        (("eval",), "XAI_API_KEY"),
    ],
)
def test_eval_fails_fast_without_its_url_or_keys(
    world: _World,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, ...],
    missing: str,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic")
    monkeypatch.delenv(missing)
    code, out = _run(capsys, *argv)
    assert (code, f"{missing} is not set" in out) == (2, True)
    assert world.events == []


def test_check_needs_neon_database_url(
    world: _World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("NEON_DATABASE_URL")
    code, out = _run(capsys, "check")
    assert (code, "setup error: NEON_DATABASE_URL is not set" in out) == (2, True)
    assert world.events == []


def test_check_never_prints_libpq_s_message_for_a_malformed_url(
    world: _World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("NEON_DATABASE_URL", "postgresql://u:s3cr%zzet@127.0.0.1:1/db")
    monkeypatch.setattr(runner, "connect", _REAL_CONNECT)
    code, out = _run(capsys, "check")
    assert code == 2
    assert "NEON_DATABASE_URL is not a valid connection URL" in out and "s3cr" not in out


def test_a_database_error_in_the_check_is_one_setup_error_line(
    world: _World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # As on a postgres:15 that never had sql/33 applied.
    def run(conn: Any, questions: list[Any]) -> list[str]:
        raise psycopg.errors.UndefinedObject('role "analyst_ro" does not exist')

    monkeypatch.setattr(check, "run", run)
    code, out = _run(capsys, "check")
    assert code == 2
    assert out == 'setup error: database error: 42704: role "analyst_ro" does not exist\n'


def test_a_gold_query_refused_mid_eval_is_one_setup_error_line(
    world: _World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic")

    def refuse(*_args: Any, **_kwargs: Any) -> evaluate.EvalRun:
        raise evaluate.GoldFileError("q07: the guard refuses the gold query: table not allowed: x")

    monkeypatch.setattr(evaluate, "evaluate", refuse)
    code, out = _run(capsys, "eval")
    assert code == 2
    assert out == "setup error: q07: the guard refuses the gold query: table not allowed: x\n"


def test_a_connection_lost_mid_eval_is_one_setup_error_line_without_libpq_s_text(
    world: _World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic")

    def lose(*_args: Any, **_kwargs: Any) -> evaluate.EvalRun:
        # libpq's text for a failed or lost connection can quote the connection string.
        raise psycopg.OperationalError("consuming input failed: host=analyst-host password=pw")

    monkeypatch.setattr(evaluate, "evaluate", lose)
    code, out = _run(capsys, "eval")
    assert code == 2
    assert out == (
        "setup error: database error: OperationalError: the connection failed or was lost\n"
    )
