"""cyber_threat_pipeline.analyst.evaluate: the eval loop, its totals and its reports.

The loop runs against Postgres as a test login in analyst_ro (DB-integration,
gated on NEON_DATABASE_URL; the login is dropped when the module ends). Its test
doubles: a 2-question gold file whose queries read no mart (the test database
has none) and one gold question over the row cap, a gold-echo provider and a wrong-SQL
provider, and an Anthropic fake returning a real ``anthropic.types.Message``
with ``Usage`` for ``judge_answer``. Every double checks that no transaction is
open when it is called. The report tests build an ``EvalRun`` directly and need
no database.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg
import pytest
from anthropic.types import Message, TextBlock, Usage
from psycopg.conninfo import make_conninfo
from psycopg.pq import TransactionStatus

from cyber_threat_pipeline.analysis import judge
from cyber_threat_pipeline.analysis.completion import Completion
from cyber_threat_pipeline.analyst import check, evaluate, prices, runner
from cyber_threat_pipeline.core.config import Settings
from tests.conftest import check_create_kwargs

_LOGIN = "analyst_eval_test_login"
_PASSWORD = "analyst-test-only"
_ESC = "\x1b[2J\x1b]0;pwned\x07"
_ESCAPED = "\\x1b[2J\\x1b]0;pwned\\x07"

_GOLD_TOML = """
[[question]]
id = "q01"
question = "What are the first three multiples of ten?"
marts = []
kind = "single"
difficulty = "easy"
ordered = true
sql = '''
select g, g * 10 as tens from generate_series(1, 3) g order by g
'''
checkable = "Exact integers."

[[question]]
id = "q02"
question = "Which two tags are there?"
marts = []
kind = "single"
difficulty = "easy"
ordered = false
tolerance = 0.5
sql = '''
select 'b' as tag union all select 'a'
'''
checkable = "Compared as a set."
"""


def _completion(text: str, model: str = "grok-4.7") -> Completion:
    return Completion(
        text=text,
        model=model,
        stop_reason="stop",
        input_tokens=1_000,
        cached_input_tokens=400,
        output_tokens=100,
        reasoning_tokens=60,
        raw={"body": text},
    )


@pytest.fixture()
def gold(tmp_path: Path) -> list[evaluate.GoldQuestion]:
    path = tmp_path / "gold.toml"
    path.write_text(_GOLD_TOML, encoding="utf-8")
    return evaluate.load_gold(path)


@pytest.fixture(scope="module")
def login_url(_pg_session: psycopg.Connection, pg_url: str) -> Iterator[str]:
    cur = _pg_session.cursor()
    cur.execute(f"drop role if exists {_LOGIN}")
    cur.execute(f"create role {_LOGIN} login password '{_PASSWORD}' in role analyst_ro")
    try:
        yield make_conninfo(pg_url, user=_LOGIN, password=_PASSWORD)
    finally:
        cur.execute(f"drop role if exists {_LOGIN}")


@pytest.fixture()
def conn(login_url: str) -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    connection = runner.connect(login_url)
    try:
        runner.check_session(connection)
        yield connection
    finally:
        connection.close()


class _Calls:
    """The doubles' log: each model call's name, made only while no transaction is open."""

    def __init__(self, conn: psycopg.Connection[tuple[Any, ...]]) -> None:
        self.conn = conn
        self.names: list[str] = []

    def made(self, name: str) -> None:
        assert self.conn.info.transaction_status is TransactionStatus.IDLE, name
        self.names.append(name)


class _FakeAnthropic:
    """The judge's client: a real Message with Usage; records each request."""

    def __init__(self, calls: _Calls, reply: str) -> None:
        self.calls, self.reply = calls, reply
        self.messages = self

    def __call__(self, **_kwargs: Any) -> _FakeAnthropic:
        return self

    def create(self, **kwargs: Any) -> Message:
        check_create_kwargs(kwargs)
        self.calls.made("judge")
        return Message(
            id="msg_test",
            type="message",
            role="assistant",
            model="claude-haiku-4-5",
            content=[TextBlock(type="text", text=self.reply)],
            stop_reason="end_turn",
            stop_sequence=None,
            usage=Usage(input_tokens=700, output_tokens=90),
        )


@pytest.fixture()
def calls(conn: psycopg.Connection[tuple[Any, ...]], monkeypatch: pytest.MonkeyPatch) -> _Calls:
    log = _Calls(conn)
    reply = '{"claims": [{"claim": "a", "supported": true}, {"claim": "b", "supported": false}]}'
    monkeypatch.setattr(
        "cyber_threat_pipeline.analysis.claude.anthropic.Anthropic", _FakeAnthropic(log, reply)
    )
    return log


def _cfg() -> Settings:
    return Settings.model_validate(
        {"NEON_DATABASE_URL": "postgresql://u:p@h/db", "OTX_API_KEY": "x", "ANTHROPIC_API_KEY": "k"}
    )


def _run(
    conn: psycopg.Connection[tuple[Any, ...]],
    gold: list[evaluate.GoldQuestion],
    calls: _Calls,
    sql: str | None,
) -> evaluate.EvalRun:
    """A run whose SQL call replies with ``sql`` (the wrong-SQL provider), or the gold SQL."""

    def write_sql(q: evaluate.GoldQuestion) -> Completion:
        calls.made("sql")
        return _completion(f"```sql\n{q.sql if sql is None else sql}\n```")

    def explain(text: str) -> Completion:
        calls.made("explanation")
        return _completion("The rows show it.")

    cfg = _cfg()
    return evaluate.evaluate(
        conn,
        gold,
        provider="grok",
        write_sql=write_sql,
        explain=explain,
        judge=lambda q, s, rows, text: judge.judge_answer(q, s, rows, text, cfg),
    )


def test_a_gold_echo_run_scores_100_percent(
    conn: psycopg.Connection[tuple[Any, ...]], gold: list[evaluate.GoldQuestion]
) -> None:
    result = evaluate.evaluate(conn, gold, provider="gold-echo", write_sql=check.gold_echo)
    totals = evaluate.summary(result)
    assert (totals["passed"], totals["total"], totals["percent"]) == (2, 2, Decimal(100))
    assert [len(a.calls) for a in result.answers] == [1, 1]  # no explanation, no judge
    assert [a.rendering for a in result.answers] == [
        "SELECT g, g * 10 AS tens FROM GENERATE_SERIES(1, 3) AS g ORDER BY g LIMIT 1001",
        "SELECT 'b' AS tag UNION ALL SELECT 'a' LIMIT 1001",
    ]


def test_a_wrong_sql_run_fails_each_question_with_its_reason(
    conn: psycopg.Connection[tuple[Any, ...]], gold: list[evaluate.GoldQuestion], calls: _Calls
) -> None:
    result = _run(conn, gold, calls, "select 0 as x")
    assert [(a.passed, a.reason) for a in result.answers] == [
        (False, "row count differs: gold 3, model 1"),
        (False, "row count differs: gold 2, model 1"),
    ]
    # Each question: the SQL call, then (after the transaction) the explanation and judge.
    assert calls.names == ["sql", "explanation", "judge"] * 2
    assert evaluate.summary(result)["meets_bar"] is False


def test_a_correct_answer_in_another_shape_passes(
    conn: psycopg.Connection[tuple[Any, ...]], gold: list[evaluate.GoldQuestion], calls: _Calls
) -> None:
    # Extra column, other names and order; q02 compares as a set.
    sql = "select g * 10 as t, 'x' as extra, g as n from generate_series(1, 3) g order by g"
    first = _run(conn, gold[:1], calls, sql).answers[0]
    assert (first.passed, first.reason, first.judge) == (True, None, (1, 2))
    second = _run(conn, gold[1:], calls, "select 'a' union all select 'b'").answers[0]
    assert second.passed


def test_the_totals_add_up(
    conn: psycopg.Connection[tuple[Any, ...]], gold: list[evaluate.GoldQuestion], calls: _Calls
) -> None:
    result = _run(conn, gold, calls, None)
    totals = evaluate.summary(result)
    every = [call for a in result.answers for call in a.calls]
    assert [call.name for call in every] == ["sql", "explanation", "judge"] * 2
    assert totals["tokens"] == {
        "input": 4 * 1_000 + 2 * 700,
        "cached_input": 4 * 400,
        "output": 4 * 100 + 2 * 90,
        "reasoning": 4 * 60,
    }
    grok = prices.dollars(_completion(""))
    haiku = (700 * Decimal("1.00") + 90 * Decimal("5.00")) / 1_000_000
    assert isinstance(grok, Decimal)
    assert totals["dollars"]["analyst"] == evaluate.Dollars(4 * grok, True)
    assert totals["dollars"]["judge"] == evaluate.Dollars(2 * haiku, True)
    assert totals["dollars"]["total"] == evaluate.Dollars(4 * grok + 2 * haiku, True)
    assert totals["judge"] == {"explanations": 2, "supported": 2, "claims": 4}
    assert (totals["passed"], totals["meets_bar"]) == (2, True)


def test_a_failed_call_is_recorded_and_the_dollars_read_incomplete(
    conn: psycopg.Connection[tuple[Any, ...]], gold: list[evaluate.GoldQuestion]
) -> None:
    def write_sql(q: evaluate.GoldQuestion) -> Completion:
        raise TimeoutError("read timed out")

    result = evaluate.evaluate(conn, gold, provider="grok", write_sql=write_sql)
    assert [a.reason for a in result.answers] == [
        "sql call failed: TimeoutError: read timed out"
    ] * 2
    analyst = evaluate.summary(result)["dollars"]["analyst"]
    assert analyst == evaluate.Dollars(Decimal(0), False)
    assert analyst.text() == "incomplete (priced calls: $0.0000)"


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        ("CANNOT_ANSWER no such data", "cannot answer: no such data"),
        ("select 1", "refused: no single SQL block"),
        ("```sql\nselect * from raw.pulses\n```", "refused: table not allowed: raw.pulses"),
        ("```sql\nselect nope from generate_series(1, 3) g\n```", "error: 42703: "),
    ],
)
def test_a_refusal_or_error_fails_the_question(
    conn: psycopg.Connection[tuple[Any, ...]],
    gold: list[evaluate.GoldQuestion],
    reply: str,
    reason: str,
) -> None:
    result = evaluate.evaluate(
        conn, gold[:1], provider="grok", write_sql=lambda q: _completion(reply)
    )
    (answer,) = result.answers
    assert not answer.passed and answer.reason is not None
    assert answer.reason.startswith(reason)


def test_a_model_result_cut_at_the_cap_fails(
    conn: psycopg.Connection[tuple[Any, ...]], gold: list[evaluate.GoldQuestion]
) -> None:
    # Two LIMITs: the outer one is capped at 1,001, so the result is cut.
    reply = "```sql\nselect g from generate_series(1, 5000) g limit 2000\n```"
    (answer,) = evaluate.evaluate(
        conn, gold[:1], provider="grok", write_sql=lambda q: _completion(reply)
    ).answers
    assert answer.reason == "model result cut at the row cap"


def test_a_gold_result_cut_at_the_cap_stops_before_the_model_s_query(
    conn: psycopg.Connection[tuple[Any, ...]], gold: list[evaluate.GoldQuestion]
) -> None:
    # A gold double over the cap. Its cut read may abort the transaction (psycopg
    # cancels the rest), so the model's query must not be read after it.
    big = dataclasses.replace(gold[0], sql="select g from generate_series(1, 200000) g")
    (answer,) = evaluate.evaluate(conn, [big], provider="grok", write_sql=check.gold_echo).answers
    assert answer.reason == "gold result cut at the row cap"
    assert answer.gold is not None and answer.gold.cut
    assert answer.model is None


def test_brief_input_s_generated_at_is_none_when_unreadable(
    conn: psycopg.Connection[tuple[Any, ...]], gold: list[evaluate.GoldQuestion]
) -> None:
    # The test database has no marts.brief_input.
    result = evaluate.evaluate(conn, gold[:1], provider="gold-echo", write_sql=check.gold_echo)
    assert result.generated_at == (None, None)


# --- reports (no database) ------------------------------------------------------------


def _answer(qid: str, passed: bool, *, sql: str = "select 1", explanation: str = "Two.") -> Any:
    rows = runner.Result(columns=("n",), rows=[(1,), (2,)], cut=False)
    return evaluate.Answer(
        id=qid,
        question=f"Question {qid}?",
        passed=passed,
        reason=None if passed else "rows differ (compared as a set)",
        weak=False,
        calls=(
            evaluate.Call("sql", _completion(f"```sql\n{sql}\n```")),
            evaluate.Call("explanation", _completion(explanation)),
            evaluate.Call("judge", None, "no score"),
        ),
        model_sql=sql,
        rendering=sql.upper(),
        gold=rows,
        model=rows,
        explanation=explanation,
        judge=None,
    )


def _eval_run(provider: str, stamp: str, *answers: Any) -> evaluate.EvalRun:
    at = datetime(2026, 11, 26, 18, 0, tzinfo=UTC)
    return evaluate.EvalRun(provider, stamp, at, at, ("2026-11-23", "2026-11-23"), answers)


def test_reports_are_written_and_compare_md_keeps_the_latest_run_per_provider(
    tmp_path: Path,
) -> None:
    out = tmp_path / "analyst-evals"
    evaluate.write_reports(_eval_run("grok", "20261126T170000Z", _answer("q01", False)), out)
    evaluate.write_reports(_eval_run("grok", "20261126T180000Z", _answer("q01", True)), out)
    written = evaluate.write_reports(
        _eval_run("claude", "20261126T190000Z", _answer("q01", False)), out, record=True
    )
    report = json.loads((out / "20261126T180000Z-grok.json").read_text("utf-8"))
    assert report["totals"]["passed"] == 1 and report["prices_read"] == "2026-11-21"
    assert report["questions"][0]["calls"][2] == {
        "name": "judge",
        "error": "no score",
        "model": None,
        "stop_reason": None,
        "input_tokens": None,
        "cached_input_tokens": None,
        "output_tokens": None,
        "reasoning_tokens": None,
        "dollars": None,
        "unpriced": "call failed: no score",
    }
    comparison = (out / "compare.md").read_text("utf-8")
    assert "| grok | 20261126T180000Z | 1/1 (100.0%) |" in comparison
    assert "| claude | 20261126T190000Z | 0/1 (0.0%) |" in comparison
    assert "| q01 | fail: rows differ (compared as a set) | pass |" in comparison
    replies = out / "20261126T190000Z-claude-replies"
    assert sorted(p.name for p in replies.iterdir()) == ["q01-explanation.json", "q01-sql.json"]
    assert json.loads((replies / "q01-sql.json").read_text("utf-8")) == {
        "body": "```sql\nselect 1\n```"
    }
    assert replies / "q01-sql.json" in written


def test_the_markdown_escapes_model_written_text(tmp_path: Path) -> None:
    answer = _answer("q01", False, sql=f"select '{_ESC}' -- ```", explanation=f"It {_ESC}\u2028.")
    text = evaluate.markdown(_eval_run("claude", "20261126T190000Z", answer))
    assert "\x1b" not in text and "\x07" not in text and "\u2028" not in text
    assert f"select '{_ESCAPED}' -- ```" in text
    assert "````sql" in text  # a fence longer than the SQL's own backticks
    assert f"It {_ESCAPED}\\u2028." in text
    assert "a Claude model (Haiku) grades a Claude model's explanations" in text
    assert "judge incomplete (priced calls: $0.0000)" in text


def test_the_markdown_warns_when_the_marts_were_rebuilt_during_the_run() -> None:
    run = _eval_run("grok", "20261126T190000Z", _answer("q01", True))
    rebuilt = evaluate.EvalRun(
        run.provider, run.stamp, run.started_at, run.finished_at, ("a", "b"), run.answers
    )
    assert "WARNING: brief_input.generated_at changed during the run" in evaluate.markdown(rebuilt)
    assert "WARNING" not in evaluate.markdown(run)


def test_a_failed_answer_with_an_empty_gold_result_is_no_weak_pass() -> None:
    passed = dataclasses.replace(
        _answer("q01", True), weak=True, gold=runner.Result((), [], False), model=None
    )
    failed = dataclasses.replace(
        _answer("q02", False),
        reason="row count differs: gold 0, model 1",
        weak=True,  # compare marks every empty gold result weak
        gold=runner.Result((), [], False),
    )
    run = _eval_run("grok", "20261126T190000Z", passed, failed)
    assert evaluate.summary(run)["weak"] == 1
    text = evaluate.markdown(run)
    assert "Weak passes (empty gold result): 1." in text
    assert "| q02 | fail | row count differs: gold 0, model 1 |  |" in text
    assert [q["weak"] for q in evaluate.to_json(run)["questions"]] == [True, False]
    only_failed = _eval_run("grok", "20261126T190000Z", failed)
    assert "Weak passes (empty gold result): 0." in evaluate.markdown(only_failed)


@pytest.mark.parametrize(("stop", "cut"), [("length", True), ("max_tokens", True), ("stop", False)])
def test_an_explanation_cut_at_its_output_limit_is_recorded_as_cut(stop: str, cut: bool) -> None:
    answer = _answer("q01", True)
    sql_call, explanation_call, judge_call = answer.calls
    assert explanation_call.completion is not None
    explanation_call = dataclasses.replace(
        explanation_call,
        completion=dataclasses.replace(explanation_call.completion, stop_reason=stop),
    )
    answer = dataclasses.replace(answer, calls=(sql_call, explanation_call, judge_call))
    run = _eval_run("grok", "20261126T190000Z", answer)
    heading = "Explanation (cut: the reply stopped at its output limit):"
    assert (heading in evaluate.markdown(run)) is cut
    assert evaluate.to_json(run)["questions"][0].get("explanation_cut") is cut
