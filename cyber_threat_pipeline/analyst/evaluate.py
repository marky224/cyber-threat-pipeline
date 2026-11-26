"""The analyst eval: every gold question through one provider, scored by result match.

``evaluate(conn, questions, provider=..., write_sql=..., explain=..., judge=...)``
takes each gold question in order:

1. the SQL call, before any transaction opens;
2. the reply's SQL block and the guard: a CANNOT_ANSWER, a reply with no single
   SQL block, or a refused query fails the question;
3. the gold query's rendering, then the model's, in one ``READ ONLY REPEATABLE
   READ`` transaction, gold first, so both see one snapshot and one ``now()``.
   A Postgres error, a timeout, or a model result cut at the row cap fails the
   question; otherwise ``compare`` decides (column names ignored, rows in order
   only for an ordered question, numbers within the question's tolerance);
4. after the rollback, the explanation call and its judge, when the run has
   them. The gold-echo run has neither.

No model call happens inside the transaction. A call that raises is recorded as
failed, and the run goes on. Every call is priced from ``prices.py``; a failed
or unpriced call makes its group's dollars "incomplete". The run records
``brief_input.generated_at`` at its start and end, since a weekly rebuild
during the run changes the marts between questions.

``write_reports(run, out_dir, record=...)`` writes ``<stamp>-<provider>.json``
and ``.md``, refreshes ``compare.md`` from the latest run per provider, and with
``record`` saves each reply body (no headers, so no key) under
``<stamp>-<provider>-replies/``. The markdown escapes control characters in
every model-written string, as ``ask`` does on the terminal.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg

from cyber_threat_pipeline.analysis.completion import Completion
from cyber_threat_pipeline.analysis.judge import AnswerScore
from cyber_threat_pipeline.analyst import guard, prices, prompt, runner
from cyber_threat_pipeline.analyst.compare import compare

GOLD_FILE = Path(__file__).with_name("gold.toml")
PASS_BAR = Decimal(80)  # percent of the gold questions, by result match
SHOWN_ROWS = 20  # rows of each result shown for a failed question

_REPORT = re.compile(r"^(?P<stamp>[0-9]{8}T[0-9]{6}Z)-(?P<provider>[a-z0-9_-]+)\.json$")
_ANALYST_CALLS = ("sql", "explanation")

WriteSql = Callable[["GoldQuestion"], Completion]
Explain = Callable[[str], Completion]
Judge = Callable[[str, str, str, str], AnswerScore | None]


class GoldFileError(Exception):
    """The gold file can't be read, or one of its queries is refused or fails."""


@dataclass(frozen=True)
class GoldQuestion:
    id: str
    question: str
    marts: tuple[str, ...]
    kind: str
    difficulty: str
    ordered: bool
    tolerance: Decimal
    sql: str
    checkable: str


def load_gold(path: Path = GOLD_FILE) -> list[GoldQuestion]:
    """The gold questions, in file order."""
    try:
        entries = tomllib.loads(path.read_text(encoding="utf-8"))["question"]
        return [
            GoldQuestion(
                id=str(q["id"]),
                question=str(q["question"]),
                marts=tuple(q["marts"]),
                kind=str(q["kind"]),
                difficulty=str(q["difficulty"]),
                ordered=bool(q["ordered"]),
                tolerance=Decimal(str(q.get("tolerance", 0))),
                sql=str(q["sql"]),
                checkable=str(q["checkable"]),
            )
            for q in entries
        ]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError, ValueError) as error:
        raise GoldFileError(f"cannot read {path.name}: {type(error).__name__}: {error}") from None


@dataclass(frozen=True)
class Call:
    """One model call: its reply, or why it failed."""

    name: str  # "sql", "explanation" or "judge"
    completion: Completion | None
    error: str | None = None

    @property
    def dollars(self) -> Decimal | prices.Unpriced:
        if self.completion is None:
            return prices.Unpriced(f"call failed: {self.error}")
        return prices.dollars(self.completion)


@dataclass(frozen=True)
class Answer:
    """One gold question's outcome."""

    id: str
    question: str
    passed: bool
    reason: str | None
    weak: bool
    calls: tuple[Call, ...]
    model_sql: str | None = None
    rendering: str | None = None
    gold: runner.Result | None = None
    model: runner.Result | None = None
    explanation: str | None = None
    judge: tuple[int, int] | None = None


@dataclass(frozen=True)
class EvalRun:
    provider: str
    stamp: str
    started_at: datetime
    finished_at: datetime
    generated_at: tuple[str | None, str | None]
    answers: tuple[Answer, ...]


def evaluate(
    conn: psycopg.Connection[tuple[Any, ...]],
    questions: Sequence[GoldQuestion],
    *,
    provider: str,
    write_sql: WriteSql,
    explain: Explain | None = None,
    judge: Judge | None = None,
) -> EvalRun:
    """Run every gold question through one provider; see the module docstring."""
    started = datetime.now(UTC)
    first = _generated_at(conn)
    answers = tuple(_answer(conn, q, write_sql, explain, judge) for q in questions)
    return EvalRun(
        provider=provider,
        stamp=started.strftime("%Y%m%dT%H%M%SZ"),
        started_at=started,
        finished_at=datetime.now(UTC),
        generated_at=(first, _generated_at(conn)),
        answers=answers,
    )


def _generated_at(conn: psycopg.Connection[tuple[Any, ...]]) -> str | None:
    try:
        result = runner.run(conn, "select generated_at from marts.brief_input")
    except runner.QueryFailed:
        return None
    return str(result.rows[0][0]) if result.rows else None


def _call(name: str, make: Callable[[], Completion]) -> Call:
    try:
        return Call(name, make())
    except Exception as error:
        return Call(name, None, f"{type(error).__name__}: {_first_line(error)}")


def _answer(
    conn: psycopg.Connection[tuple[Any, ...]],
    q: GoldQuestion,
    write_sql: WriteSql,
    explain: Explain | None,
    judge: Judge | None,
) -> Answer:
    def fail(reason: str, **kw: Any) -> Answer:
        return Answer(q.id, q.question, False, reason, False, tuple(calls), **kw)

    calls = [_call("sql", lambda: write_sql(q))]
    sql_completion = calls[0].completion
    if sql_completion is None:
        return fail(f"sql call failed: {calls[0].error}")
    reply = prompt.extract_sql(sql_completion.text)
    if isinstance(reply, prompt.CannotAnswer):
        return fail(f"cannot answer: {reply.reason}")
    if isinstance(reply, guard.Refusal):
        return fail(f"refused: {reply.reason}")
    checked = guard.check(reply)
    if isinstance(checked, guard.Refusal):
        return fail(f"refused: {checked.reason}", model_sql=reply)
    gold_checked = guard.check(q.sql)
    if isinstance(gold_checked, guard.Refusal):
        raise GoldFileError(f"{q.id}: the guard refuses the gold query: {gold_checked.reason}")

    gold: runner.Result | None = None
    model: runner.Result | None = None
    error: runner.QueryFailed | None = None
    try:
        with runner.transaction(conn, repeatable_read=True) as read:
            gold = read(gold_checked.sql)
            model = read(checked.sql)
    except runner.QueryFailed as failed:
        error = failed
    # The transaction is closed: every model call below runs outside it.
    explanation, score = _explain(q, checked.sql, model, explain, judge, calls)

    def done(passed: bool, reason: str | None, weak: bool = False) -> Answer:
        return Answer(
            q.id,
            q.question,
            passed,
            reason,
            weak,
            tuple(calls),
            model_sql=reply,
            rendering=checked.sql,
            gold=gold,
            model=model,
            explanation=explanation,
            judge=score,
        )

    if error is not None:
        why = _query_error(error)
        return done(False, f"gold query failed: {why}" if gold is None else why)
    assert gold is not None and model is not None
    if gold.cut:
        return done(False, "gold result cut at the row cap")
    if model.cut:
        return done(False, "model result cut at the row cap")
    verdict = compare(gold.rows, model.rows, ordered=q.ordered, tolerance=q.tolerance)
    return done(verdict.passed, verdict.reason, verdict.weak)


def _explain(
    q: GoldQuestion,
    sql: str,
    model: runner.Result | None,
    explain: Explain | None,
    judge: Judge | None,
    calls: list[Call],
) -> tuple[str | None, tuple[int, int] | None]:
    """The explanation call and its judge, after the transaction; appends to ``calls``."""
    if explain is None or model is None:
        return None, None
    text = prompt.explanation_prompt(q.question, sql, model.columns, model.rows, cut=model.cut)
    call = _call("explanation", lambda: explain(text))
    calls.append(call)
    if call.completion is None or judge is None:
        return (call.completion.text if call.completion else None), None
    rows = prompt.rows_text(model.columns, model.rows, cut=model.cut)
    score = judge(q.question, sql, rows, call.completion.text)
    if score is None:
        calls.append(Call("judge", None, "no score"))
        return call.completion.text, None
    calls.append(Call("judge", score.completion))
    return call.completion.text, (score.supported, score.total)


def _query_error(error: runner.QueryFailed) -> str:
    if error.timed_out:
        return f"timeout (cancelled after {runner.STATEMENT_TIMEOUT})"
    return f"error: {error.sqlstate}: {error.message}"


def _first_line(error: Exception) -> str:
    lines = str(error).splitlines()
    return lines[0] if lines else ""


# --- totals -----------------------------------------------------------------------


@dataclass(frozen=True)
class Dollars:
    """The priced calls' sum, and whether every call in the group was priced."""

    priced: Decimal
    complete: bool

    def text(self) -> str:
        money = f"${self.priced:.4f}"
        return money if self.complete else f"incomplete (priced calls: {money})"


def summary(run: EvalRun) -> dict[str, Any]:
    """Accuracy, tokens by kind, dollars by group and the judge's count, for one run."""
    total = len(run.answers)
    passed = sum(a.passed for a in run.answers)
    percent = Decimal(100 * passed) / total if total else Decimal(0)
    calls = [call for a in run.answers for call in a.calls]
    tokens = {kind: 0 for kind in ("input", "cached_input", "output", "reasoning")}
    unreported = 0
    for call in calls:
        c = call.completion
        counts = (
            (None, None, None, None)
            if c is None
            else (c.input_tokens, c.cached_input_tokens, c.output_tokens, c.reasoning_tokens)
        )
        if counts[0] is None:
            unreported += 1
        for kind, n in zip(tokens, counts, strict=True):
            tokens[kind] += n or 0
    analyst = _dollars([c for c in calls if c.name in _ANALYST_CALLS])
    judged = _dollars([c for c in calls if c.name == "judge"])
    both = Dollars(analyst.priced + judged.priced, analyst.complete and judged.complete)
    scores = [a.judge for a in run.answers if a.judge is not None]
    return {
        "passed": passed,
        "total": total,
        "percent": percent,
        "meets_bar": percent >= PASS_BAR,
        "weak": sum(a.weak for a in run.answers),
        "tokens": tokens,
        "calls": len(calls),
        "calls_with_unreported_tokens": unreported,
        "dollars": {"analyst": analyst, "judge": judged, "total": both},
        "judge": {
            "explanations": len(scores),
            "supported": sum(s[0] for s in scores),
            "claims": sum(s[1] for s in scores),
        },
    }


def _dollars(calls: list[Call]) -> Dollars:
    priced, complete = Decimal(0), True
    for call in calls:
        cost = call.dollars
        if isinstance(cost, prices.Unpriced):
            complete = False
        else:
            priced += cost
    return Dollars(priced, complete)


# --- reports ------------------------------------------------------------------------


def write_reports(run: EvalRun, out_dir: Path, *, record: bool = False) -> list[Path]:
    """Write the run's JSON and markdown, refresh compare.md, and save replies if asked."""
    out_dir.mkdir(parents=True, exist_ok=True)
    base = f"{run.stamp}-{run.provider}"
    report = to_json(run)
    written = [out_dir / f"{base}.json", out_dir / f"{base}.md"]
    written[0].write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    written[1].write_text(markdown(run), encoding="utf-8")
    if record:
        replies = out_dir / f"{base}-replies"
        replies.mkdir(exist_ok=True)
        for answer in run.answers:
            for call in answer.calls:
                if call.completion is not None:
                    path = replies / f"{answer.id}-{call.name}.json"
                    path.write_text(json.dumps(call.completion.raw, indent=2) + "\n", "utf-8")
                    written.append(path)
    comparison = out_dir / "compare.md"
    comparison.write_text(compare_markdown(out_dir), encoding="utf-8")
    written.append(comparison)
    return written


def to_json(run: EvalRun) -> dict[str, Any]:
    """The run as plain JSON values: Decimals and times as strings."""
    totals = summary(run)
    return {
        "provider": run.provider,
        "stamp": run.stamp,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat(),
        "prices_read": prices.PRICES_READ.isoformat(),
        "brief_input_generated_at": {"start": run.generated_at[0], "end": run.generated_at[1]},
        "totals": {
            **{k: v for k, v in totals.items() if k != "dollars"},
            "percent": str(totals["percent"].quantize(Decimal("0.1"))),
            "dollars": {
                group: {"priced": str(d.priced), "complete": d.complete}
                for group, d in totals["dollars"].items()
            },
        },
        "questions": [_answer_json(a) for a in run.answers],
    }


def _answer_json(a: Answer) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": a.id,
        "question": a.question,
        "passed": a.passed,
        "reason": a.reason,
        "weak": a.weak,
        "model_sql": a.model_sql,
        "rendering": a.rendering,
        "gold_rows": None if a.gold is None else len(a.gold.rows),
        "model_rows": None if a.model is None else len(a.model.rows),
        "explanation": a.explanation,
        "judge": None if a.judge is None else {"supported": a.judge[0], "claims": a.judge[1]},
        "calls": [_call_json(call) for call in a.calls],
    }
    if not a.passed:
        out["gold_sample"] = _sample(a.gold)
        out["model_sample"] = _sample(a.model)
    return out


def _call_json(call: Call) -> dict[str, Any]:
    c, cost = call.completion, call.dollars
    return {
        "name": call.name,
        "error": call.error,
        "model": None if c is None else c.model,
        "stop_reason": None if c is None else c.stop_reason,
        "input_tokens": None if c is None else c.input_tokens,
        "cached_input_tokens": None if c is None else c.cached_input_tokens,
        "output_tokens": None if c is None else c.output_tokens,
        "reasoning_tokens": None if c is None else c.reasoning_tokens,
        "dollars": None if isinstance(cost, prices.Unpriced) else str(cost),
        "unpriced": cost.reason if isinstance(cost, prices.Unpriced) else None,
    }


def _sample(result: runner.Result | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "columns": list(result.columns),
        "rows": [[None if v is None else str(v) for v in row] for row in result.rows[:SHOWN_ROWS]],
    }


def markdown(run: EvalRun) -> str:
    """The run's report; every model-written string has its control characters escaped."""
    t = summary(run)
    lines = [
        f"# Analyst eval: {run.provider}",
        "",
        f"Run {run.stamp}, {run.started_at:%Y-%m-%d %H:%M:%S} to "
        f"{run.finished_at:%Y-%m-%d %H:%M:%S} UTC. Prices read {prices.PRICES_READ}.",
        "",
        f"- Accuracy: {t['passed']}/{t['total']} ({t['percent']:.1f}%); meets the "
        f"{PASS_BAR}% bar: {'yes' if t['meets_bar'] else 'no'}. Weak passes (empty gold "
        f"result): {t['weak']}.",
        f"- Dollars: analyst {t['dollars']['analyst'].text()}; judge "
        f"{t['dollars']['judge'].text()}; total {t['dollars']['total'].text()}.",
        f"- Tokens: input {t['tokens']['input']:,} (cached {t['tokens']['cached_input']:,}); "
        f"output {t['tokens']['output']:,} (reasoning {t['tokens']['reasoning']:,}); "
        f"{t['calls_with_unreported_tokens']} of {t['calls']} calls reported none.",
        f"- Judge: {t['judge']['supported']} of {t['judge']['claims']} claims supported, over "
        f"{t['judge']['explanations']} explanations (reported only; it never decides a pass).",
        _snapshot_line(run.generated_at),
    ]
    if run.provider == "claude":
        lines.append(
            "- Note: on this run a Claude model (Haiku) grades a Claude model's explanations."
        )
    lines += [
        "",
        "| id | result | reason | weak | gold rows | model rows | judge | dollars |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for a in run.answers:
        lines.append(
            f"| {a.id} | {'pass' if a.passed else 'fail'} | {_cell(a.reason or '')} | "
            f"{'weak' if a.weak else ''} | {_count(a.gold)} | {_count(a.model)} | "
            f"{'' if a.judge is None else f'{a.judge[0]}/{a.judge[1]}'} | "
            f"{_dollars(list(a.calls)).text()} |"
        )
    for a in run.answers:
        lines += _answer_markdown(a)
    return "\n".join(lines) + "\n"


def _snapshot_line(generated_at: tuple[str | None, str | None]) -> str:
    start, end = generated_at
    if start is None and end is None:
        return "- brief_input.generated_at: not readable at the start or the end of the run."
    if start != end:
        return (
            f"- WARNING: brief_input.generated_at changed during the run ({start} at the "
            f"start, {end} at the end): a dbt build ran, so later questions saw new data."
        )
    return f"- brief_input.generated_at: {start}, the same at the start and the end."


def _answer_markdown(a: Answer) -> list[str]:
    verdict = "pass" if a.passed else f"fail: {_esc_line(a.reason or '')}"
    lines = ["", f"## {a.id}: {_esc_line(a.question)}", "", f"**{verdict}**"]
    if a.model_sql is not None:
        lines += ["", "The model's SQL:", "", *_fenced(a.model_sql, "sql")]
    if a.rendering is not None:
        lines += ["", "The rendering that ran:", "", *_fenced(a.rendering, "sql")]
    if not a.passed:
        for label, result in (("Gold", a.gold), ("Model", a.model)):
            if result is not None:
                lines += ["", f"{label} rows ({len(result.rows):,}):", "", *_rows(result)]
    if a.explanation is not None:
        lines += ["", "Explanation:", "", *_fenced(a.explanation, "")]
    lines += ["", "Calls:", ""]
    lines += [f"- {_call_line(call)}" for call in a.calls]
    return lines


def _call_line(call: Call) -> str:
    c, money = call.completion, _esc_line(prices.describe(call.dollars))
    if c is None:
        return f"{call.name}: failed ({_esc_line(call.error or '')}), {money}"
    return (
        f"{call.name}: {_esc_line(c.model)}, stop {_esc_line(str(c.stop_reason))}, input "
        f"{_tokens(c.input_tokens)} (cached {_tokens(c.cached_input_tokens)}), output "
        f"{_tokens(c.output_tokens)} (reasoning {_tokens(c.reasoning_tokens)}), {money}"
    )


def _rows(result: runner.Result) -> list[str]:
    header = [" | ".join(result.columns)] if result.columns else []
    body = [" | ".join("NULL" if v is None else str(v) for v in row) for row in result.rows]
    shown = body[:SHOWN_ROWS]
    if len(body) > len(shown):
        shown.append(f"... {len(body) - len(shown):,} more")
    return _fenced("\n".join(header + shown) or "(no rows)", "")


def _fenced(text: str, lang: str) -> list[str]:
    """A code block whose fence is longer than any run of backticks in the text."""
    body = prompt.escape(text)
    runs = [len(m) for m in re.findall(r"`+", body)]
    fence = "`" * max(3, max(runs, default=0) + 1)
    return [f"{fence}{lang}", body, fence]


def _esc_line(text: str) -> str:
    return prompt.escape(text, keep_newlines=False)


def _cell(text: str) -> str:
    return _esc_line(text).replace("|", "\\|")


def _count(result: runner.Result | None) -> str:
    return "" if result is None else f"{len(result.rows):,}"


def _tokens(n: int | None) -> str:
    return "unreported" if n is None else f"{n:,}"


def compare_markdown(out_dir: Path) -> str:
    """Providers side by side, from the latest run per provider in ``out_dir``."""
    latest: dict[str, Path] = {}
    for path in sorted(out_dir.glob("*.json")):
        match = _REPORT.match(path.name)
        if match is not None:
            latest[match["provider"]] = path  # sorted by stamp, so the last one wins
    reports = {name: json.loads(path.read_text("utf-8")) for name, path in sorted(latest.items())}
    lines = [
        "# Analyst eval: providers side by side",
        "",
        "The latest run per provider in this folder.",
        "",
        "| provider | run | accuracy | input | cached | output | reasoning | analyst $ | judge $ "
        "| total $ | judge |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, r in reports.items():
        t = r["totals"]
        tok = t["tokens"]
        money = {
            group: Dollars(Decimal(d["priced"]), d["complete"]).text()
            for group, d in t["dollars"].items()
        }
        lines.append(
            f"| {_cell(name)} | {_cell(r['stamp'])} | {t['passed']}/{t['total']} "
            f"({t['percent']}%) | {tok['input']:,} | {tok['cached_input']:,} | "
            f"{tok['output']:,} | {tok['reasoning']:,} | {money['analyst']} | {money['judge']} | "
            f"{money['total']} | {t['judge']['supported']}/{t['judge']['claims']} |"
        )
    ids = sorted({q["id"] for r in reports.values() for q in r["questions"]})
    names = list(reports)
    lines += ["", "| question | " + " | ".join(_cell(n) for n in names) + " |"]
    lines.append("|---|" + "---|" * len(names))
    by_id = {n: {q["id"]: q for q in r["questions"]} for n, r in reports.items()}
    for qid in ids:
        cells = []
        for n in names:
            q = by_id[n].get(qid)
            if q is None:
                cells.append("")
            elif q["passed"]:
                cells.append("pass")
            else:
                cells.append(_cell(f"fail: {q['reason']}"))
        lines.append(f"| {qid} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"
