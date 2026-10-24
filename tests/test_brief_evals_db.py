"""DB-integration tests: `make analysis` stores grounding scores in pipeline.brief_evals.

Gated on NEON_DATABASE_URL like the other DB tests (a docker postgres:15
locally, the CI postgres service in CI). Providers are stubbed; no LLM calls.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest

from cyber_threat_pipeline.analysis import __main__ as orchestrator
from cyber_threat_pipeline.analysis import providers as providers_mod
from cyber_threat_pipeline.core.config import Settings
from tests.conftest import FakeJudgeClient

FIXTURE = Path(__file__).parent / "fixtures" / "brief_2026_10_14"
SQL_31 = Path(__file__).resolve().parent.parent / "sql" / "31_brief_evals.sql"


@pytest.fixture()
def analysis_env(
    monkeypatch: pytest.MonkeyPatch, pg_conn: psycopg.Connection, pg_url: str, tmp_path: Path
) -> Iterator[Path]:
    """Real DB for the insert; fixture brief_input; stubbed 'local' provider."""
    brief_input = json.loads((FIXTURE / "brief_input.json").read_text())
    monkeypatch.setattr(
        "cyber_threat_pipeline.analysis.prompt.fetch_brief_input", lambda _conn: brief_input
    )
    page = tmp_path / "analyst-brief.md"
    monkeypatch.setattr("cyber_threat_pipeline.analysis.writer.PAGE_PATH", page)
    for key in ("ANALYSIS_PROVIDERS", "ANALYSIS_PRIMARY_PROVIDER", "ANALYSIS_SECONDARY_PROVIDER"):
        monkeypatch.delenv(key, raising=False)
    yield page


def _stub_local(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    original = providers_mod.PROVIDERS["local"]
    registry = dict(providers_mod.PROVIDERS)
    registry["local"] = providers_mod.Provider(
        name=original.name,
        query=lambda _prompt, **_kw: text,
        default_model=original.default_model,
        credential_kind=original.credential_kind,
        credential_attr=original.credential_attr,
        display_label=original.display_label,
    )
    monkeypatch.setattr(providers_mod, "PROVIDERS", registry)


def _settings(pg_url: str) -> Settings:
    return Settings.model_validate(
        {"NEON_DATABASE_URL": pg_url, "OTX_API_KEY": "fake", "ANALYSIS_PROVIDERS": "local"}
    )


def _rows(conn: psycopg.Connection) -> list[tuple[Any, ...]]:
    with conn.cursor() as cur:
        cur.execute(
            "select run_id, provider, model, words, facts_total, facts_verified, findings,"
            " brief_generated_at is not null, judge_model, judge_claims_total"
            " from pipeline.brief_evals order by id"
        )
        return cur.fetchall()


def test_scores_are_stored_per_provider_and_linked_to_the_latest_run(
    monkeypatch: pytest.MonkeyPatch,
    pg_conn: psycopg.Connection,
    pg_url: str,
    analysis_env: Path,
) -> None:
    with pg_conn.cursor() as cur:
        cur.execute("insert into pipeline.runs (status, trigger) values ('success', 'test')")
        cur.execute("insert into pipeline.runs (status, trigger) values ('success', 'test')")
        cur.execute("select max(id) from pipeline.runs")
        row = cur.fetchone()
    assert row is not None
    latest = row[0]
    _stub_local(monkeypatch, (FIXTURE / "brief.md").read_text())

    assert orchestrator.run(cfg=_settings(pg_url)) == 0

    rows = _rows(pg_conn)
    # The default local slot runs twice but dedupes to one block, so one row.
    assert len(rows) == 1
    run_id, provider, _model, words, total, verified, findings, has_gen, judge, judged = rows[0]
    assert (run_id, provider, words, total, verified) == (latest, "local", 502, 19, 12)
    assert len(findings) == 17
    assert {"check", "text", "detail"} == set(findings[0])
    assert has_gen and judge is None and judged is None
    assert "_Grounding: 12/19 facts verified" in analysis_env.read_text()


def test_scores_are_stored_without_a_run_row(
    monkeypatch: pytest.MonkeyPatch,
    pg_conn: psycopg.Connection,
    pg_url: str,
    analysis_env: Path,
) -> None:
    _stub_local(monkeypatch, (FIXTURE / "brief_corrected.md").read_text())

    assert orchestrator.run(cfg=_settings(pg_url)) == 0

    rows = _rows(pg_conn)
    assert [(r[0], r[4], r[5], r[6]) for r in rows] == [(None, 31, 31, [])]


def test_scores_are_stored_even_if_the_read_connection_was_dropped(
    monkeypatch: pytest.MonkeyPatch,
    pg_conn: psycopg.Connection,
    pg_url: str,
    analysis_env: Path,
) -> None:
    # The connection that reads brief_input sits idle through the LLM calls;
    # the Neon pooler can close it. The insert must not depend on it.
    brief_input: dict[str, Any] = json.loads((FIXTURE / "brief_input.json").read_text())

    def fetch_then_drop(conn: psycopg.Connection) -> dict[str, Any]:
        conn.close()
        return brief_input

    monkeypatch.setattr("cyber_threat_pipeline.analysis.prompt.fetch_brief_input", fetch_then_drop)
    _stub_local(monkeypatch, (FIXTURE / "brief_corrected.md").read_text())

    assert orchestrator.run(cfg=_settings(pg_url)) == 0

    assert [(r[4], r[5]) for r in _rows(pg_conn)] == [(31, 31)]


def test_grafana_ro_can_read_the_scores(pg_conn: psycopg.Connection) -> None:
    with pg_conn.cursor() as cur:
        cur.execute("set role grafana_ro")
        try:
            cur.execute("select count(*) from pipeline.brief_evals")
            assert cur.fetchone() == (0,)
        finally:
            cur.execute("reset role")


def test_missing_table_only_warns_and_the_page_is_still_written(
    monkeypatch: pytest.MonkeyPatch,
    pg_conn: psycopg.Connection,
    pg_url: str,
    analysis_env: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Like a run that lands before sql/31_brief_evals.sql reaches Neon.
    _stub_local(monkeypatch, (FIXTURE / "brief.md").read_text())
    with pg_conn.cursor() as cur:
        cur.execute("drop table pipeline.brief_evals")
    try:
        assert orchestrator.run(cfg=_settings(pg_url)) == 0
    finally:
        with pg_conn.cursor() as cur:
            cur.execute(SQL_31.read_text())

    assert "_Grounding: 12/19 facts verified" in analysis_env.read_text()
    assert "Could not store grounding scores" in caplog.text


def test_judge_scores_are_stored_with_the_row(
    monkeypatch: pytest.MonkeyPatch,
    pg_conn: psycopg.Connection,
    pg_url: str,
    analysis_env: Path,
    fake_judge_client: Callable[[str | Exception], FakeJudgeClient],
) -> None:
    fake_judge_client(
        '{"claims": [{"claim": "a", "supported": true}, {"claim": "b", "supported": false}]}'
    )
    _stub_local(monkeypatch, (FIXTURE / "brief_corrected.md").read_text())
    cfg = Settings.model_validate(
        {
            "NEON_DATABASE_URL": pg_url,
            "OTX_API_KEY": "fake",
            "ANALYSIS_PROVIDERS": "local",
            "ANALYSIS_JUDGE": "claude",
            "ANTHROPIC_API_KEY": "k",
        }
    )

    assert orchestrator.run(cfg=cfg) == 0

    with pg_conn.cursor() as cur:
        cur.execute(
            "select judge_model, judge_claims_total, judge_claims_supported from pipeline.brief_evals"
        )
        assert cur.fetchall() == [("claude-haiku-4-5", 2, 1)]
