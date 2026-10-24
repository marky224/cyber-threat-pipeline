"""The committed Brief-grounding panel and alert SQL, run as grafana_ro.

DB-integration (gated on NEON_DATABASE_URL). Reads the SQL straight from
monitoring/dashboard.json and monitoring/alerts.yaml so the test covers what
is provisioned, not a copy.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import psycopg

MONITORING = Path(__file__).resolve().parent.parent / "monitoring"


def _panel_sql() -> str:
    panels = json.loads((MONITORING / "dashboard.json").read_text())["panels"]
    [panel] = [p for p in panels if p["title"].startswith("Brief grounding")]
    sql: str = panel["targets"][0]["rawSql"]
    return sql.replace("$__timeFilter(evaluated_at)", "true")


def _alert_sql() -> str:
    text = (MONITORING / "alerts.yaml").read_text()
    rule = text[text.index("uid: ctp-brief-grounding") :]
    match = re.search(r"rawSql: \|\n((?:\s{16}.*\n)+)", rule)
    assert match is not None
    return match.group(1)


def _as_grafana(conn: psycopg.Connection, sql: str) -> tuple[list[str], list[tuple[object, ...]]]:
    """Run ``sql`` as grafana_ro (the role Grafana's datasource uses)."""
    with conn.cursor() as cur:
        cur.execute("set role grafana_ro")
        try:
            cur.execute(sql)
            assert cur.description is not None
            return [c.name for c in cur.description], cur.fetchall()
        finally:
            cur.execute("reset role")


def _insert(conn: psycopg.Connection, provider: str, verified: int, total: int, age: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "insert into pipeline.brief_evals (evaluated_at, brief_generated_at, provider, model,"
            " words, facts_total, facts_verified, findings)"
            " values (now() - %s::interval, now(), %s, 'm', 300, %s, %s, '[]')",
            (age, provider, total, verified),
        )


def test_alert_value_is_the_worst_latest_provider_ratio(pg_conn: psycopg.Connection) -> None:
    _insert(pg_conn, "claude", 31, 31, "10 days")  # too old to count
    _insert(pg_conn, "claude", 12, 19, "1 hour")
    _insert(pg_conn, "local", 31, 31, "1 hour")

    _, rows = _as_grafana(pg_conn, _alert_sql())
    assert round(float(str(rows[0][0])), 4) == round(12 / 19, 4)  # < 0.9: fires


def test_alert_is_quiet_when_every_latest_brief_verifies(pg_conn: psycopg.Connection) -> None:
    _insert(pg_conn, "claude", 12, 19, "2 days")
    _insert(pg_conn, "claude", 31, 31, "1 hour")  # latest wins
    _insert(pg_conn, "local", 0, 0, "1 hour")  # nothing to check: ignored

    assert _as_grafana(pg_conn, _alert_sql())[1] == [(1.0,)]


def test_alert_only_counts_providers_from_the_latest_analysis_run(
    pg_conn: psycopg.Connection,
) -> None:
    _insert(pg_conn, "grok", 2, 10, "1 day")  # grok was dropped after this run
    _insert(pg_conn, "claude", 31, 31, "1 hour")

    assert _as_grafana(pg_conn, _alert_sql())[1] == [(1.0,)]


def test_alert_has_a_value_with_no_rows(pg_conn: psycopg.Connection) -> None:
    assert _as_grafana(pg_conn, _alert_sql())[1] == [(1.0,)]


def test_panel_returns_one_series_point_per_provider_run(pg_conn: psycopg.Connection) -> None:
    _insert(pg_conn, "claude", 12, 19, "1 hour")
    _insert(pg_conn, "local", 0, 0, "1 hour")

    columns, rows = _as_grafana(pg_conn, _panel_sql())
    assert columns == ["time", "metric", "verified_pct", "judge_pct"]
    points = sorted(
        (r[1], None if r[2] is None else round(float(str(r[2])), 1), r[3]) for r in rows
    )
    assert points == [("claude", 63.2, None), ("local", None, None)]
