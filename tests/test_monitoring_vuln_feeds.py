"""The committed vulnerability-feed panel and alert SQL, run as grafana_ro.

DB-integration (gated on NEON_DATABASE_URL). Reads the SQL and the alert
threshold straight from monitoring/dashboard.json and monitoring/alerts.yaml,
so the test covers what is provisioned, not a copy. marts.mart_data_quality is
a stand-in with only the columns the queries read (dbt isn't run here).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import psycopg
import pytest

MONITORING = Path(__file__).resolve().parent.parent / "monitoring"


def _panel_sql() -> str:
    panels = json.loads((MONITORING / "dashboard.json").read_text())["panels"]
    [panel] = [p for p in panels if p["title"].startswith("Vulnerability feeds")]
    sql: str = panel["targets"][0]["rawSql"]
    return sql


def _alert() -> tuple[str, float]:
    """The rule's query and its ``gt`` threshold (read as text, like the grounding test)."""
    text = (MONITORING / "alerts.yaml").read_text()
    rule = text[text.index("uid: ctp-vuln-feed-stale") :]
    sql = re.search(r"rawSql: \|\n((?:\s{16}.*\n)+)", rule)
    threshold = re.search(r"evaluator: \{ type: gt, params: \[([0-9.]+)\] \}", rule)
    assert sql is not None and threshold is not None
    return sql.group(1), float(threshold.group(1))


@pytest.fixture()
def dq(pg_conn: psycopg.Connection) -> psycopg.Connection:
    """A stand-in marts.mart_data_quality (dbt's grants: grafana_ro via default privileges)."""
    with pg_conn.cursor() as cur:
        cur.execute("drop table if exists marts.mart_data_quality")
        cur.execute(
            "create table marts.mart_data_quality"
            " (run_id bigint, kev_fetched_at timestamptz, epss_fetched_at timestamptz)"
        )
    return pg_conn


def _row(conn: psycopg.Connection, run_id: int, kev_age: str | None, epss_age: str | None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "insert into marts.mart_data_quality values"
            " (%s, now() - %s::interval, now() - %s::interval)",
            (run_id, kev_age, epss_age),
        )


def _as_grafana(conn: psycopg.Connection, sql: str) -> tuple[list[str], list[tuple[Any, ...]]]:
    """Run ``sql`` as grafana_ro (the role Grafana's datasource uses)."""
    with conn.cursor() as cur:
        cur.execute("set role grafana_ro")
        try:
            cur.execute(sql)
            assert cur.description is not None
            return [c.name for c in cur.description], cur.fetchall()
        finally:
            cur.execute("reset role")


def _alert_value(conn: psycopg.Connection) -> float | None:
    sql, _ = _alert()
    _, rows = _as_grafana(conn, sql)
    return float(rows[0][0]) if rows else None


def test_fresh_feeds_keep_the_alert_quiet(dq: psycopg.Connection) -> None:
    _row(dq, 1, "1 day", "2 days")
    value = _alert_value(dq)
    assert value is not None
    assert 1.9 < value < 2.1
    assert not value > _alert()[1]


@pytest.mark.parametrize(("kev_age", "epss_age"), [("16 days", "1 day"), ("1 day", "16 days")])
def test_either_feed_over_15_days_old_fires(
    dq: psycopg.Connection, kev_age: str, epss_age: str
) -> None:
    _row(dq, 1, kev_age, epss_age)
    value = _alert_value(dq)
    assert value is not None
    assert value > _alert()[1]


@pytest.mark.parametrize(("kev_age", "epss_age"), [(None, "1 day"), ("1 day", None), (None, None)])
def test_a_feed_never_fetched_fires(
    dq: psycopg.Connection, kev_age: str | None, epss_age: str | None
) -> None:
    _row(dq, 1, kev_age, epss_age)
    assert _alert_value(dq) == pytest.approx(999.0)


def test_only_the_latest_run_row_counts(dq: psycopg.Connection) -> None:
    _row(dq, 1, "40 days", "40 days")
    _row(dq, 2, "1 day", "1 day")
    value = _alert_value(dq)
    assert value is not None
    assert not value > _alert()[1]


def test_no_row_gives_no_data(dq: psycopg.Connection) -> None:
    assert _alert_value(dq) is None


def test_the_panel_shows_each_feeds_age_in_days(dq: psycopg.Connection) -> None:
    _row(dq, 1, "3 days", None)
    columns, rows = _as_grafana(dq, _panel_sql())
    assert columns == ["KEV", "EPSS"]
    [(kev_days, epss_days)] = rows
    assert 2.9 < float(kev_days) < 3.1
    assert epss_days is None
