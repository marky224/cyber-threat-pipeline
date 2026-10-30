"""Tests for ``make enrich`` (cyber_threat_pipeline.enrichment.__main__.run).

DB-integration (gated on NEON_DATABASE_URL) with a scripted network: the feeds
answer from tests/fake_http.py and the recorded fixtures, and any real HTTP
send fails the test. A feed problem must leave that feed's stored snapshot
exactly as it was, leave the other feed alone, and still return 0.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
import requests

from cyber_threat_pipeline.enrichment import __main__ as enrich
from cyber_threat_pipeline.enrichment import epss, fetch, kev, load
from tests.fake_http import (
    FakeAdapter,
    Reply,
    Script,
    block_real_http,
    epss_body,
    kev_body,
    session_with,
)
from tests.test_enrichment_load import add_indicator

FIXTURES = Path(__file__).parent / "fixtures" / "kev_epss"
KEV_RECORDED = (FIXTURES / "kev_catalog.json").read_bytes()  # 12 entries
EPSS_RECORDED = (FIXTURES / "epss_response.json").read_bytes()
EPSS_IDS = [
    "CVE-2021-44228",
    "CVE-2024-3400",
    "CVE-2026-59310",
    "CVE-2026-97229",
    "CVE-2026-9999999",
]
CISA, MIRROR, FIRST = "www.cisa.gov", "raw.githubusercontent.com", "api.first.org"
DOWN: list[Script] = [Reply(503), Reply(503), Reply(503)]


@pytest.fixture(autouse=True)
def _no_real_http_or_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    block_real_http(monkeypatch)
    monkeypatch.setattr(fetch, "sleep", lambda seconds: None)


@pytest.fixture()
def corpus(pg_conn: psycopg.Connection) -> Iterator[psycopg.Connection]:
    """The five ids the recorded EPSS response answers, as CVE indicators."""
    for n, cve_id in enumerate(EPSS_IDS, start=1):
        add_indicator(pg_conn, n, cve_id, f"2026-10-0{n}")
    yield pg_conn


def _run(pg_url: str, routes: dict[str, list[Script]]) -> FakeAdapter:
    session, adapter = session_with(routes)
    assert enrich.run(pg_url, session=session) == 0
    return adapter


def _table(conn: psycopg.Connection, table: str) -> list[tuple[Any, ...]]:
    with conn.cursor() as cur:
        cur.execute(f"select * from raw.{table} order by cve_id")
        return cur.fetchall()


def _store_kev(conn: psycopg.Connection, cve_ids: list[str]) -> list[tuple[Any, ...]]:
    load.write_kev(conn, kev.parse(kev_body(cve_ids, version="stored")))
    return _table(conn, "kev_vulnerabilities")


def _store_epss(conn: psycopg.Connection, cve_ids: list[str]) -> list[tuple[Any, ...]]:
    load.write_epss(conn, epss.parse(epss_body(dict.fromkeys(cve_ids, "0.01")), cve_ids))
    return _table(conn, "epss_scores")


def test_both_feeds_are_fetched_and_stored(pg_url: str, corpus: psycopg.Connection) -> None:
    adapter = _run(pg_url, {CISA: [Reply(body=KEV_RECORDED)], FIRST: [Reply(body=EPSS_RECORDED)]})
    assert adapter.hosts() == [CISA, FIRST]
    assert adapter.query(1)["cve"] == [",".join(reversed(EPSS_IDS))]  # newest first
    assert len(_table(corpus, "kev_vulnerabilities")) == 12
    assert {r[0] for r in _table(corpus, "epss_scores")} == set(EPSS_IDS) - {"CVE-2026-9999999"}


@pytest.mark.parametrize(
    "cisa",
    [
        DOWN,
        [requests.ConnectionError("dns"), requests.ConnectTimeout("slow"), Reply(500)],
        [Reply(403)],
        [Reply(body=b"<html><body>Access Denied</body></html>")],
        [Reply(body=kev_body(["CVE-2026-0001"])[:-2])],
    ],
)
def test_a_failing_cisa_gov_falls_back_to_the_mirror(
    pg_url: str, corpus: psycopg.Connection, cisa: list[Script]
) -> None:
    adapter = _run(
        pg_url,
        {CISA: list(cisa), MIRROR: [Reply(body=KEV_RECORDED)], FIRST: [Reply(body=EPSS_RECORDED)]},
    )
    assert adapter.hosts()[-2:] == [MIRROR, FIRST]
    assert len(_table(corpus, "kev_vulnerabilities")) == 12


@pytest.mark.parametrize(
    "replies",
    [
        (DOWN, DOWN),
        ([Reply(body=b"not json")], [Reply(body=b"[]")]),
        ([Reply(body=kev_body(["CVE-2026-0001", "CVE-2026-0001"]))], [Reply(404)]),
    ],
)
def test_no_valid_catalog_keeps_the_stored_snapshot_and_still_stores_epss(
    pg_url: str, corpus: psycopg.Connection, replies: tuple[list[Script], list[Script]]
) -> None:
    stored = _store_kev(corpus, ["CVE-2021-44228", "CVE-2024-3400"])
    cisa, mirror = replies
    _run(pg_url, {CISA: list(cisa), MIRROR: list(mirror), FIRST: [Reply(body=EPSS_RECORDED)]})
    assert _table(corpus, "kev_vulnerabilities") == stored
    assert len(_table(corpus, "epss_scores")) == 4


def test_the_shrink_guard_keeps_the_stored_snapshot(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    stored = _store_kev(pg_conn, [f"CVE-2026-{n:04d}" for n in range(1, 15)])  # 14 > 12 / 0.9
    adapter = _run(pg_url, {CISA: [Reply(body=KEV_RECORDED)], MIRROR: [Reply(body=KEV_RECORDED)]})
    assert adapter.hosts() == [CISA, MIRROR]
    assert _table(pg_conn, "kev_vulnerabilities") == stored


@pytest.mark.parametrize(
    "second_batch",
    [
        DOWN,
        [Reply(body=epss_body({"CVE-2026-0001": "0.5"}, total=2))],  # cut short
        [Reply(body=epss_body({"CVE-2026-0001": "1.5"}))],
        [Reply(body=epss_body({"CVE-2019-0708": "0.5"}))],  # an id nobody asked for
    ],
)
def test_one_failed_epss_batch_keeps_every_stored_score(
    pg_url: str,
    pg_conn: psycopg.Connection,
    monkeypatch: pytest.MonkeyPatch,
    second_batch: list[Script],
) -> None:
    monkeypatch.setattr(epss, "MAX_IDS_PER_CALL", 2)
    ids = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    for n, cve_id in enumerate(ids, start=1):
        add_indicator(pg_conn, n, cve_id, f"2026-10-0{n}")
    stored = _store_epss(pg_conn, ids)
    first_batch = Reply(body=epss_body({"CVE-2026-0003": "0.9", "CVE-2026-0002": "0.8"}))
    adapter = _run(
        pg_url,
        {CISA: [Reply(body=KEV_RECORDED)], FIRST: [first_batch, *second_batch]},
    )
    assert adapter.query(1)["cve"] == ["CVE-2026-0003,CVE-2026-0002"]
    assert adapter.query(2)["cve"] == ["CVE-2026-0001"]
    assert _table(pg_conn, "epss_scores") == stored
    assert len(_table(pg_conn, "kev_vulnerabilities")) == 12


def test_no_scores_at_all_keeps_the_stored_scores_and_says_so(
    pg_url: str, corpus: psycopg.Connection, caplog: pytest.LogCaptureFixture
) -> None:
    stored = _store_epss(corpus, EPSS_IDS[:2])
    _run(pg_url, {CISA: [Reply(body=KEV_RECORDED)], FIRST: [Reply(body=epss_body({}))]})
    assert _table(corpus, "epss_scores") == stored
    assert "none of 5 CVE ids came back scored" in caplog.text


def test_no_cve_indicators_means_no_epss_call(pg_url: str, pg_conn: psycopg.Connection) -> None:
    add_indicator(pg_conn, 1, "evil.example", "2026-10-01", type_="domain")
    adapter = _run(pg_url, {CISA: [Reply(body=KEV_RECORDED)]})
    assert adapter.hosts() == [CISA]
    assert _table(pg_conn, "epss_scores") == []


def test_only_the_newest_ids_are_scored_past_the_cap(
    pg_url: str, corpus: psycopg.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(epss, "MAX_CVES", 2)
    newest = {"CVE-2026-9999999": "0.2", "CVE-2026-97229": "0.3"}
    adapter = _run(
        pg_url, {CISA: [Reply(body=KEV_RECORDED)], FIRST: [Reply(body=epss_body(newest))]}
    )
    assert adapter.query(1)["cve"] == ["CVE-2026-9999999,CVE-2026-97229"]


def test_no_database_connection_is_open_while_the_feeds_download(
    pg_url: str, corpus: psycopg.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[psycopg.Connection] = []
    real_connect = psycopg.connect

    def recording_connect(*args: Any, **kwargs: Any) -> psycopg.Connection:
        conn = real_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(psycopg, "connect", recording_connect)
    session, adapter = session_with(
        {CISA: [Reply(body=KEV_RECORDED)], FIRST: [Reply(body=EPSS_RECORDED)]}
    )
    open_during_downloads: list[int] = []
    adapter.on_send.append(lambda: open_during_downloads.append(sum(not c.closed for c in opened)))
    assert enrich.run(pg_url, session=session) == 0
    assert open_during_downloads == [0, 0]
    assert len(opened) == 2
    assert all(c.closed for c in opened)


def test_both_feeds_failing_still_exits_0(pg_url: str, pg_conn: psycopg.Connection) -> None:
    stored = _store_kev(pg_conn, ["CVE-2026-0001"])
    _run(pg_url, {CISA: DOWN[:], MIRROR: DOWN[:]})
    assert _table(pg_conn, "kev_vulnerabilities") == stored


def test_a_nul_in_the_catalog_version_never_reaches_the_database(
    pg_url: str, corpus: psycopg.Connection
) -> None:
    body = json.loads(KEV_RECORDED)
    body["catalogVersion"] = "2026.10.29\u0000"
    _run(
        pg_url, {CISA: [Reply(body=json.dumps(body).encode())], FIRST: [Reply(body=EPSS_RECORDED)]}
    )
    assert {r[6] for r in _table(corpus, "kev_vulnerabilities")} == {"2026.10.29"}
    assert len(_table(corpus, "epss_scores")) == 4


def test_an_epss_score_postgres_cannot_store_is_a_warning(
    pg_url: str, corpus: psycopg.Connection, caplog: pytest.LogCaptureFixture
) -> None:
    stored = _store_epss(corpus, EPSS_IDS[:2])
    body = json.loads(EPSS_RECORDED)
    body["data"][0]["epss"] = "1E-1000000"
    _run(pg_url, {CISA: [Reply(body=KEV_RECORDED)], FIRST: [Reply(body=json.dumps(body).encode())]})
    assert _table(corpus, "epss_scores") == stored
    assert len(_table(corpus, "kev_vulnerabilities")) == 12
    assert "EPSS failed: EPSS response rejected" in caplog.text


def test_rows_the_database_rejects_keep_that_feeds_snapshot_and_the_other_feed_is_written(
    pg_url: str,
    corpus: psycopg.Connection,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    stored = _store_kev(corpus, ["CVE-2021-44228"])

    def write_a_row_the_check_rejects(conn: psycopg.Connection, catalog: object) -> int:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute(
                "insert into raw.kev_vulnerabilities"
                " (cve_id, date_added, catalog_version, catalog_released_at)"
                " values ('not-a-cve', '2026-10-01', 'x', now())"
            )
        return 1

    monkeypatch.setattr(load, "write_kev", write_a_row_the_check_rejects)
    _run(pg_url, {CISA: [Reply(body=KEV_RECORDED)], FIRST: [Reply(body=EPSS_RECORDED)]})
    assert _table(corpus, "kev_vulnerabilities") == stored
    assert len(_table(corpus, "epss_scores")) == 4
    assert "KEV: the database rejected the catalog (CheckViolation)" in caplog.text
    assert "not-a-cve" not in caplog.text


def test_a_lost_connection_while_writing_still_raises(
    pg_url: str, corpus: psycopg.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    def lose_the_connection(conn: psycopg.Connection, catalog: object) -> int:
        raise psycopg.OperationalError("server closed the connection unexpectedly")

    monkeypatch.setattr(load, "write_kev", lose_the_connection)
    session, _ = session_with(
        {CISA: [Reply(body=KEV_RECORDED)], FIRST: [Reply(body=EPSS_RECORDED)]}
    )
    with pytest.raises(psycopg.OperationalError):
        enrich.run(pg_url, session=session)


def test_a_database_error_is_not_swallowed(pg_url: str) -> None:
    session, adapter = session_with({})
    with pytest.raises(psycopg.OperationalError):
        enrich.run(pg_url.rsplit("/", 1)[0] + "/no_such_database", session=session)
    assert adapter.sent == []
