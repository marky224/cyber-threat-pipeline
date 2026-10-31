"""Tests for cyber_threat_pipeline.enrichment.fetch: the bounds on every feed download.

No network: a scripted adapter answers (tests/fake_http.py), and requests'
real HTTP adapter is made to fail if anything reaches it.
"""

from __future__ import annotations

import socket
from collections.abc import Sequence

import pytest
import requests
import requests.adapters

from cyber_threat_pipeline.enrichment import fetch
from cyber_threat_pipeline.enrichment.fetch import FetchError, get_bytes
from tests.fake_http import FakeAdapter, Reply, Script, block_real_http, session_with

URL = "https://feed.example/data.json"
FAR = 10_000.0  # a deadline nobody reaches
REAL_SEND = requests.adapters.HTTPAdapter.send  # captured before any test blocks it


@pytest.fixture(autouse=True)
def _no_real_http(monkeypatch: pytest.MonkeyPatch) -> None:
    block_real_http(monkeypatch)


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    waited: list[float] = []
    monkeypatch.setattr(fetch, "sleep", waited.append)
    monkeypatch.setattr(fetch, "monotonic", lambda: 0.0)
    return waited


def _get(script: Sequence[Script], *, max_bytes: int = 1_000, deadline: float = FAR) -> bytes:
    session, _ = session_with({"feed.example": list(script)})
    return get_bytes(session, URL, max_bytes=max_bytes, deadline=deadline)


def test_returns_the_body_and_sends_the_bounds(sleeps: list[float]) -> None:
    session, adapter = session_with({"feed.example": [Reply(body=[b"ab", b"cd"])]})
    body = get_bytes(session, URL, max_bytes=100, deadline=FAR, params={"cve": "CVE-2026-0001"})
    assert body == b"abcd"
    assert adapter.timeouts == [(10.0, 30.0)]
    assert adapter.verify == [True]  # TLS certificates are checked
    assert adapter.sent[0].headers["User-Agent"] == fetch.USER_AGENT
    assert adapter.query(0) == {"cve": ["CVE-2026-0001"]}
    assert sleeps == []


def test_timeouts_shrink_to_the_time_left(sleeps: list[float]) -> None:
    session, adapter = session_with({"feed.example": [Reply(body=b"x")]})
    get_bytes(session, URL, max_bytes=10, deadline=5.0)
    assert adapter.timeouts == [(5.0, 5.0)]


def test_body_over_the_cap_is_abandoned_mid_stream(sleeps: list[float]) -> None:
    session, adapter = session_with({"feed.example": [Reply(body=[b"x" * 10] * 100)]})
    with pytest.raises(FetchError, match="body over 25 bytes"):
        get_bytes(session, URL, max_bytes=25, deadline=FAR)
    assert adapter.raws[0].chunks_read == 3


def test_5xx_is_retried_with_back_off(sleeps: list[float]) -> None:
    assert _get([Reply(503), Reply(502), Reply(body=b"ok")]) == b"ok"
    assert sleeps == [2.0, 4.0]


def test_gives_up_after_three_attempts(sleeps: list[float]) -> None:
    session, adapter = session_with({"feed.example": [Reply(500), Reply(500), Reply(500)]})
    with pytest.raises(FetchError, match="HTTP 500, gave up after 3 attempts"):
        get_bytes(session, URL, max_bytes=10, deadline=FAR)
    assert len(adapter.sent) == 3
    assert sleeps == [2.0, 4.0]


def test_connection_errors_and_timeouts_are_retried(sleeps: list[float]) -> None:
    script: list[Script] = [requests.ConnectionError("refused"), requests.ReadTimeout("slow")]
    assert _get([*script, Reply(body=b"ok")]) == b"ok"
    assert sleeps == [2.0, 4.0]


def test_a_body_cut_off_mid_transfer_is_retried(sleeps: list[float]) -> None:
    assert _get([Reply(body=[b"a", b"b"], fail_after=1), Reply(body=b"ok")]) == b"ok"
    assert sleeps == [2.0]


def test_retry_after_is_honoured_and_capped(sleeps: list[float]) -> None:
    script = [
        Reply(429, headers={"Retry-After": "7"}),
        Reply(429, headers={"Retry-After": "3600"}),
        Reply(body=b"ok"),
    ]
    assert _get(script) == b"ok"
    assert sleeps == [7.0, 60.0]


@pytest.mark.parametrize("value", ["soon", "-5", "nan", "Wed, 21 Oct 2026 07:28:00 GMT"])
def test_unusable_retry_after_falls_back_to_back_off(sleeps: list[float], value: str) -> None:
    assert _get([Reply(429, headers={"Retry-After": value}), Reply(body=b"ok")]) == b"ok"
    assert sleeps == [2.0]


@pytest.mark.parametrize("status", [301, 403, 404])
def test_other_statuses_fail_at_once(sleeps: list[float], status: int) -> None:
    session, adapter = session_with({"feed.example": [Reply(status)]})
    with pytest.raises(FetchError, match=f"feed.example: HTTP {status}"):
        get_bytes(session, URL, max_bytes=10, deadline=FAR)
    assert len(adapter.sent) == 1
    assert sleeps == []


def test_no_attempt_starts_after_the_deadline(sleeps: list[float]) -> None:
    session, adapter = session_with({"feed.example": [Reply(body=b"ok")]})
    with pytest.raises(FetchError, match="time budget spent"):
        get_bytes(session, URL, max_bytes=10, deadline=0.0)
    assert adapter.sent == []


def test_no_wait_runs_past_the_deadline(sleeps: list[float]) -> None:
    session, adapter = session_with({"feed.example": [Reply(503), Reply(body=b"ok")]})
    with pytest.raises(FetchError, match="HTTP 503, no time left to retry"):
        get_bytes(session, URL, max_bytes=10, deadline=1.5)
    assert len(adapter.sent) == 1
    assert sleeps == []


def test_a_body_still_arriving_at_the_deadline_is_abandoned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter([0.0, 1.0, 2.0, 3.0, 4.0, 5.0])
    monkeypatch.setattr(fetch, "monotonic", lambda: next(ticks))
    session, adapter = session_with({"feed.example": [Reply(body=[b"x"] * 10)]})
    with pytest.raises(FetchError, match="time budget spent mid-body"):
        get_bytes(session, URL, max_bytes=100, deadline=2.5)
    assert adapter.raws[0].chunks_read == 3


def test_refuses_a_non_https_url(sleeps: list[float]) -> None:
    session, adapter = session_with({"feed.example": [Reply(body=b"ok")]})
    with pytest.raises(FetchError, match="refusing a non-HTTPS URL"):
        get_bytes(session, "http://feed.example/data.json", max_bytes=10, deadline=FAR)
    assert adapter.sent == []


def test_a_redirect_to_plain_http_is_never_followed(sleeps: list[float]) -> None:
    redirect = Reply(302, headers={"Location": "http://feed.example/data.json"}, body=[b"x"] * 3)
    session, adapter = session_with({"feed.example": [redirect]})
    with pytest.raises(FetchError, match="redirected off HTTPS"):
        get_bytes(session, URL, max_bytes=10, deadline=FAR)
    assert len(adapter.sent) == 1
    assert adapter.raws[0].chunks_read == 0


def test_a_redirect_body_is_never_read(sleeps: list[float]) -> None:
    # requests would read every 3xx body whole: no size cap, no deadline.
    five_mb = [b"x" * 1024] * 5 * 1024
    redirect = Reply(302, headers={"Location": "https://feed.example/b"}, body=five_mb)
    session, adapter = session_with({"feed.example": [redirect, Reply(body=b"ok")]})
    assert get_bytes(session, URL, max_bytes=1024, deadline=FAR) == b"ok"
    assert adapter.raws[0].chunks_read == 0
    assert [r.url for r in adapter.sent] == [URL, "https://feed.example/b"]


def test_the_deadline_is_checked_at_every_hop(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter(range(100))
    monkeypatch.setattr(fetch, "monotonic", lambda: float(next(ticks)))
    monkeypatch.setattr(fetch, "sleep", lambda seconds: None)
    hops: list[Script] = [
        Reply(302, headers={"Location": f"https://feed.example/{n}"}) for n in "bcd"
    ]
    session, adapter = session_with({"feed.example": [*hops, Reply(body=b"ok")]})
    with pytest.raises(FetchError, match="time budget spent"):
        get_bytes(session, URL, max_bytes=10, deadline=1.5)
    assert len(adapter.sent) == 2


@pytest.mark.parametrize("location", ["https://.evil/x", "https://*/x"])
def test_the_time_budget_running_out_between_hops_names_the_sender(
    monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    ticks = iter([0.0, 1.0])
    monkeypatch.setattr(fetch, "monotonic", lambda: next(ticks))
    redirect = Reply(302, headers={"Location": location})
    session, adapter = session_with({"feed.example": [redirect, Reply(body=b"ok")]})
    with pytest.raises(FetchError) as e:
        get_bytes(session, URL, max_bytes=10, deadline=0.5)
    # The host that sent the redirect; never the Location, which nobody checked yet.
    assert str(e.value) == "feed.example: time budget spent"
    assert len(adapter.sent) == 1


def test_a_relative_location_is_followed_without_the_first_requests_params(
    sleeps: list[float],
) -> None:
    redirect = Reply(301, headers={"Location": "/b?page=2"})
    session, adapter = session_with({"feed.example": [redirect, Reply(body=b"ok")]})
    body = get_bytes(session, URL, max_bytes=10, deadline=FAR, params={"cve": "CVE-2026-0001"})
    assert body == b"ok"
    assert adapter.query(0) == {"cve": ["CVE-2026-0001"]}
    assert adapter.sent[1].url == "https://feed.example/b?page=2"


def test_more_than_five_redirects_fail(sleeps: list[float]) -> None:
    hops: list[Script] = [
        Reply(307, headers={"Location": f"https://feed.example/{n}"}) for n in range(6)
    ]
    session, adapter = session_with({"feed.example": hops})
    with pytest.raises(FetchError, match="more than 5 redirects"):
        get_bytes(session, URL, max_bytes=10, deadline=FAR)
    assert len(adapter.sent) == 6


def test_a_redirect_without_a_location_fails_at_once(sleeps: list[float]) -> None:
    session, adapter = session_with({"feed.example": [Reply(302)]})
    with pytest.raises(FetchError, match="HTTP 302"):
        get_bytes(session, URL, max_bytes=10, deadline=FAR)
    assert len(adapter.sent) == 1


@pytest.mark.parametrize(
    ("location", "error"),
    [
        ("https://[::1/", "ValueError"),  # urljoin can't parse it
        ("https://a:99999/x", "InvalidURL"),  # requests can't prepare it
        ("https://*/x", "InvalidURL"),
        ("https://.evil/x", "InvalidURL"),
    ],
)
def test_an_unusable_redirect_location_is_a_fetch_error_naming_no_location(
    sleeps: list[float], caplog: pytest.LogCaptureFixture, location: str, error: str
) -> None:
    redirect = Reply(302, headers={"Location": location})
    session, adapter = session_with({"feed.example": [redirect, Reply(body=b"ok")]})
    with pytest.raises(FetchError) as e:
        get_bytes(session, URL, max_bytes=10, deadline=FAR)
    # The host that sent the redirect and the error class; never the Location.
    assert str(e.value) == f"feed.example: {error}"
    assert len(adapter.sent) == 1  # fails at once: no retry, no second hop
    assert sleeps == []
    assert location not in caplog.text


def test_a_location_urllib3_rejects_at_connect_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    # requests' real HTTPAdapter for the second hop, with DNS stubbed: nothing leaves.
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", REAL_SEND)

    def no_dns(*args: object, **kwargs: object) -> None:
        raise AssertionError("a test tried to resolve a host")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    session = fetch.new_session()
    redirect = Reply(302, headers={"Location": "https://evil..com/x"})
    session.mount("https://feed.example/", FakeAdapter({"feed.example": [redirect]}))
    with pytest.raises(FetchError) as e:
        get_bytes(session, URL, max_bytes=10, deadline=FAR)
    assert str(e.value) == "feed.example: LocationParseError"
    assert sleeps == []


@pytest.mark.parametrize(
    ("error", "named"),
    [
        # The hop's own answer: urllib3 rejects its header (two Content-Lengths, say).
        pytest.param(
            requests.exceptions.InvalidHeader("Content-Length contained multiple (1, 2)"),
            "cdn.example",
            id="InvalidHeader",
        ),
        # The Location itself: still the host that sent it.
        pytest.param(
            requests.exceptions.InvalidURL("Failed to parse: https://cdn.example/x"),
            "feed.example",
            id="InvalidURL",
        ),
    ],
)
def test_a_failed_hop_names_the_hop_unless_its_location_is_unusable(
    sleeps: list[float], error: Exception, named: str
) -> None:
    redirect = Reply(302, headers={"Location": "https://cdn.example/x"})
    session, adapter = session_with({"feed.example": [redirect], "cdn.example": [error]})
    with pytest.raises(FetchError) as e:
        get_bytes(session, URL, max_bytes=10, deadline=FAR)
    assert str(e.value) == f"{named}: {type(error).__name__}"  # the class, never its text
    assert adapter.hosts() == ["feed.example", "cdn.example"]  # fails at once: no retry
    assert sleeps == []


def test_new_session_speaks_only_https_and_ignores_the_environment() -> None:
    session = fetch.new_session()
    assert list(session.adapters) == ["https://"]
    assert session.trust_env is False
    assert session.headers["User-Agent"] == fetch.USER_AGENT
