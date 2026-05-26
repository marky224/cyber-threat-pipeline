"""Tests for the OTX retry helper. 429/5xx handling without hitting the network."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
import requests

from cyber_threat_pipeline.ingestion.extract import _call_with_retry


def _http_error(status: int, headers: dict[str, str] | None = None) -> requests.HTTPError:
    response = MagicMock(spec=requests.Response)
    response.status_code = status
    response.headers = headers or {}
    err = requests.HTTPError(response=response)
    return err


def test_retry_honors_retry_after_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

    attempts: list[int] = []

    def fn() -> str:
        attempts.append(1)
        if len(attempts) == 1:
            raise _http_error(429, headers={"Retry-After": "7"})
        return "ok"

    assert _call_with_retry(fn) == "ok"
    assert sleeps == [7.0]


def test_retry_backs_off_on_5xx(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

    calls: list[int] = []

    def fn() -> str:
        calls.append(1)
        if len(calls) < 3:
            raise _http_error(503)
        return "ok"

    assert _call_with_retry(fn) == "ok"
    assert sleeps == [1.0, 2.0]


def test_4xx_other_than_429_surfaces_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda s: None)

    def fn() -> Any:
        raise _http_error(403)

    with pytest.raises(requests.HTTPError):
        _call_with_retry(fn)


def test_gives_up_after_max_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda s: None)

    def fn() -> Any:
        raise _http_error(429, headers={"Retry-After": "1"})

    with pytest.raises(RuntimeError, match="failed after"):
        _call_with_retry(fn, max_attempts=3)
