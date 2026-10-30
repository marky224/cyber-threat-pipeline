"""A scripted stand-in for the network, for the enrichment tests.

``FakeAdapter`` is mounted on ``https://`` of a real ``fetch.new_session()``,
so fetch's real request path (request preparation, its own redirect handling,
requests' streaming and error wrapping) runs while nothing leaves the process.
``block_real_http`` makes any real send fail.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import ProtocolError


@dataclass
class Reply:
    """One scripted response. ``fail_after`` cuts the body off after that many chunks."""

    status: int = 200
    body: bytes | list[bytes] = b""
    headers: dict[str, str] = field(default_factory=dict)
    fail_after: int | None = None


Script = Reply | Exception


class _Raw:
    """Enough of urllib3's HTTPResponse for requests to stream from."""

    def __init__(self, chunks: list[bytes], fail_after: int | None) -> None:
        self._chunks = chunks
        self._fail_after = fail_after
        self.chunks_read = 0

    def stream(self, amt: int | None = None, decode_content: bool | None = None) -> Iterator[bytes]:
        while self.chunks_read < len(self._chunks):
            if self.chunks_read == self._fail_after:
                raise ProtocolError("connection broken")
            self.chunks_read += 1
            yield self._chunks[self.chunks_read - 1]

    def read(self, amt: int | None = None, decode_content: bool | None = None) -> bytes:
        return b"".join(self.stream())

    def close(self) -> None:
        pass

    def release_conn(self) -> None:
        pass


class FakeAdapter(BaseAdapter):
    """Answers each request from the script queued for its host, in order."""

    def __init__(self, routes: Mapping[str, list[Script]]) -> None:
        super().__init__()
        self.routes = {host: list(queue) for host, queue in routes.items()}
        self.sent: list[requests.PreparedRequest] = []
        self.timeouts: list[Any] = []
        self.verify: list[Any] = []
        self.raws: list[_Raw] = []
        self.on_send: list[Any] = []  # callables run before each answer

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: Any = True,
        cert: Any = None,
        proxies: Any = None,
    ) -> requests.Response:
        self.sent.append(request)
        self.timeouts.append(timeout)
        self.verify.append(verify)
        for hook in self.on_send:
            hook()
        host = urlsplit(str(request.url)).hostname or ""
        item = self.routes[host].pop(0)
        if isinstance(item, Exception):
            raise item
        chunks = item.body if isinstance(item.body, list) else [item.body]
        raw = _Raw(chunks, item.fail_after)
        self.raws.append(raw)
        response = requests.Response()
        response.status_code = item.status
        response.headers = CaseInsensitiveDict(item.headers)
        response.raw = raw
        response.url = str(request.url)
        response.request = request
        response.reason = "scripted"
        return response

    def close(self) -> None:
        pass

    def hosts(self) -> list[str]:
        return [urlsplit(str(r.url)).hostname or "" for r in self.sent]

    def query(self, index: int) -> dict[str, list[str]]:
        return parse_qs(urlsplit(str(self.sent[index].url)).query)


def session_with(routes: Mapping[str, list[Script]]) -> tuple[requests.Session, FakeAdapter]:
    """A real ``fetch.new_session()`` whose HTTPS traffic goes to a FakeAdapter."""
    from cyber_threat_pipeline.enrichment.fetch import new_session

    session = new_session()
    adapter = FakeAdapter(routes)
    session.mount("https://", adapter)
    return session, adapter


def block_real_http(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any send through requests' real HTTP adapter fail the test."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a test tried to use the network")

    monkeypatch.setattr("requests.adapters.HTTPAdapter.send", refuse)


def kev_body(cve_ids: list[str], *, version: str = "2026.10.29", name: str = "name") -> bytes:
    """A valid KEV catalog body listing ``cve_ids``."""
    entries = [
        {
            "cveID": cve_id,
            "vendorProject": "Vendor",
            "product": "Product",
            "vulnerabilityName": f"{cve_id} {name}",
            "dateAdded": "2026-10-01",
            "knownRansomwareCampaignUse": "Unknown",
        }
        for cve_id in cve_ids
    ]
    catalog = {
        "catalogVersion": version,
        "dateReleased": "2026-10-29T19:09:34.4003Z",
        "count": len(entries),
        "vulnerabilities": entries,
    }
    return json.dumps(catalog).encode()


def epss_body(scores: dict[str, str], *, total: int | None = None) -> bytes:
    """A valid EPSS API body scoring each id in ``scores`` (epss as a decimal string)."""
    data = [
        {"cve": cve_id, "epss": epss, "percentile": "0.5", "date": "2026-10-29"}
        for cve_id, epss in scores.items()
    ]
    body = {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": len(data) if total is None else total,
        "offset": 0,
        "limit": 100,
        "data": data,
    }
    return json.dumps(body).encode()
