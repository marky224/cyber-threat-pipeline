"""Bounded HTTPS GET for the vulnerability feeds (CISA KEV, FIRST EPSS).

The feeds are outside services, so every download is bounded:

- HTTPS only, at every hop, with TLS verified. Redirects (at most five) are
  followed here, not by requests: its ``Session.send`` reads every 3xx body
  whole (even with ``allow_redirects=False``), past the size cap and the
  deadline, so each request goes straight to the session's HTTPS adapter. A
  redirect's body is never read; its ``Location`` (a relative one resolved
  against the current URL) must be HTTPS; the deadline is checked again before
  each hop; and ``params`` go on the first request only. A ``Location`` that
  urljoin, requests or urllib3 can't use (``ValueError``, ``InvalidURL``,
  ``LocationParseError``) fails at once, without a retry. ``new_session`` also
  mounts no ``http://`` adapter, as a backstop, and ignores the environment (no
  proxy variables, no ``~/.netrc`` credentials).
- A project User-Agent; 10 s to connect, 30 s per read.
- The body is read in 64 KiB chunks and abandoned once it passes ``max_bytes``
  (counted after gzip decoding, so a compressed bomb is cut off too).
- At most three attempts. A connection error, a timeout, a body cut off
  mid-transfer, a 429 or a 5xx is retried after 2 s, then 4 s; a 429's numeric
  Retry-After replaces that wait, capped at 60 s. Any other non-200 fails at
  once.
- ``deadline`` (a ``time.monotonic()`` value that every call for one feed
  shares) bounds the lot: no attempt or hop starts and no wait runs past it, each
  timeout is cut to the time left, and the body is abandoned at the first
  chunk that ends past it. A server that drips bytes can still hold one chunk
  open longer; the pipeline step's own timeout is the hard stop.

Every failure raises ``FetchError`` with a short reason (host and status or
exception class name), never response content. A hop that can't even be
requested is named by the host that sent the redirect, never by its
``Location``: the parsers' messages quote the URL, so only the class is kept.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from time import monotonic, sleep
from urllib.parse import urljoin, urlsplit

import requests

logger = logging.getLogger(__name__)

USER_AGENT = "cyber-threat-pipeline (+https://github.com/marky224/cyber-threat-pipeline)"
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 30.0
ATTEMPTS = 3
BACKOFF = (2.0, 4.0)  # waits before attempts 2 and 3
RETRY_AFTER_CAP = 60.0
MAX_REDIRECTS = 5
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_CHUNK = 64 * 1024


class FetchError(Exception):
    """A download failed or broke one of its bounds."""


class _Retryable(Exception):
    """A failure worth another attempt; ``wait`` overrides the back-off."""

    def __init__(self, reason: str, wait: float | None = None) -> None:
        super().__init__(reason)
        self.wait = wait


def new_session() -> requests.Session:
    """A session that only speaks HTTPS and sends the project User-Agent."""
    session = requests.Session()
    del session.adapters["http://"]
    session.trust_env = False
    session.headers["User-Agent"] = USER_AGENT
    return session


def get_bytes(
    session: requests.Session,
    url: str,
    *,
    max_bytes: int,
    deadline: float,
    params: Mapping[str, str] | None = None,
) -> bytes:
    """GET ``url`` within the bounds in the module docstring; return the body."""
    host = urlsplit(url).hostname or "?"
    if not url.startswith("https://"):
        raise FetchError(f"{host}: refusing a non-HTTPS URL")
    for attempt in range(1, ATTEMPTS + 1):
        try:
            return _follow(session, url, params, max_bytes, deadline)
        except _Retryable as e:
            if attempt == ATTEMPTS:
                raise FetchError(f"{host}: {e}, gave up after {ATTEMPTS} attempts") from None
            wait = BACKOFF[attempt - 1] if e.wait is None else e.wait
            if monotonic() + wait >= deadline:
                raise FetchError(f"{host}: {e}, no time left to retry") from None
            logger.warning(
                "%s: %s; retrying in %.0fs (attempt %d/%d)", host, e, wait, attempt, ATTEMPTS
            )
            sleep(wait)
    raise AssertionError("unreachable")


def _follow(
    session: requests.Session,
    url: str,
    params: Mapping[str, str] | None,
    max_bytes: int,
    deadline: float,
) -> bytes:
    """One attempt: the request and up to ``MAX_REDIRECTS`` hops, each one bounded.

    ``sender`` is the host whose redirect led to ``url`` (our own host on the
    first request); errors about a hop that can't be made name it, not the hop.
    """
    host = sender = urlsplit(url).hostname or "?"
    for _ in range(MAX_REDIRECTS + 1):
        answer = _get_once(session, url, params, host, sender, max_bytes, deadline)
        if isinstance(answer, bytes):
            return answer
        sender = host
        try:
            url, params = urljoin(url, answer), None
            host = urlsplit(url).hostname or "?"
        except ValueError as e:  # e.g. an unclosed IPv6 bracket; the message quotes it
            raise FetchError(f"{sender}: {type(e).__name__}") from None
        if not url.startswith("https://"):
            raise FetchError(f"{sender}: redirected off HTTPS")
    raise FetchError(f"{sender}: more than {MAX_REDIRECTS} redirects")


def _get_once(
    session: requests.Session,
    url: str,
    params: Mapping[str, str] | None,
    host: str,
    sender: str,
    max_bytes: int,
    deadline: float,
) -> bytes | str:
    """One request: the body, or a redirect's ``Location`` (its body left unread)."""
    left = deadline - monotonic()
    if left <= 0:
        raise FetchError(f"{host}: time budget spent")
    timeout = (min(CONNECT_TIMEOUT, left), min(READ_TIMEOUT, left))
    try:
        request = session.prepare_request(requests.Request("GET", url, params=params))
        # Straight to the adapter (TLS verified, no proxies): Session.send reads a
        # redirect's whole body even with allow_redirects=False, to fill
        # Response.next, past every bound here.
        response = session.get_adapter(url).send(request, stream=True, timeout=timeout)
    except (requests.ConnectionError, requests.Timeout) as e:
        raise _Retryable(type(e).__name__) from None
    except ValueError as e:
        # A URL requests or urllib3 can't use: requests' InvalidURL (also a
        # RequestException) or urllib3's LocationParseError (not one), raised while
        # preparing or connecting. Their messages quote the URL: the class only.
        raise FetchError(f"{sender}: {type(e).__name__}") from None
    except requests.RequestException as e:
        raise FetchError(f"{host}: {type(e).__name__}") from None
    with response:
        status = response.status_code
        if status in _REDIRECTS:
            location = response.headers.get("Location")
            if not location:
                raise FetchError(f"{host}: HTTP {status} without a Location")
            return location  # closing the response drops the body unread
        if status == 429 or 500 <= status < 600:
            wait = _retry_after(response) if status == 429 else None
            raise _Retryable(f"HTTP {status}", wait)
        if status != 200:
            raise FetchError(f"{host}: HTTP {status}")
        body = bytearray()
        try:
            for chunk in response.iter_content(chunk_size=_CHUNK):
                body += chunk
                if len(body) > max_bytes:
                    raise FetchError(f"{host}: body over {max_bytes:,} bytes")
                if monotonic() > deadline:
                    raise FetchError(f"{host}: time budget spent mid-body")
        except (
            requests.ConnectionError,
            requests.Timeout,
            requests.exceptions.ChunkedEncodingError,
        ) as e:
            raise _Retryable(type(e).__name__) from None
        except requests.RequestException as e:
            raise FetchError(f"{host}: {type(e).__name__}") from None
    return bytes(body)


def _retry_after(response: requests.Response) -> float | None:
    """A 429's Retry-After in seconds, capped; None if absent or not a number."""
    try:
        seconds = float(response.headers.get("Retry-After", ""))
    except ValueError:
        return None
    if not 0 <= seconds < float("inf"):
        return None
    return min(seconds, RETRY_AFTER_CAP)
