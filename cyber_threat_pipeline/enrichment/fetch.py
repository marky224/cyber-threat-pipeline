"""Bounded HTTPS GET for the vulnerability feeds (CISA KEV, FIRST EPSS).

The feeds are outside services, so every download is bounded:

- HTTPS only. ``new_session`` mounts no ``http://`` adapter, so a redirect to
  plain HTTP fails before a request goes out. It also ignores the environment
  (no proxy variables, no ``~/.netrc`` credentials) and follows at most five
  redirects.
- A project User-Agent; 10 s to connect, 30 s per read.
- The body is read in 64 KiB chunks and abandoned once it passes ``max_bytes``
  (counted after gzip decoding, so a compressed bomb is cut off too).
- At most three attempts. A connection error, a timeout, a body cut off
  mid-transfer, a 429 or a 5xx is retried after 2 s, then 4 s; a 429's numeric
  Retry-After replaces that wait, capped at 60 s. Any other non-200 fails at
  once.
- ``deadline`` (a ``time.monotonic()`` value that every call for one feed
  shares) bounds the lot: no attempt starts and no wait runs past it, each
  timeout is cut to the time left, and the body is abandoned at the first
  chunk that ends past it. A server that drips bytes can still hold one chunk
  open longer; the pipeline step's own timeout is the hard stop.

Every failure raises ``FetchError`` with a short reason (host and status or
exception name), never response content.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from time import monotonic, sleep
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)

USER_AGENT = "cyber-threat-pipeline (+https://github.com/marky224/cyber-threat-pipeline)"
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 30.0
ATTEMPTS = 3
BACKOFF = (2.0, 4.0)  # waits before attempts 2 and 3
RETRY_AFTER_CAP = 60.0
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
    session.max_redirects = 5
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
            return _get_once(session, url, params, host, max_bytes, deadline)
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


def _get_once(
    session: requests.Session,
    url: str,
    params: Mapping[str, str] | None,
    host: str,
    max_bytes: int,
    deadline: float,
) -> bytes:
    left = deadline - monotonic()
    if left <= 0:
        raise FetchError(f"{host}: time budget spent")
    timeout = (min(CONNECT_TIMEOUT, left), min(READ_TIMEOUT, left))
    try:
        response = session.get(url, params=params, timeout=timeout, stream=True)
    except requests.exceptions.InvalidSchema:
        raise FetchError(f"{host}: redirected off HTTPS") from None
    except (requests.ConnectionError, requests.Timeout) as e:
        raise _Retryable(type(e).__name__) from None
    except requests.RequestException as e:
        raise FetchError(f"{host}: {type(e).__name__}") from None
    with response:
        status = response.status_code
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
