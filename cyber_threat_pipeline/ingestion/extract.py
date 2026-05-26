"""OTX extract — cold-start and incremental, with 429 / 5xx retry.

Spec: _private/specs/02-ingestion.md §4.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
from collections.abc import Callable
from typing import Any

from OTXv2 import OTXv2  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


def extract_pulses(
    api_key: str,
    modified_since: dt.datetime | None,
) -> list[dict[str, Any]]:
    """Fetch pulses from OTX.

    ``modified_since=None`` → full backfill (cold start); otherwise incremental.
    Returns SDK-shaped pulse dicts with indicators nested under ``pulse['indicators']``.
    """
    otx = OTXv2(api_key)
    mode = (
        "full backfill (cold start)"
        if modified_since is None
        else f"incremental since {modified_since.isoformat()}"
    )
    logger.info("OTX extract: %s", mode)

    pulses: list[dict[str, Any]] = _call_with_retry(
        lambda: (
            otx.getall() if modified_since is None else otx.getall(modified_since=modified_since)
        )
    )

    logger.info("OTX extract: fetched %d pulses", len(pulses))
    return pulses


def _call_with_retry(fn: Callable[[], Any], max_attempts: int = 5) -> Any:
    """Call ``fn()``; on 429 honor Retry-After; on transient 5xx exponential back-off."""
    import requests

    backoff = 1.0
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except requests.HTTPError as e:
            response = e.response
            if response is None:
                raise
            status = response.status_code
            if status == 429:
                wait = float(response.headers.get("Retry-After", "60"))
                logger.warning(
                    "OTX 429; waiting %.0fs (attempt %d/%d)", wait, attempt, max_attempts
                )
                time.sleep(wait)
                continue
            if 500 <= status < 600:
                logger.warning(
                    "OTX %d; backing off %.1fs (attempt %d/%d)",
                    status,
                    backoff,
                    attempt,
                    max_attempts,
                )
                time.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            raise
    raise RuntimeError(f"OTX extract failed after {max_attempts} attempts")
