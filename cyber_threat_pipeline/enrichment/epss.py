"""FIRST EPSS API: batch the requests and validate each response. Pure, no I/O.

The API (``EPSS_URL``, marked BETA by FIRST) answers ``?cve=<id>,<id>,...``
with ``{"status": "OK", "total": N, "data": [{"cve", "epss", "percentile",
"date"}, ...]}``; the scores are decimal strings. Its docs cap ``cve`` at 2000
characters including commas, and call the API "designed for lookup, not bulk
access": the pipeline looks up only the CVE ids its corpus holds.
``batches`` keeps each request to at most 100 ids and 2000 characters.

A response is untrusted input, accepted whole or not at all. ``parse`` returns
its scores only when the body:

- parses as one JSON object with ``status`` "OK", an integer ``total`` and a
  ``data`` list of exactly ``total`` rows (a ``total`` above the rows returned
  means the answer was cut short);
- gives every row a ``cve`` this request asked for, at most once, an ``epss``
  and a ``percentile`` that are finite decimals from 0 to 1 with at most 9
  decimal places (they must fit ``numeric(10, 9)``: no ``1E-1000000``, no
  20,000-digit fraction; a zero is written at 9 places too, so ``0E-1000000``
  fits), and a ``date``.

An id FIRST doesn't score simply has no row. Failures raise ``FeedInvalid``
with a short reason that never quotes feed content.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from datetime import date
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError

from cyber_threat_pipeline.enrichment import FeedInvalid
from cyber_threat_pipeline.enrichment.kev import CveId

EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_IDS_PER_CALL = 100
MAX_PARAM_CHARS = 2000
MAX_BYTES = 1024 * 1024  # 100 rows are ~10 KB
MAX_CVES = 5000  # newest first; the 2026-10-14 corpus held under 2,070 CVE indicators

_NINE_PLACES = Decimal("1E-9")


def _nine_places(value: Decimal) -> Decimal:
    """Write the score at 9 places: zero passes any precision check as 0E-1000000."""
    return value.quantize(_NINE_PLACES)


# Matches raw.epss_scores' numeric(10, 9): FIRST publishes 9 decimal places.
_Score = Annotated[
    Decimal,
    Field(ge=0, le=1, max_digits=10, decimal_places=9, allow_inf_nan=False),
    AfterValidator(_nine_places),
]
_STRICT = ConfigDict(strict=True, extra="ignore", frozen=True)


class EpssScore(BaseModel):
    """One CVE's score on one EPSS date."""

    model_config = _STRICT

    cve_id: CveId = Field(alias="cve")
    epss: _Score
    percentile: _Score
    score_date: date = Field(alias="date")


class _Response(BaseModel):
    model_config = _STRICT

    status: Literal["OK"]
    total: int = Field(ge=0)
    data: tuple[EpssScore, ...]


def batches(cve_ids: Sequence[str]) -> list[list[str]]:
    """Split ids into requests of at most 100 ids and 2000 characters joined by commas."""
    out: list[list[str]] = []
    batch: list[str] = []
    length = 0
    for cve_id in cve_ids:
        if batch and (len(batch) == MAX_IDS_PER_CALL or length + 1 + len(cve_id) > MAX_PARAM_CHARS):
            out.append(batch)
            batch, length = [], 0
        length += len(cve_id) + (1 if batch else 0)
        batch.append(cve_id)
    if batch:
        out.append(batch)
    return out


def parse(raw: bytes, requested: Collection[str]) -> list[EpssScore]:
    """Validate one response to a request for ``requested``, or raise ``FeedInvalid``."""
    try:
        response = _Response.model_validate_json(raw)
    except ValidationError as e:
        errors = e.errors(include_url=False, include_context=False, include_input=False)
        where = ".".join(str(part) for part in errors[0]["loc"]) or "body"
        raise FeedInvalid(
            f"EPSS response rejected: {len(errors)} problem(s); first at {where}:"
            f" {errors[0]['msg']}"
        ) from None
    rows = response.data
    if response.total != len(rows):
        raise FeedInvalid(f"EPSS response rejected: total is {response.total}, {len(rows)} rows")
    wanted = set(requested)
    unasked = sum(1 for r in rows if r.cve_id not in wanted)
    if unasked:
        raise FeedInvalid(f"EPSS response rejected: {unasked} row(s) for ids not requested")
    if len({r.cve_id for r in rows}) != len(rows):
        raise FeedInvalid("EPSS response rejected: an id appears twice")
    return list(rows)
