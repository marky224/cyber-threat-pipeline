"""Tests for cyber_threat_pipeline.enrichment.epss: batching and what a response must be.

tests/fixtures/kev_epss/epss_response.json is one FIRST EPSS API response,
fetched 2026-10-30 from api.first.org/data/v1/epss for the five ids in
``REQUESTED``. FIRST doesn't score CVE-2026-9999999, so ``total`` is 4.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from cyber_threat_pipeline.enrichment import FeedInvalid
from cyber_threat_pipeline.enrichment.epss import (
    MAX_IDS_PER_CALL,
    MAX_PARAM_CHARS,
    batches,
    parse,
)

FIXTURE = Path(__file__).parent / "fixtures" / "kev_epss" / "epss_response.json"
RECORDED: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
REQUESTED = [
    "CVE-2021-44228",
    "CVE-2024-3400",
    "CVE-2026-59310",
    "CVE-2026-97229",
    "CVE-2026-9999999",
]


def _mutated(change: Callable[[dict[str, Any]], object]) -> bytes:
    response = copy.deepcopy(RECORDED)
    change(response)
    return json.dumps(response).encode()


def _row(response: dict[str, Any], i: int = 0) -> dict[str, Any]:
    row: dict[str, Any] = response["data"][i]
    return row


def test_the_recorded_response_parses() -> None:
    scores = {s.cve_id: s for s in parse(FIXTURE.read_bytes(), REQUESTED)}
    assert set(scores) == set(REQUESTED) - {"CVE-2026-9999999"}
    log4shell = scores["CVE-2021-44228"]
    assert log4shell.epss == Decimal("0.999990000")
    assert log4shell.percentile == Decimal("1.000000000")
    assert log4shell.score_date == date(2026, 10, 29)
    assert scores["CVE-2026-97229"].epss == Decimal("0.184270000")


def test_numbers_instead_of_strings_are_accepted() -> None:
    def numeric(r: dict[str, Any]) -> None:
        _row(r)["epss"], _row(r)["percentile"] = 0.5, 1

    assert parse(_mutated(numeric), REQUESTED)[0].epss == Decimal("0.5")


def test_an_answer_with_no_rows_is_fine() -> None:
    empty = _mutated(lambda r: r.update(total=0, data=[]))
    assert parse(empty, ["CVE-2026-9999999"]) == []


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda r: r.update(total=5), "total is 5, 4 rows"),
        (lambda r: r.update(total=3), "total is 3, 4 rows"),
        (lambda r: r.update(status="ERROR"), "status"),
        (lambda r: r.pop("status"), "status"),
        (lambda r: r.update(total="4"), "total"),
        (lambda r: r.pop("data"), "data"),
        (lambda r: _row(r).update(epss="1.5"), "epss"),
        (lambda r: _row(r).update(epss="-0.000001"), "epss"),
        (lambda r: _row(r).update(percentile="1.01"), "percentile"),
        (lambda r: _row(r).update(epss="NaN"), "epss"),
        (lambda r: _row(r).update(epss="high"), "epss"),
        (lambda r: _row(r).update(epss=None), "epss"),
        (lambda r: _row(r).update(date="yesterday"), "date"),
        (lambda r: _row(r).update(cve="CVE-26-1"), "cve"),
        (lambda r: _row(r).update(cve="CVE-2019-0708"), "1 row(s) for ids not requested"),
        (lambda r: _row(r, 1).update(cve=_row(r, 0)["cve"]), "an id appears twice"),
    ],
)
def test_a_broken_response_is_rejected_whole(
    change: Callable[[dict[str, Any]], object], problem: str
) -> None:
    with pytest.raises(FeedInvalid, match="EPSS response rejected") as e:
        parse(_mutated(change), REQUESTED)
    assert problem in str(e.value)


@pytest.mark.parametrize(
    "score",
    ["1E-1000000", "0." + "1" * 20_000, "0.1234567891"],
    ids=["tiny-exponent", "20000-digits", "10-places"],
)
def test_a_score_that_does_not_fit_numeric_10_9_is_rejected(score: str) -> None:
    # raw.epss_scores.epss is numeric(10, 9): anything parse accepts must fit it.
    with pytest.raises(FeedInvalid, match="epss"):
        parse(_mutated(lambda r: _row(r).update(epss=score)), REQUESTED)


@pytest.mark.parametrize("zero", ["0E-1000000", "0E+1000000", "0E-20", "0"])
def test_zero_with_any_exponent_is_kept_at_9_places(zero: str) -> None:
    # Zero passes any precision check, but Postgres can't take 0E-1000000.
    [score] = parse(_mutated(lambda r: _row(r).update(epss=zero)), REQUESTED)[:1]
    assert score.epss == 0
    assert score.epss.as_tuple().exponent == -9


@pytest.mark.parametrize("body", [b"", b"<html>rate limited</html>", b"[]", b"null"])
def test_a_body_that_is_not_a_response_object_is_rejected(body: bytes) -> None:
    with pytest.raises(FeedInvalid, match="EPSS response rejected"):
        parse(body, REQUESTED)


def test_batches_hold_at_most_100_ids() -> None:
    ids = [f"CVE-2026-{n:04d}" for n in range(1, 251)]
    split = batches(ids)
    assert [len(b) for b in split] == [100, 100, 50]
    assert [i for b in split for i in b] == ids


def test_batches_stay_within_2000_characters_including_commas() -> None:
    long_ids = [f"CVE-2026-{n:015d}" for n in range(1, 201)]  # 24 characters each
    split = batches(long_ids)
    assert all(len(",".join(b)) <= MAX_PARAM_CHARS for b in split)
    assert all(len(b) <= MAX_IDS_PER_CALL for b in split)
    assert [len(b) for b in split] == [80, 80, 40]  # 80 * 24 + 79 commas = 1,999
    assert [i for b in split for i in b] == long_ids


def test_no_ids_means_no_batches() -> None:
    assert batches([]) == []
