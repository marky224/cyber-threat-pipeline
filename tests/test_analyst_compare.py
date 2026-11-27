"""cyber_threat_pipeline.analyst.compare: the result-match rule. Pure tests, no database."""

from __future__ import annotations

import datetime as dt
from decimal import Decimal
from typing import Any

import pytest

from cyber_threat_pipeline.analyst.compare import MAX_COLUMNS, Verdict, compare

_PASS = Verdict(True, None, False)


def _match(gold: list[tuple[Any, ...]], model: list[tuple[Any, ...]], **kw: Any) -> Verdict:
    kw.setdefault("ordered", False)
    return compare(gold, model, **kw)


def test_equal_rows_pass() -> None:
    assert _match([("a", 1), ("b", 2)], [("a", 1), ("b", 2)], ordered=True) == _PASS


def test_an_ordered_question_fails_on_rows_in_another_order() -> None:
    verdict = _match([("a", 1), ("b", 2)], [("b", 2), ("a", 1)], ordered=True)
    assert verdict == Verdict(False, "rows differ (compared in order)", False)


def test_an_unordered_question_compares_rows_as_a_multiset() -> None:
    assert _match([("a", 1), ("b", 2), ("b", 2)], [("b", 2), ("a", 1), ("b", 2)]) == _PASS
    verdict = _match([("a", 1), ("b", 2), ("b", 2)], [("a", 1), ("a", 1), ("b", 2)])
    assert verdict == Verdict(False, "rows differ (compared as a set)", False)


def test_column_names_and_order_are_ignored_and_extra_columns_allowed() -> None:
    # gold (tag, count); the model's columns are (count, extra, tag).
    gold = [("ransomware", 9), ("phishing", 4)]
    model = [(9, "x", "ransomware"), (4, "y", "phishing")]
    assert _match(gold, model, ordered=True) == _PASS


def test_each_gold_column_maps_to_a_distinct_model_column() -> None:
    # Both gold columns hold the same values, but the model has only one such column.
    assert _match([(1, 1), (2, 2)], [(1, "a"), (2, "b")]).passed is False


def test_the_mapping_is_found_jointly_for_a_multiset() -> None:
    # Column by column either model column fits gold's first column; only one pairing
    # of whole rows matches.
    gold = [(1, 2), (2, 1)]
    model = [(2, 1), (1, 2)]
    assert _match(gold, model) == _PASS
    assert _match([(1, 1), (2, 2)], [(1, 2), (2, 1)]).passed is False


def test_row_counts_must_be_equal() -> None:
    verdict = _match([("a",), ("b",)], [("a",)])
    assert verdict == Verdict(False, "row count differs: gold 2, model 1", False)


def test_at_most_ten_model_columns() -> None:
    row = tuple(range(MAX_COLUMNS + 1))
    verdict = _match([(0,)], [row])
    assert verdict == Verdict(False, "model returned 11 columns, more than 10", False)
    assert _match([(0,)], [row[:MAX_COLUMNS]]) == _PASS


def test_fewer_model_columns_than_gold_fail() -> None:
    assert _match([(1, 2)], [(1,)]) == Verdict(False, "model returned 1 columns, gold has 2", False)


def test_an_empty_gold_result_is_a_weak_pass() -> None:
    assert _match([], []) == Verdict(True, None, True)
    assert _match([], [("a",)]) == Verdict(False, "row count differs: gold 0, model 1", True)


@pytest.mark.parametrize(
    ("gold", "model", "passed"),
    [
        pytest.param(None, None, True, id="null-equals-null"),
        pytest.param(None, 0, False, id="null-is-not-zero"),
        pytest.param(None, "", False, id="null-is-not-empty-text"),
        pytest.param(True, 1, False, id="bool-is-not-a-number"),
        pytest.param(False, 0, False, id="false-is-not-zero"),
        pytest.param(True, True, True, id="bool-equals-bool"),
        pytest.param(3, Decimal("3.000"), True, id="int-equals-numeric"),
        pytest.param(Decimal("0.1"), 0.1, True, id="numeric-equals-float"),
        pytest.param(3, "3", False, id="number-is-not-text"),
        pytest.param("Ransomware", "ransomware", False, id="text-is-exact"),
        pytest.param(dt.date(2026, 11, 2), dt.datetime(2026, 11, 2), True, id="date-is-midnight"),
        pytest.param(
            dt.date(2026, 11, 2), dt.datetime(2026, 11, 2, 0, 0, 1), False, id="date-is-not-later"
        ),
        pytest.param(
            dt.date(2026, 11, 2),
            dt.datetime(2026, 11, 2, tzinfo=dt.UTC),
            True,
            id="date-is-midnight-timestamptz",
        ),
        pytest.param({"a": [1, 2]}, {"a": [1.0, 2]}, True, id="json-by-value"),
        pytest.param({"a": 1, "b": 2}, {"b": 2, "a": 1}, True, id="json-key-order"),
        pytest.param({"a": [1, 2]}, {"a": [2, 1]}, False, id="json-array-order"),
        pytest.param({"a": "1"}, {"a": 1}, False, id="json-string-is-not-number"),
    ],
)
def test_values_are_normalized(gold: Any, model: Any, passed: bool) -> None:
    assert _match([(gold,)], [(model,)]).passed is passed
    assert _match([(gold,)], [(model,)], ordered=True).passed is passed


@pytest.mark.parametrize("ordered", [True, False])
def test_numbers_compare_within_the_tolerance(ordered: bool) -> None:
    tolerance = Decimal("0.05")
    gold = [("ipv4", Decimal("12.3")), ("domain", Decimal("50.0"))]
    within = [("ipv4", Decimal("12.34")), ("domain", Decimal("49.95"))]
    outside = [("ipv4", Decimal("12.36")), ("domain", Decimal("50.0"))]
    assert _match(gold, within, ordered=ordered, tolerance=tolerance) == _PASS
    assert _match(gold, outside, ordered=ordered, tolerance=tolerance).passed is False
    assert _match(gold, within, ordered=ordered).passed is False  # default tolerance 0


def test_a_tolerance_pairs_numbers_within_each_group_in_sorted_order() -> None:
    gold = [("a", Decimal("1.00")), ("a", Decimal("2.00")), ("b", Decimal("1.00"))]
    model = [("a", Decimal("2.01")), ("b", Decimal("0.99")), ("a", Decimal("0.99"))]
    assert _match(gold, model, tolerance=Decimal("0.01")) == _PASS
    # The text parts must still match exactly.
    model[1] = ("c", Decimal("1.00"))
    assert _match(gold, model, tolerance=Decimal("0.01")).passed is False


_NAN, _INF = Decimal("NaN"), Decimal("Infinity")


@pytest.mark.parametrize(
    ("gold", "model", "kw", "passed"),
    [
        pytest.param(_INF, _INF, {"ordered": True}, True, id="infinity-ordered"),
        pytest.param(-_INF, -_INF, {"tolerance": Decimal("0.1")}, True, id="minus-infinity"),
        # Postgres treats NaN = NaN as true, for numeric and float8 alike. Each side gets
        # its own NaN object: a dict lookup would match one object by identity.
        pytest.param(_NAN, Decimal("NaN"), {}, True, id="nan-as-a-set"),
        pytest.param(_NAN, float("nan"), {"ordered": True}, True, id="nan-float-ordered"),
        pytest.param(
            _NAN, Decimal("NaN"), {"tolerance": Decimal("0.1")}, True, id="nan-with-tolerance"
        ),
        pytest.param(_NAN, 1, {"tolerance": Decimal("0.1")}, False, id="nan-vs-finite"),
        pytest.param(_INF, -_INF, {"ordered": True}, False, id="infinity-vs-minus-infinity"),
        pytest.param(float("inf"), 1e308, {"tolerance": Decimal("0.1")}, False, id="inf-vs-big"),
    ],
)
def test_non_finite_numbers_compare_without_raising(
    gold: Any, model: Any, kw: dict[str, Any], passed: bool
) -> None:
    verdict = _match([(gold,)], [(model,)], **kw)
    assert verdict.passed is passed
    assert (verdict.reason is None) is passed
