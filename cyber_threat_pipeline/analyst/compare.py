"""Result match: does a model's result equal the gold result? SQL text is never compared.

``compare(gold, model, ordered=..., tolerance=...)`` takes the two results' rows
and returns a ``Verdict``:

- Column names are ignored. Each gold column must map to a distinct model
  column whose values are equal row for row; every one-to-one mapping is
  tried. Extra model columns are allowed, up to ``MAX_COLUMNS`` in all.
- The row counts must be equal. Rows are compared in order when the question
  is ``ordered``, otherwise as multisets.
- Values are normalized first: NULL equals only NULL, and a bool is never a
  number; integers, numerics and floats compare as Decimals, within
  ``tolerance``; text is exact; a date equals the same day's midnight
  timestamp (a timestamptz by its wall-clock time in the session's time zone,
  which both results share); JSON compares by value.
- With a tolerance, rows compared as a multiset are first grouped by their
  values that aren't numbers, and each group's rows are paired in sorted order
  of their numbers. That pairing is exact for one number per row, which is
  what every gold question with a tolerance returns.
- When the gold result is empty, a match still passes but is marked ``weak``.

A refusal, CANNOT_ANSWER, a Postgres error, a timeout or a model result cut at
the row cap never reaches ``compare``: the eval fails those itself.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

MAX_COLUMNS = 10

# A normalized value: (kind, value). Numbers are ("num", Decimal); every other
# kind compares exactly.
_Cell = tuple[str, Any]
_Row = tuple[_Cell, ...]


@dataclass(frozen=True)
class Verdict:
    """Whether the model's rows match the gold rows, why not, and whether the gold was empty."""

    passed: bool
    reason: str | None
    weak: bool


def compare(
    gold: Sequence[Sequence[Any]],
    model: Sequence[Sequence[Any]],
    *,
    ordered: bool,
    tolerance: Decimal = Decimal(0),
) -> Verdict:
    """Compare two results' rows under the result-match rule (module docstring)."""
    gold_rows = [tuple(_normalize(v) for v in row) for row in gold]
    model_rows = [tuple(_normalize(v) for v in row) for row in model]
    weak = not gold_rows
    if len(gold_rows) != len(model_rows):
        return Verdict(
            False, f"row count differs: gold {len(gold_rows)}, model {len(model_rows)}", weak
        )
    if not gold_rows:
        return Verdict(True, None, weak)
    gold_width, model_width = len(gold_rows[0]), len(model_rows[0])
    if model_width > MAX_COLUMNS:
        return Verdict(
            False, f"model returned {model_width} columns, more than {MAX_COLUMNS}", weak
        )
    if model_width < gold_width:
        return Verdict(False, f"model returned {model_width} columns, gold has {gold_width}", weak)
    for mapping in _mappings(gold_rows, model_rows, ordered=ordered, tolerance=tolerance):
        projected = [tuple(row[j] for j in mapping) for row in model_rows]
        if _rows_match(gold_rows, projected, ordered=ordered, tolerance=tolerance):
            return Verdict(True, None, weak)
    how = "in order" if ordered else "as a set"
    return Verdict(False, f"rows differ (compared {how})", weak)


def _normalize(value: Any) -> _Cell:
    if value is None:
        return ("null", None)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int | Decimal):
        return ("num", Decimal(value))
    if isinstance(value, float):
        return ("num", Decimal(repr(value)))
    if isinstance(value, str):
        return ("text", value)
    if isinstance(value, dt.datetime):
        # A timestamptz arrives in the session's time zone; compare its wall clock.
        return ("time", value.replace(tzinfo=None))
    if isinstance(value, dt.date):
        return ("time", dt.datetime.combine(value, dt.time()))
    if isinstance(value, dict | list):
        return ("json", _json_key(value))
    return (type(value).__name__, value)


def _json_key(value: Any) -> Any:
    """A hashable form of a JSON value that compares by value (1 equals 1.0)."""
    if isinstance(value, dict):
        return ("object", tuple(sorted((key, _json_key(v)) for key, v in value.items())))
    if isinstance(value, list):
        return ("array", tuple(_json_key(v) for v in value))
    if isinstance(value, bool) or value is None:
        return ("scalar", value)
    if isinstance(value, int | float | Decimal):
        return ("number", Decimal(repr(value)) if isinstance(value, float) else Decimal(value))
    return ("string", str(value))


def _cells_match(a: _Cell, b: _Cell, tolerance: Decimal) -> bool:
    if a[0] == "num" and b[0] == "num":
        return bool(abs(a[1] - b[1]) <= tolerance)
    return a == b


def _mappings(
    gold: list[_Row], model: list[_Row], *, ordered: bool, tolerance: Decimal
) -> Iterator[tuple[int, ...]]:
    """One-to-one maps of gold columns onto model columns whose own values could match."""
    gold_width, model_width = len(gold[0]), len(model[0])
    fits = [
        [
            _column_fits([r[i] for r in gold], [r[j] for r in model], ordered, tolerance)
            for j in range(model_width)
        ]
        for i in range(gold_width)
    ]
    yield from _assign(fits, 0, frozenset())


def _assign(fits: list[list[bool]], i: int, used: frozenset[int]) -> Iterator[tuple[int, ...]]:
    if i == len(fits):
        yield ()
        return
    for j, fit in enumerate(fits[i]):
        if fit and j not in used:
            for rest in _assign(fits, i + 1, used | {j}):
                yield (j, *rest)


def _column_fits(gold: list[_Cell], model: list[_Cell], ordered: bool, tolerance: Decimal) -> bool:
    if ordered:
        return all(_cells_match(a, b, tolerance) for a, b in zip(gold, model, strict=True))
    return _rows_match(
        [(c,) for c in gold], [(c,) for c in model], ordered=False, tolerance=tolerance
    )


def _rows_match(gold: list[_Row], model: list[_Row], *, ordered: bool, tolerance: Decimal) -> bool:
    if ordered:
        return all(
            all(_cells_match(a, b, tolerance) for a, b in zip(g, m, strict=True))
            for g, m in zip(gold, model, strict=True)
        )
    if tolerance == 0:
        return Counter(gold) == Counter(model)
    gold_groups, model_groups = _groups(gold), _groups(model)
    if gold_groups.keys() != model_groups.keys():
        return False
    for key, gold_numbers in gold_groups.items():
        model_numbers = model_groups[key]
        if len(gold_numbers) != len(model_numbers):
            return False
        for g, m in zip(sorted(gold_numbers), sorted(model_numbers), strict=True):
            if any(abs(a - b) > tolerance for a, b in zip(g, m, strict=True)):
                return False
    return True


def _groups(rows: list[_Row]) -> dict[_Row, list[tuple[Decimal, ...]]]:
    """Rows keyed by their values that aren't numbers, each holding its numbers."""
    groups: dict[_Row, list[tuple[Decimal, ...]]] = defaultdict(list)
    for row in rows:
        key = tuple(("num", None) if cell[0] == "num" else cell for cell in row)
        groups[key].append(tuple(cell[1] for cell in row if cell[0] == "num"))
    return groups
