"""Pure-function tests for transform() and max_modified()."""

from __future__ import annotations

import json
from typing import Any

from cyber_threat_pipeline.ingestion.transform import (
    INDICATOR_COLUMNS,
    PULSE_COLUMNS,
    max_modified,
    transform,
)


def _pulse(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "p1",
        "name": "Pulse One",
        "description": "desc",
        "author_name": "alice",
        "public": 1,
        "revision": 3,
        "adversary": "APT-X",
        "industries": ["finance"],
        "tlp": "WHITE",
        "tags": ["malware"],
        "created": "2026-05-01T00:00:00",
        "modified": "2026-05-10T00:00:00",
        "references": ["https://example.com/a"],
        "targeted_countries": ["US"],
        "indicators": [],
    }
    base.update(overrides)
    return base


def _ind(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": 1001,
        "indicator": "1.2.3.4",
        "type": "IPv4",
        "title": "t",
        "description": "d",
        "access_reason": "",
        "created": "2026-05-01T00:00:00",
        "is_active": 1,
        "access_type": "public",
        "content": "",
        "role": "",
        "expiration": None,
        "access_groups": [],
        "observations": 2,
    }
    base.update(overrides)
    return base


def test_pulse_columns_count_matches_row_arity() -> None:
    pulses_rows, _ = transform([_pulse()])
    assert len(pulses_rows[0]) == len(PULSE_COLUMNS)


def test_indicator_columns_count_matches_row_arity() -> None:
    _, ind_rows = transform([_pulse(indicators=[_ind()])])
    assert len(ind_rows[0]) == len(INDICATOR_COLUMNS)


def test_transform_basic_shape() -> None:
    pulses_rows, ind_rows = transform([_pulse(indicators=[_ind()])])
    assert len(pulses_rows) == 1
    assert len(ind_rows) == 1
    pulse = pulses_rows[0]
    assert pulse[0] == "p1"
    assert pulse[4] is True  # public coerced to bool
    assert pulse[8] == "white"  # tlp lowercased
    assert json.loads(pulse[7]) == ["finance"]
    assert json.loads(pulse[12]) == ["https://example.com/a"]
    assert ind_rows[0][1] == "p1"  # FK pulse_id
    assert ind_rows[0][8] is True  # is_active coerced


def test_transform_or_defaults_handle_missing_and_none() -> None:
    """The ``or ""`` / ``or 0`` defaults must coerce None as well as missing."""
    p = _pulse(description=None, adversary=None)
    p["indicators"] = [
        _ind(title=None, description=None, content=None, role=None, observations=None),
    ]
    pulses_rows, ind_rows = transform([p])
    assert pulses_rows[0][2] == ""
    assert pulses_rows[0][6] == ""
    ind = ind_rows[0]
    assert ind[4] == ""  # title
    assert ind[5] == ""  # description
    assert ind[10] == ""  # content
    assert ind[11] == ""  # role
    assert ind[14] == 0  # observations


def test_transform_tlp_missing_defaults_white() -> None:
    p = _pulse()
    p.pop("tlp", None)
    pulses_rows, _ = transform([p])
    assert pulses_rows[0][8] == "white"


def test_transform_last_wins_dedup() -> None:
    a = _pulse(id="dup", name="first", indicators=[_ind(id=42, indicator="A")])
    b = _pulse(id="dup", name="second", indicators=[_ind(id=42, indicator="B")])
    pulses_rows, ind_rows = transform([a, b])
    assert len(pulses_rows) == 1
    assert pulses_rows[0][1] == "second"
    assert len(ind_rows) == 1
    assert ind_rows[0][2] == "B"


def test_transform_jsonb_fields_are_json_strings() -> None:
    pulses_rows, ind_rows = transform([_pulse(indicators=[_ind(access_groups=["g1"])])])
    p = pulses_rows[0]
    assert isinstance(p[7], str) and json.loads(p[7]) == ["finance"]
    assert isinstance(p[9], str) and json.loads(p[9]) == ["malware"]
    assert isinstance(p[12], str) and json.loads(p[12]) == ["https://example.com/a"]
    assert isinstance(p[13], str) and json.loads(p[13]) == ["US"]
    assert isinstance(ind_rows[0][13], str) and json.loads(ind_rows[0][13]) == ["g1"]


def test_max_modified_returns_latest() -> None:
    pulses = [
        _pulse(id="a", modified="2026-05-01T00:00:00"),
        _pulse(id="b", modified="2026-05-15T00:00:00"),
        _pulse(id="c", modified="2026-05-08T00:00:00"),
    ]
    assert max_modified(pulses) == "2026-05-15T00:00:00"


def test_max_modified_empty_returns_none() -> None:
    assert max_modified([]) is None
