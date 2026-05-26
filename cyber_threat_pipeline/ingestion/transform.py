"""OTX pulse dicts → row tuples ready for the load layer. Pure functions, no I/O.

Spec: _private/specs/02-ingestion.md §5.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

PULSE_COLUMNS: tuple[str, ...] = (
    "id",
    "name",
    "description",
    "author_name",
    "public",
    "revision",
    "adversary",
    "industries",
    "tlp",
    "tags",
    "created",
    "modified",
    "references",
    "targeted_countries",
)

INDICATOR_COLUMNS: tuple[str, ...] = (
    "id",
    "pulse_id",
    "indicator",
    "type",
    "title",
    "description",
    "access_reason",
    "created",
    "is_active",
    "access_type",
    "content",
    "role",
    "expiration",
    "access_groups",
    "observations",
)


def transform(
    pulses: Sequence[dict[str, Any]],
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    """Flatten OTX response into row tuples ready for the load layer.

    JSONB-bound fields are serialized via ``json.dumps``. Duplicate IDs are
    de-duplicated last-wins.
    """
    pulse_rows: dict[str, tuple[Any, ...]] = {}
    indicator_rows: dict[int, tuple[Any, ...]] = {}

    for p in pulses:
        pulse_rows[p["id"]] = (
            p["id"],
            p["name"],
            p.get("description") or "",
            p["author_name"],
            bool(p["public"]),
            p["revision"],
            p.get("adversary") or "",
            json.dumps(p["industries"]),
            (p.get("tlp") or "white").lower(),
            json.dumps(p["tags"]),
            p["created"],
            p["modified"],
            json.dumps(p["references"]),
            json.dumps(p["targeted_countries"]),
        )
        for i in p["indicators"]:
            indicator_rows[int(i["id"])] = (
                int(i["id"]),
                p["id"],
                i["indicator"],
                i["type"],
                i.get("title") or "",
                i.get("description") or "",
                i.get("access_reason") or "",
                i["created"],
                bool(i["is_active"]),
                i.get("access_type") or "public",
                i.get("content") or "",
                i.get("role") or "",
                i["expiration"],
                json.dumps(i.get("access_groups") or []),
                i.get("observations") or 0,
            )

    return list(pulse_rows.values()), list(indicator_rows.values())


def max_modified(pulses: Sequence[dict[str, Any]]) -> str | None:
    """Return the maximum ``modified`` timestamp across the batch (ISO string), or None if empty."""
    if not pulses:
        return None
    return str(max(p["modified"] for p in pulses))
