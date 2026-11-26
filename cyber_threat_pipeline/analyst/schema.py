"""The marts the analyst may read.

``MART_NAMES`` is the guard's table allow-list: the 11 models in
``transform/models/marts/``. dbt also builds the staging and intermediate models
into the ``marts`` schema, and the staging views read ``raw`` with their owner's
rights, so none of them is on the list.
"""

from __future__ import annotations

MART_SCHEMA = "marts"

MART_NAMES: frozenset[str] = frozenset(
    {
        "brief_input",
        "mart_cve_enrichment",
        "mart_data_quality",
        "mart_data_quality_history",
        "mart_indicator_freshness",
        "mart_indicator_types",
        "mart_pulse_trends_monthly",
        "mart_targeted_countries",
        "mart_threat_tags",
        "mart_top_industries",
        "mart_top_pulses",
    }
)
