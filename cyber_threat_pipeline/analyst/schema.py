"""The marts the analyst may read, and the schema card its SQL prompt carries.

``MART_NAMES`` is the guard's table allow-list: the 11 models in
``transform/models/marts/``. dbt also builds the staging and intermediate models
into the ``marts`` schema, and the staging views read ``raw`` with their owner's
rights, so none of them is on the list.

``MARTS`` is the schema card: each mart's grain and each column's Postgres type
(as ``information_schema.columns`` names it) and meaning, written from the
models, not generated from dbt docs, since the app env doesn't read
``transform/``. It leaves out ``mart_pulse_trends_monthly``'s
``pulses_first_seen_this_month``, which always equals ``pulse_count``. It holds
names, types, meanings and the values the code defines, never a data value.
"""

from __future__ import annotations

from dataclasses import dataclass

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


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    meaning: str


@dataclass(frozen=True)
class Mart:
    name: str
    grain: str
    columns: tuple[Column, ...]


_V, _T, _B, _N = "character varying", "text", "bigint", "numeric"
_D, _TS, _TSZ = "date", "timestamp without time zone", "timestamp with time zone"
_BOOL, _J = "boolean", "jsonb"


def _cols(*columns: tuple[str, str, str]) -> tuple[Column, ...]:
    return tuple(Column(*column) for column in columns)


_QUALITY = (
    ("run_id", _B, "the pipeline run the row describes"),
    ("started_at", _TSZ, "when that run started"),
    ("watermark_after", _TS, "the OTX modified-since watermark after that run"),
)
_INDICATOR_STATS = (
    ("total_indicators", _B, "indicators in the corpus"),
    ("active_indicators", _B, "active indicators"),
    ("expired_indicators", _B, "indicators past their expiration"),
    ("dropped_indicators", _B, "indicators dropped from their pulse's latest sync"),
    ("orphan_indicators", _B, "indicators with no pulse"),
    ("null_indicator_value", _B, "indicators with no value"),
    ("pct_active", _N, "active / total indicators, a percentage 0-100, two decimals"),
    ("max_pulse_modified", _TS, "the latest pulse modified time in the corpus"),
)

MARTS: tuple[Mart, ...] = (
    Mart(
        "mart_top_pulses",
        "one row per pulse",
        _cols(
            ("id", _V, "OTX pulse id"),
            ("name", _T, "pulse name"),
            ("author_name", _V, "pulse author"),
            ("created", _TS, "when OTX created the pulse"),
            ("modified", _TS, "when OTX last modified the pulse"),
            ("indicator_count", _B, "indicators in the pulse (0 when it has none)"),
            ("type_count", _B, "distinct indicator types in the pulse"),
            ("active_indicator_count", _B, "active indicators in the pulse"),
        ),
    ),
    Mart(
        "mart_indicator_types",
        "one row per indicator type",
        _cols(
            ("type", _V, "indicator type, as OTX names it (for example IPv4, domain, CVE)"),
            ("indicator_count", _B, "indicators of this type"),
            ("active_count", _B, "active indicators of this type"),
            ("expired_count", _B, "indicators of this type past their expiration"),
            ("dropped_count", _B, "indicators of this type dropped from their pulse's sync"),
        ),
    ),
    Mart(
        "mart_indicator_freshness",
        "one row per (type, freshness_bucket) that has indicators",
        _cols(
            ("type", _V, "indicator type"),
            ("freshness_bucket", _T, "the indicator's expiration bucket (see notes)"),
            ("indicator_count", _B, "indicators of this type in this bucket"),
        ),
    ),
    Mart(
        "mart_targeted_countries",
        "one row per targeted country",
        _cols(
            ("country", _T, "country name as OTX sent it"),
            ("pulse_count", _B, "pulses targeting the country"),
            ("indicator_count", _B, "indicators in those pulses"),
            ("active_indicator_count", _B, "active indicators in those pulses"),
        ),
    ),
    Mart(
        "mart_threat_tags",
        "one row per tag, exactly as OTX sent it",
        _cols(
            ("tag", _T, "the tag"),
            ("pulse_count", _B, "pulses with the tag"),
            ("indicator_count", _B, "indicators in those pulses"),
        ),
    ),
    Mart(
        "mart_top_industries",
        "one row per targeted industry",
        _cols(
            ("industry", _T, "industry name as OTX sent it"),
            ("pulse_count", _B, "pulses targeting the industry"),
        ),
    ),
    Mart(
        "mart_pulse_trends_monthly",
        "one row per month that had pulses created (no row for an empty month)",
        _cols(
            ("month", _D, "first day of the month of OTX's created date"),
            ("pulse_count", _B, "pulses created that month"),
            ("indicator_count", _B, "indicators in those pulses"),
        ),
    ),
    Mart(
        "mart_data_quality",
        "one row: the latest successful pipeline run",
        _cols(
            *_QUALITY[:3],
            ("tlp_distribution", _J, 'pulses per TLP value, {"<tlp>": pulse_count}'),
            *_INDICATOR_STATS,
            ("kev_catalog_version", _T, "the CISA KEV catalog version last fetched"),
            ("kev_fetched_at", _TSZ, "when KEV was last fetched (NULL before the first fetch)"),
            ("epss_score_date", _D, "the FIRST EPSS score date last fetched"),
            ("epss_fetched_at", _TSZ, "when EPSS was last fetched (NULL before the first fetch)"),
            ("cve_ids", _B, "distinct CVE ids in the corpus"),
            ("cve_ids_in_kev", _B, "of those, in the latest KEV snapshot"),
            ("cve_ids_with_epss", _B, "of those, with an EPSS score"),
            ("cve_indicators_malformed", _B, "CVE indicators that aren't a valid CVE id"),
        ),
    ),
    Mart(
        "mart_data_quality_history",
        "one row per successful pipeline run since the history began",
        _cols(
            *_QUALITY,
            *_INDICATOR_STATS,
            ("recorded_at", _TSZ, "when the build recorded the row"),
        ),
    ),
    Mart(
        "mart_cve_enrichment",
        "one row per CVE id in the corpus",
        _cols(
            ("cve_id", _T, "CVE id, upper case (CVE-YYYY-NNNN)"),
            ("indicator_count", _B, "CVE indicators with this id"),
            ("pulse_count", _B, "pulses holding this id"),
            ("active_indicator_count", _B, "active indicators with this id"),
            ("first_seen_at", _TSZ, "when the pipeline first saw the id"),
            ("seen_7d", _BOOL, "an active indicator with this id was first seen in the 7 days"),
            ("in_kev", _BOOL, "in the latest CISA KEV snapshot; never NULL"),
            ("kev_date_added", _D, "when KEV added it (NULL when not in KEV)"),
            ("kev_vendor_project", _T, "KEV vendor or project"),
            ("kev_product", _T, "KEV product"),
            ("kev_vulnerability_name", _T, "KEV vulnerability name"),
            ("kev_known_ransomware", _BOOL, "KEV marks it as used in ransomware campaigns"),
            ("epss", _N, "FIRST EPSS score, 0-1 (NULL when unscored, which is not 0)"),
            ("epss_percentile", _N, "EPSS percentile, 0-1"),
            ("epss_score_date", _D, "the EPSS score's date"),
        ),
    ),
    Mart(
        "brief_input",
        "one row: the weekly brief's input",
        _cols(
            ("generated_at", _TSZ, "when the build made the row"),
            ("corpus_header", _J, "corpus totals (see notes)"),
            ("top_types", _J, "the 5 largest indicator types (see notes)"),
            ("top_countries", _J, "the 5 countries with the most pulses"),
            ("top_tags", _J, "the 5 tags with the most pulses"),
            ("top_industries", _J, "the 5 industries with the most pulses"),
            ("emerging_pulses_7d", _J, "every pulse first seen in the 7 days, newest first"),
            ("emerging_indicators_7d", _J, "active indicators first seen in the 7 days, by type"),
            ("cve_exploitation_7d", _J, "this week's CVEs against KEV and EPSS (see notes)"),
        ),
    ),
)

_NOTES = """\
Notes:
- Every mart is rebuilt by the weekly dbt build; answers are as of that build, and "the 7
  days" means the 7 days before it.
- An active indicator is not expired (no expiration, or one in the future) and not dropped
  (still in its pulse's latest OTX sync).
- freshness_bucket is by expiration only: 'no_expiration', 'expired', 'expiring_le_30d'
  (not expired, expiring within 30 days), 'active_gt_30d'.
- TLP values: 'white', 'green', 'amber', 'red'.
- Names, tags, countries and industries are text exactly as OTX sent them.
- brief_input JSON: top_types and emerging_indicators_7d are [{"type", "count"}];
  top_countries [{"country", "pulse_count"}]; top_tags [{"tag", "pulse_count"}];
  top_industries [{"industry", "pulse_count"}]; each list in count order and '[]' when
  empty. emerging_pulses_7d is [{"id", "name", "description", "tlp", "tags",
  "targeted_countries", "first_seen_at", "indicator_count"}]. corpus_header is
  {"total_pulses", "total_indicators", "active_indicators", "expired_indicators"}.
  cve_exploitation_7d is {"cves", "in_kev", "epss_high", "epss_high_not_in_kev",
  "epss_threshold", "kev_cves" (ids), "kev_cves_cap", "kev_catalog_date",
  "epss_score_date"}; a count is NULL until its feed's first fetch.
"""


def card() -> str:
    """The schema card: every mart with its grain and columns, then the notes."""
    lines: list[str] = []
    for mart in MARTS:
        lines.append(f"marts.{mart.name}: {mart.grain}.")
        lines.extend(f"  {c.name} ({c.type}): {c.meaning}" for c in mart.columns)
    return "\n".join(lines) + "\n\n" + _NOTES
