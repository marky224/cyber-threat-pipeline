"""Build the analyst-brief prompt deterministically from the brief_input mart row.

Spec: _private/specs/04-analysis-llm.md §3.

The exact same prompt string is sent to every configured provider — that's the
whole point of the side-by-side artifact. Interpretation is the comparison axis;
prompt variation is not.
"""

from __future__ import annotations

import re
import textwrap
from typing import Any

import psycopg

from cyber_threat_pipeline.enrichment import CVE_ID_PATTERN

# Column order returned by ``fetch_brief_input``. Kept as a tuple so the row
# unpacking stays positional + matches the dbt mart contract (spec 03 §7.9).
_BRIEF_COLUMNS = (
    "generated_at",
    "corpus_header",
    "top_types",
    "top_countries",
    "top_tags",
    "top_industries",
    "emerging_pulses_7d",
    "emerging_indicators_7d",
    "cve_exploitation_7d",
)

_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def fetch_brief_input(conn: psycopg.Connection) -> dict[str, Any]:
    """Read the single ``marts.brief_input`` row as a dict.

    Raises ``RuntimeError`` if the row is missing — that means dbt hasn't
    built the mart yet, which is an upstream-orchestration bug.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            select generated_at, corpus_header, top_types, top_countries,
                   top_tags, top_industries, emerging_pulses_7d, emerging_indicators_7d,
                   cve_exploitation_7d
            from marts.brief_input
            """
        )
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("marts.brief_input is empty — did dbt build run?")
    return dict(zip(_BRIEF_COLUMNS, row, strict=True))


def _fmt_list(items: list[dict[str, Any]], label_key: str, count_key: str) -> str:
    if not items:
        return "(none)"
    return ", ".join(f"{i[label_key]}: {i[count_key]}" for i in items)


def _fmt_emerging_pulses(pulses: list[dict[str, Any]]) -> str:
    if not pulses:
        return "  (no new pulses in the last 7 days)"
    lines: list[str] = []
    for p in pulses:
        tags = ", ".join(p["tags"]) if p.get("tags") else "—"
        countries = ", ".join(p["targeted_countries"]) if p.get("targeted_countries") else "—"
        tlp = str(p.get("tlp", "")).upper() or "?"
        lines.append(
            f"  - [{tlp}] {p['name']} (id={p['id']}, indicators={p['indicator_count']}, "
            f"first_seen={p['first_seen_at']})\n"
            f"      tags: {tags}\n"
            f"      countries: {countries}"
        )
    return "\n".join(lines)


def _count(v: object) -> int | None:
    """A count from the CVE block, or None unless it is an int >= 0."""
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _threshold(v: object) -> float | None:
    """The EPSS threshold, or None unless it is a number in (0, 1]."""
    if isinstance(v, bool) or not isinstance(v, int | float) or not 0 < v <= 1:
        return None
    return float(v)


def _iso_date(v: object) -> str | None:
    return v if isinstance(v, str) and _ISO_DATE.fullmatch(v) else None


def _fmt_cve_exploitation(block: object) -> str | None:
    """The "Exploited CVEs this week" lines, or None when brief_input has no block.

    The block's values derive from the KEV and EPSS feeds, which are untrusted,
    so each is checked again here: only int counts >= 0, a threshold in (0, 1],
    ISO dates and ids matching ``CVE_ID_PATTERN`` render. A value that fails
    reads "not available" (a date is left out, a bad id dropped). The lines
    hold no braces or backticks: the writer puts the prompt in a code fence on
    an Evidence page.
    """
    if not isinstance(block, dict):
        return None
    lines = ["## Exploited CVEs this week"]
    cves = _count(block.get("cves"))
    if cves == 0:
        return "\n".join([*lines, "No CVE indicators first seen this week."])
    lines.append(
        "This week's CVEs (distinct CVE ids with an active indicator first seen in the last"
        f" 7 days): {'not available this run' if cves is None else cves}"
    )

    in_kev = _count(block.get("in_kev"))
    if in_kev is None:
        lines.append("CISA KEV: not available this run")
    else:
        released = _iso_date(block.get("kev_catalog_date"))
        source = f"KEV, released {released}" if released else "KEV"
        lines.append(f"In CISA's Known Exploited Vulnerabilities catalog ({source}): {in_kev}")
        listed = block.get("kev_cves")
        ids = [
            c
            for c in (listed if isinstance(listed, list) else [])
            if isinstance(c, str) and re.fullmatch(CVE_ID_PATTERN, c)
        ]
        if ids:
            # The row caps the list; a cut list says so, so its length isn't
            # read as the KEV count.
            cut = f" (top {len(ids)} by EPSS)" if in_kev > len(ids) else ""
            lines.append(f"KEV-listed, highest EPSS first{cut}: {', '.join(ids)}")

    epss_high = _count(block.get("epss_high"))
    threshold = _threshold(block.get("epss_threshold"))
    if epss_high is None or threshold is None:
        lines.append("FIRST EPSS: not available this run")
    else:
        scored = _iso_date(block.get("epss_score_date"))
        source = f"; FIRST scores of {scored}" if scored else ""
        lines.append(
            f"EPSS of {threshold:g} or more (a {100 * threshold:g}% or higher chance of"
            f" exploitation in the next 30 days{source}): {epss_high}"
        )
        not_in_kev = _count(block.get("epss_high_not_in_kev"))
        if in_kev is not None and not_in_kev is not None:
            lines.append(f"EPSS of {threshold:g} or more and not in KEV: {not_in_kev}")
    return "\n".join(lines)


def build_prompt(brief: dict[str, Any]) -> str:
    """Render the prompt string. Pure; deterministic for a given ``brief``."""
    header = brief["corpus_header"]
    top_types = brief["top_types"] or []
    top_countries = brief["top_countries"] or []
    top_tags = brief["top_tags"] or []
    top_industries = brief["top_industries"] or []
    emerging_pulses = brief["emerging_pulses_7d"] or []
    emerging_indicators = brief["emerging_indicators_7d"] or []

    # Indent the block's continuation lines to the template's 8 spaces so the
    # dedent below strips the template indent, not just the common minimum.
    emerging_block = _fmt_emerging_pulses(emerging_pulses).replace("\n", "\n" + " " * 8)
    # The CVE block and its rule render only when brief_input has the column:
    # without it (an older row) the prompt is byte-identical to before.
    cve_block = _fmt_cve_exploitation(brief.get("cve_exploitation_7d"))
    cve_section = kev_rule = ""
    if cve_block is not None:
        cve_section = "\n\n" + " " * 8 + cve_block.replace("\n", "\n" + " " * 8)
        kev_rule = (
            "\n        - Call a CVE known exploited only if the KEV list above names it, and give"
            "\n          the KEV count from its line, not the length of the list."
        )

    body = textwrap.dedent(f"""\
        You are a threat-intelligence analyst. Produce a concise brief on the current
        state of the AlienVault OTX corpus, focusing on **emerging threats from the
        last 7 days**.

        ## Corpus context (as of {brief["generated_at"]})
        - Total pulses:                 {header["total_pulses"]:,}
        - Total indicators:             {header["total_indicators"]:,}
        - Active indicators:            {header["active_indicators"]:,}  (active = not expired AND not dropped from its pulse)
        - Expired indicators:           {header["expired_indicators"]:,}
        - Top 5 indicator types:        {_fmt_list(top_types, "type", "count")}
        - Top 5 targeted countries:     {_fmt_list(top_countries, "country", "pulse_count")}
        - Top 5 tags:                   {_fmt_list(top_tags, "tag", "pulse_count")}
        - Top 5 targeted industries:    {_fmt_list(top_industries, "industry", "pulse_count")}

        ## Emerging in the last 7 days
        Indicator types newly seen:     {_fmt_list(emerging_indicators, "type", "count")}
        New pulses (first_seen_at within 7d):
        {emerging_block}{cve_section}

        ## What to produce
        Write a brief of 250-400 words, headings included; never more than 400.
        Use exactly these four markdown headings, in this order, each on its own line,
        and no other "##" headings (a "# " title line above them is fine):
        - "## Headline": one sentence on the week's most notable signal.
        - "## Emerging threats": 3-5 bullets on the new pulses — group by theme:
          ransomware, phishing, APT, supply chain, etc. — and cite pulse names. End
          every bullet with the id of each pulse it draws on, written as (id=<pulse id>).
        - "## Contrast with the corpus": 1-3 bullets on how this week's pulses differ
          from the corpus top-5 lists above, e.g. a country, tag or industry that is
          absent from them.
        - "## Analyst caveats": 1-2 bullets on what this data can NOT tell us:
          attribution confidence, victim impact, dwell time, sampling bias from OTX
          subscriptions.

        Use markdown. Do not invent indicators, pulse names, or numbers — work strictly
        from what's above:
        - The data has no previous-week figures, so do not call anything a spike, surge,
          rise, drop or shift, and do not compare this week with earlier ones.
        - Copy every number from the data above, or count items you name in the same
          sentence. Do not add up counts across pulses, and do not group countries
          into regions unless you list them.
        - When you quote a pulse name, copy it exactly.{kev_rule}
        - If the data can't support a point, say "not in the data" instead of estimating.
        """)
    return body.strip()
