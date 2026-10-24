"""Build the analyst-brief prompt deterministically from the brief_input mart row.

Spec: _private/specs/04-analysis-llm.md §3.

The exact same prompt string is sent to every configured provider — that's the
whole point of the side-by-side artifact. Interpretation is the comparison axis;
prompt variation is not.
"""

from __future__ import annotations

import textwrap
from typing import Any

import psycopg

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
)


def fetch_brief_input(conn: psycopg.Connection) -> dict[str, Any]:
    """Read the single ``marts.brief_input`` row as a dict.

    Raises ``RuntimeError`` if the row is missing — that means dbt hasn't
    built the mart yet, which is an upstream-orchestration bug.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            select generated_at, corpus_header, top_types, top_countries,
                   top_tags, top_industries, emerging_pulses_7d, emerging_indicators_7d
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
        {emerging_block}

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
        - When you quote a pulse name, copy it exactly.
        - If the data can't support a point, say "not in the data" instead of estimating.
        """)
    return body.strip()
