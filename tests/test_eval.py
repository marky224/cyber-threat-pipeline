"""Tests for cyber_threat_pipeline.analysis.eval.

The golden fixture is the public Analyst Brief of 2026-10-14
(tests/fixtures/brief_2026_10_14/): brief.md is what was published,
brief_corrected.md fixes every labelled error, brief_alt_correct.md is a
second correct brief written in different phrasing. Unit cases below use a
small synthetic input.
"""

from __future__ import annotations

import json
import re
import signal
import time
from pathlib import Path
from types import FrameType
from typing import Any

import pytest

from cyber_threat_pipeline.analysis.eval import (
    FACT_CHECKS,
    REQUIRED_SECTIONS,
    EvalResult,
    Finding,
    evaluate,
)

FIXTURE = Path(__file__).parent / "fixtures" / "brief_2026_10_14"
BRIEF_INPUT: dict[str, Any] = json.loads((FIXTURE / "brief_input.json").read_text())
LABELS: list[dict[str, Any]] = json.loads((FIXTURE / "labels.json").read_text())["labels"]
BRIEF = (FIXTURE / "brief.md").read_text()
CORRECTED = (FIXTURE / "brief_corrected.md").read_text()
ALT_CORRECT = (FIXTURE / "brief_alt_correct.md").read_text()


def _pairs(result: EvalResult) -> list[tuple[str, str]]:
    return [(f.check, f.text) for f in result.findings]


def _label(label_id: str) -> dict[str, Any]:
    return next(lbl for lbl in LABELS if lbl["id"] == label_id)


# --------------------------------------------------------------------------
# Golden fixture
# --------------------------------------------------------------------------


def test_published_brief_raises_exactly_the_expected_findings() -> None:
    result = evaluate(BRIEF, BRIEF_INPUT)

    def sentence(label_id: str) -> str:
        return str(_label(label_id)["original"])

    # The first five bullets are under "## Emerging Threats"; the next three
    # stay in it, since "## Corpus-Level Shifts" names no required section.
    emerging_bullets = [line[2:] for line in BRIEF.splitlines() if line.startswith("- ")][:8]
    assert _pairs(result) == [
        ("section_missing", "Contrast with the corpus"),
        ("length_out_of_band", "502 words"),
        *[("pulse_citation_missing", b) for b in emerging_bullets],
        ("number_unsupported", sentence("1")),
        ("number_unsupported", sentence("3a")),
        ("number_unsupported", sentence("2")),
        ("number_unsupported", sentence("3b+4a")),
        ("comparison_without_baseline", sentence("headline")),
        ("comparison_without_baseline", sentence("4b")),
        ("comparison_without_baseline", sentence("3b+4a")),
    ]
    assert (result.facts_verified, result.facts_total) == (12, 19)


@pytest.mark.parametrize("label_id", ["1", "2", "3a", "3b+4a", "4b", "headline", "5"])
def test_every_labelled_error_is_flagged_in_the_published_brief(label_id: str) -> None:
    label = _label(label_id)
    found = _pairs(evaluate(BRIEF, BRIEF_INPUT))
    for check in label["checks"]:
        if label["original"] is None:
            assert any(c == check for c, _ in found)
        else:
            assert (check, label["original"]) in found


def test_corrected_brief_passes_every_check() -> None:
    result = evaluate(CORRECTED, BRIEF_INPUT)
    assert result.findings == ()
    assert result.words <= 400
    assert result.facts_verified == result.facts_total > 0


def test_second_correct_brief_in_other_phrasing_passes_every_check() -> None:
    # Other units (MD5/SHA256 hashes, domains, IPv4 addresses, zero-days), a
    # range, a percentage, "about N"/"roughly N", and spelled-out numbers.
    result = evaluate(ALT_CORRECT, BRIEF_INPUT)
    assert result.findings == ()
    assert result.facts_verified == result.facts_total > 0


@pytest.mark.parametrize("label_id", ["1", "2", "3a", "3b+4a", "4b", "headline"])
def test_putting_one_original_sentence_back_adds_only_its_findings(label_id: str) -> None:
    label = _label(label_id)
    assert CORRECTED.count(label["corrected"]) == 1
    mutant = CORRECTED.replace(label["corrected"], label["original"])

    result = evaluate(mutant, BRIEF_INPUT)

    assert sorted(f.check for f in result.findings) == sorted(label["checks"])
    assert all(f.text == label["original"] for f in result.findings)


def test_making_the_corrected_brief_too_long_adds_only_the_length_finding() -> None:
    caveats = BRIEF[BRIEF.index("## Analyst Caveats") :].split("\n", 1)[1]
    mutant = CORRECTED.rstrip() + "\n" + caveats

    result = evaluate(mutant, BRIEF_INPUT)

    assert [f.check for f in result.findings] == ["length_out_of_band"]


# --------------------------------------------------------------------------
# Unit cases on a synthetic input
# --------------------------------------------------------------------------

ID_A = "a" * 24
ID_B = "b" * 24
ID_C = "c" * 24

SYNTH: dict[str, Any] = {
    "generated_at": "2026-10-14 00:00:00+00:00",
    "corpus_header": {
        "total_pulses": 751,
        "total_indicators": 25215,
        "active_indicators": 24111,
        "expired_indicators": 1085,
    },
    "top_types": [{"type": "domain", "count": 8501}],
    "top_countries": [{"country": "India", "pulse_count": 38}],
    "top_tags": [{"tag": "phishing", "pulse_count": 56}],
    "top_industries": [{"industry": "Finance", "pulse_count": 142}],
    "emerging_indicators_7d": [{"type": "CVE", "count": 49}, {"type": "domain", "count": 228}],
    "emerging_pulses_7d": [
        {
            "id": ID_A,
            "name": "Router botnet abuses CVE-2024-3721",
            "tlp": "white",
            "tags": ["routerbot", "cve-2024-3721", "cve-2023-1389", "phishing"],
            "targeted_countries": ["France", "Germany", "Mexico"],
            "first_seen_at": "2026-10-13T00:00:00+00:00",
            "indicator_count": 20,
        },
        {
            "id": ID_B,
            "name": "US disrupts tools as 7 govts warn",
            "tlp": "white",
            "tags": ["flax typhoon", "phishing"],
            "targeted_countries": ["Japan", "Poland", "Taiwan", "Ukraine"],
            "first_seen_at": "2026-10-13T00:00:00+00:00",
            "indicator_count": 6,
        },
        {
            "id": ID_C,
            "name": "Ukraine-focused stealer",
            "tlp": "white",
            "tags": ["lunexstealer", "ukraine targeting"],
            "targeted_countries": ["Ukraine"],
            "first_seen_at": "2026-10-13T00:00:00+00:00",
            "indicator_count": 2,
        },
    ],
}


def _brief(*bullets: str, contrast: str = "- Nothing to contrast.") -> str:
    body = "\n".join(f"- {b}" for b in bullets)
    return (
        "## Headline\n\nA week of routers.\n\n## Emerging threats\n\n"
        f"{body}\n\n## Contrast with the corpus\n\n{contrast}\n\n"
        "## Analyst caveats\n\n- Victim impact is not in the data.\n"
    )


def _findings(md: str, check: str) -> list[Finding]:
    return [f for f in evaluate(md, SYNTH).findings if f.check == check]


@pytest.mark.parametrize(
    ("claim", "ok"),
    [
        ("probes 2 CVEs", True),
        ("probes 2+ CVEs", True),  # 2 <= 2 < 3
        ("probes 3 CVEs", False),
        ("probes two vulnerabilities", True),
        ("has 20 indicators", True),
        ("has 20+ indicators", True),  # "20+" means 20-29
        ("has 10+ indicators", False),  # "10+" means 10-19; no such count
        ("has 21 indicators", False),
    ],
)
def test_cve_and_indicator_counts_follow_the_cited_pulse(claim: str, ok: bool) -> None:
    md = _brief(f"Routerbot {claim}. (id={ID_A})")
    found = _findings(md, "number_unsupported")
    assert (not found) is ok, found


def test_plus_bound_is_the_leading_digit_precision() -> None:
    # 16+ accepts 16-25; 38+ rejects 31 and 49 (the "N+" rule in eval.py's docstring).
    synth = json.loads(json.dumps(SYNTH))
    synth["emerging_pulses_7d"][0]["indicator_count"] = 25
    ok = evaluate(_brief(f"Routerbot has 16+ indicators. (id={ID_A})"), synth)
    assert not [f for f in ok.findings if f.check == "number_unsupported"]
    synth["emerging_pulses_7d"][0]["indicator_count"] = 26
    synth["emerging_pulses_7d"][1]["indicator_count"] = 26
    synth["emerging_pulses_7d"][2]["indicator_count"] = 26
    bad = evaluate(_brief(f"Routerbot has 16+ indicators. (id={ID_A})"), synth)
    assert [f.check for f in bad.findings if f.check == "number_unsupported"] == [
        "number_unsupported"
    ]


def test_cve_counts_are_never_summed_across_pulses() -> None:
    # Pulse A has 2 CVEs, pulse B none: "2 CVEs" is fine, "3 CVEs" is not.
    md = _brief(f"Routerbot and Flax Typhoon touch 3 CVEs. (id={ID_A}, id={ID_B})")
    assert _findings(md, "number_unsupported")


def test_eu_nations_count_only_eu_members() -> None:
    assert not _findings(
        _brief(f"Routerbot hits two EU nations. (id={ID_A})"), "number_unsupported"
    )
    assert _findings(_brief(f"Routerbot hits three EU nations. (id={ID_A})"), "number_unsupported")
    assert not _findings(
        _brief(f"Routerbot hits three countries. (id={ID_A})"), "number_unsupported"
    )


def test_government_counts_need_an_explicit_count_in_the_pulse() -> None:
    ok = _brief(f"Seven governments issued warnings. (id={ID_B})")
    bad = _brief(f"Four allied governments issued warnings. (id={ID_B})")
    assert not _findings(ok, "number_unsupported")
    assert _findings(bad, "number_unsupported")


def test_unique_tags_scope_numbers_to_their_pulse_without_an_id() -> None:
    # "routerbot" is a tag only pulse A has, so it cites A for number checks.
    md = _brief(f"Routerbot probes 2 CVEs. (id={ID_C})")
    assert not _findings(md, "number_unsupported")


def test_pulse_counts_come_from_how_many_pulses_mention_a_word() -> None:
    ok = _brief(f"Pulses. (id={ID_A})", contrast="- Ukraine appears in two pulses.")
    bad = _brief(f"Pulses. (id={ID_A})", contrast="- Ukraine appears in four pulses.")
    assert not _findings(ok, "number_unsupported")
    assert _findings(bad, "number_unsupported")


@pytest.mark.parametrize(
    ("contrast", "ok"),
    [
        ("- Active indicators are about 96% of the corpus.", True),
        ("- Active indicators are 95.6% of the corpus.", True),
        ("- Active indicators are 90% of the corpus.", False),
        ("- The corpus holds about 25,000 indicators.", True),
        ("- The corpus holds roughly 24,000 active ones.", True),
        ("- The corpus holds about 26,000 indicators.", False),
        ("- Pulses carry 2\u20136 indicators.", True),
        ("- Pulses carry 2-20 indicators.", True),
        ("- Pulses carry 2 to 9 indicators.", False),
        ("- 49 CVE indicators were new in the last 7 days.", True),
        ("- New domains: 228 domains in 7 days.", True),
        ("- The window covers 14 days.", False),
        ("- India leads with 38 pulses.", True),
        ("- Phishing is tagged on 56 pulses.", True),
    ],
)
def test_corpus_level_numbers(contrast: str, ok: bool) -> None:
    found = _findings(_brief(f"Routerbot. (id={ID_A})", contrast=contrast), "number_unsupported")
    assert (not found) is ok, found


@pytest.mark.parametrize(
    "text",
    [
        "Seen on 2026-10-14 at 11:10.",
        "CVE-2024-3721 is exploited.",
        f"Pulse {ID_A} is cited.",
        "UAC-0099 uses x64 loaders and GitHub C2.",
        "It is a corpus top-5 tag and a top 5 country.",
        "One sample and one loader.",
    ],
)
def test_digits_inside_ids_dates_and_names_are_not_numbers(text: str) -> None:
    result = evaluate(_brief(f"Routerbot. (id={ID_A})", contrast=f"- {text}"), SYNTH)
    assert not [f for f in result.findings if f.check == "number_unsupported"]


@pytest.mark.parametrize(
    ("sentence", "flagged"),
    [
        ("CVE indicators spiked this week.", True),
        ("Phishing rose week-over-week.", True),
        ("Activity is rising.", True),
        ("It has no prior-week precedent.", True),
        ("An unusually broad week.", True),
        ("Emerging pulses were newly seen this week.", False),
        ('The pulse "the rise of routerbot" is new.', False),
    ],
)
def test_trend_words_are_flagged_because_there_is_no_baseline(sentence: str, flagged: bool) -> None:
    md = _brief(f"Routerbot. (id={ID_A})", contrast=f"- {sentence}")
    assert bool(_findings(md, "comparison_without_baseline")) is flagged


def test_trend_words_in_headings_and_quoted_names_are_ignored() -> None:
    md = _brief(f'"the rise of" nothing. (id={ID_A})').replace(
        "## Contrast with the corpus", "## Contrast with the corpus (no shifts)"
    )
    assert not _findings(md, "comparison_without_baseline")


def test_unknown_pulse_id_cve_and_quoted_name_are_flagged() -> None:
    md = _brief(
        f'"Operation Nonexistent" exploits CVE-2099-0001. (id={"f" * 24})',
    )
    checks = {f.check for f in evaluate(md, SYNTH).findings}
    assert {"pulse_name_unknown", "cve_unknown", "pulse_id_unknown"} <= checks


def test_known_quoted_name_and_cve_pass() -> None:
    md = _brief(f'"Router botnet" exploits CVE-2024-3721. (id={ID_A})')
    checks = {f.check for f in evaluate(md, SYNTH).findings}
    assert not checks & {"pulse_name_unknown", "cve_unknown", "pulse_id_unknown"}


def test_emerging_bullet_without_an_id_is_flagged() -> None:
    md = _brief("Routerbot probes 2 CVEs.", f"Flax Typhoon. (id={ID_B})")
    found = _findings(md, "pulse_citation_missing")
    assert [f.text for f in found] == ["Routerbot probes 2 CVEs."]


def test_theme_labels_in_bold_stay_inside_emerging_threats() -> None:
    md = _brief(f"Routerbot. (id={ID_A})").replace(
        "## Emerging threats\n\n", "## Emerging threats\n\n**Routers**\n\n- No id here.\n"
    )
    assert [f.text for f in _findings(md, "pulse_citation_missing")] == ["No id here."]


@pytest.mark.parametrize("missing", REQUIRED_SECTIONS)
def test_each_required_section_is_checked(missing: str) -> None:
    md = _brief(f"Routerbot. (id={ID_A})").replace(f"## {missing}", "## Something else")
    assert [(f.text, f.detail) for f in _findings(md, "section_missing")] == [
        (missing, f'no "## " heading names {missing!r}')
    ]


def test_length_band_and_id_citations_do_not_count_as_words() -> None:
    short = _brief(f"Routerbot. (id={ID_A})")
    assert [f.check for f in evaluate(short, SYNTH).findings] == ["length_out_of_band"]
    padded = short.replace("Routerbot.", "Routerbot. " + "word " * 300)
    assert evaluate(padded, SYNTH).findings == ()
    cited = padded.replace(f"(id={ID_A})", " ".join(f"(id={ID_A})" for _ in range(200)))
    assert evaluate(cited, SYNTH).words == evaluate(padded, SYNTH).words


def test_brief_without_facts_reads_zero_of_zero() -> None:
    result = evaluate("## Headline\nCI-mocked brief.", SYNTH)
    assert (result.facts_verified, result.facts_total) == (0, 0)
    assert result.grounding_line() == "_Grounding: 0/0 facts verified by automated checks._"


def test_grounding_line_has_no_braces() -> None:
    line = evaluate(BRIEF, BRIEF_INPUT).grounding_line()
    assert line == "_Grounding: 12/19 facts verified by automated checks._"
    assert "{" not in line and "}" not in line


# --------------------------------------------------------------------------
# Trend words, bare years and pulse-count stopwords
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "flagged"),
    [
        ("Trend Micro researchers describe the loader.", False),
        ("The loader drops a RAT.", False),
        ("Indicators dropped from their pulse are excluded.", False),
        ("Phishing pulses dropped to two.", True),
        ("A clear trend toward routers.", True),
    ],
)
def test_drop_and_trend_only_count_as_comparisons(sentence: str, flagged: bool) -> None:
    md = _brief(f"Routerbot. (id={ID_A})", contrast=f"- {sentence}")
    assert bool(_findings(md, "comparison_without_baseline")) is flagged


def test_a_bare_year_is_not_a_count() -> None:
    year = _brief(f"Published in 2026, routerbot probes 2 CVEs. (id={ID_A})")
    count = _brief(f"Routerbot carries 2026 indicators. (id={ID_A})")
    assert not _findings(year, "number_unsupported")
    assert _findings(count, "number_unsupported")


@pytest.mark.parametrize(("count", "ok"), [("three", True), ("seven", False)])
def test_common_words_do_not_make_any_pulse_count_pass(count: str, ok: bool) -> None:
    # "campaign" appears in 7 pulse names/tags; it must not make "seven" pass.
    contrast = f"- Ukraine is targeted by {count} of this week's pulses in a single campaign."
    md = CORRECTED.replace(
        "- **Ukraine** is named in three of this week's pulses (Kimsuky/GitPower, "
        "MATCHBOIL/UAC-0099, LunexStealer) but is not among the corpus top-5 targeted "
        "countries.",
        contrast,
    )
    assert contrast in md
    found = [f for f in evaluate(md, BRIEF_INPUT).findings if f.check == "number_unsupported"]
    assert (not found) is ok, found


# --------------------------------------------------------------------------
# Unknown count nouns and units written before the number
# --------------------------------------------------------------------------

_LANGFLOW = "Separately, the **Langflow AI platform** is being probed across 12 CVEs."
_FLAX = "with warnings issued by seven governments."


@pytest.mark.parametrize(
    ("original", "probe"),
    [
        (_FLAX, "with warnings issued by four allies."),
        (
            _LANGFLOW,
            "Separately, the **Langflow AI platform** is being probed for CVEs (16 of them).",
        ),
        (_LANGFLOW, "Separately, the **Langflow AI platform** has a CVE count of 16."),
    ],
)
def test_unsupported_counts_planted_in_the_corrected_brief_are_flagged(
    original: str, probe: str
) -> None:
    assert CORRECTED.count(original) == 1
    result = evaluate(CORRECTED.replace(original, probe), BRIEF_INPUT)
    assert [f.check for f in result.findings] == ["number_unsupported"]


def test_an_unknown_count_noun_only_matches_a_count_the_pulse_states() -> None:
    synth = json.loads(json.dumps(SYNTH))
    synth["emerging_pulses_7d"][0]["name"] = "16 Malicious Firefox Extensions steal wallets"
    synth["emerging_pulses_7d"][0]["indicator_count"] = 4
    ok = _brief(f"Routerbot ships 16 malicious extensions. (id={ID_A})")
    # 4 is the pulse's indicator count, 3 its countries, 2 its CVEs: none is a
    # count of extensions.
    for wrong in ("4", "3", "2"):
        bad = _brief(f"Routerbot ships {wrong} malicious extensions. (id={ID_A})")
        assert [f.check for f in evaluate(bad, synth).findings if f.check == "number_unsupported"]
    assert not [f for f in evaluate(ok, synth).findings if f.check == "number_unsupported"]


def test_states_count_as_countries() -> None:
    # Pulse B targets 4 countries and has 6 indicators: "six states" must not
    # pass on the indicator count.
    assert not _findings(
        _brief(f"Flax Typhoon targets four states. (id={ID_B})"), "number_unsupported"
    )
    assert _findings(_brief(f"Flax Typhoon targets six states. (id={ID_B})"), "number_unsupported")


def test_a_unit_right_before_the_number_counts_when_none_follows() -> None:
    cases = {
        "Routerbot probes CVEs (2 of them).": True,
        "Routerbot probes CVEs (3 of them).": False,
        "Routerbot has a CVE count of 2.": True,
        "Routerbot has a CVE count of 3.": False,
        "Routerbot CVEs: 3.": False,
        # A verb before the number is not its unit: "tags another 2" stays bare.
        "The routerbot report tags another 2.": True,
    }
    for claim, ok in cases.items():
        found = _findings(_brief(f"{claim} (id={ID_A})"), "number_unsupported")
        assert (not found) is ok, claim


def test_jump_and_surge_stems_do_not_catch_product_names_or_surgery() -> None:
    cases = {
        "JumpServer and JumpCloud agents were abused.": False,
        "The actor pivots through a jump host.": False,
        "A surgical strike on hospital surgery systems.": False,
        "Phishing surged.": True,
        "Phishing jumped to two pulses.": True,
        "A jump in phishing.": True,
    }
    for sentence, flagged in cases.items():
        md = _brief(f"Routerbot. (id={ID_A})", contrast=f"- {sentence}")
        assert bool(_findings(md, "comparison_without_baseline")) is flagged, sentence


# --------------------------------------------------------------------------
# Brackets after country names, "state" compounds, long tokens, named items
# --------------------------------------------------------------------------

_UKRAINE_TAIL = " but is not among the corpus top-5 targeted countries."
_MIMOSA_TARGETS = (
    "Targets span the US, Brazil, Mexico and four EU nations (France, Germany, Italy, Spain)."
)


def test_a_parenthesised_count_after_a_country_name_is_not_a_country_count() -> None:
    cases = [
        (
            _UKRAINE_TAIL,
            " but is absent from the corpus top-5 countries: United States (81), India (38), Brazil (32).",
        ),
        (
            _MIMOSA_TARGETS,
            "Targets span seven countries (four in the EU: France, Germany, Italy, Spain).",
        ),
    ]
    for original, probe in cases:
        assert CORRECTED.count(original) == 1
        result = evaluate(CORRECTED.replace(original, probe), BRIEF_INPUT)
        assert result.findings == (), probe
    # The bare-paren shape still works for "(N of them)", and a colon never
    # makes a country count: "countries: 4" reads as a bare number.
    assert not _findings(
        _brief(f"Routerbot probes CVEs (2 of them). (id={ID_A})"), "number_unsupported"
    )
    assert _findings(
        _brief(f"Routerbot probes CVEs (3 of them). (id={ID_A})"), "number_unsupported"
    )
    assert not _findings(
        _brief(f"Flax Typhoon targets countries: 6. (id={ID_B})"), "number_unsupported"
    )


def test_state_in_a_compound_is_not_a_country_unit() -> None:
    cases = [
        ("appears in two pulses:", "appears in two state-sponsored pulses:"),
        (
            "is named in three of this week's pulses",
            "is named in three state-linked campaigns this week",
        ),
    ]
    for original, probe in cases:
        assert CORRECTED.count(original) == 1
        result = evaluate(CORRECTED.replace(original, probe), BRIEF_INPUT)
        assert result.findings == (), probe


def _timed_evaluate(md: str, brief_input: dict[str, Any], limit: float = 5.0) -> float:
    """Seconds evaluate() takes; a SIGALRM after ``limit`` fails fast instead of hanging."""

    def too_slow(_signum: int, _frame: FrameType | None) -> None:
        raise TimeoutError(f"evaluate() took over {limit} s")

    previous = signal.signal(signal.SIGALRM, too_slow)
    signal.setitimer(signal.ITIMER_REAL, limit)
    try:
        started = time.perf_counter()
        evaluate(md, brief_input)
        return time.perf_counter() - started
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def test_long_tokens_and_whitespace_runs_stay_fast() -> None:
    # The backward unit look used to scan the whole text before each number,
    # which is quadratic on one long token: about 20 s for a 5,000-character one.
    numbers = " ".join(str(i) for i in range(1, 51))
    for name in ("A" * 20_000 + " " + numbers, numbers + " " + "A" * 20_000):
        synth = json.loads(json.dumps(SYNTH))
        synth["emerging_pulses_7d"][0]["name"] = name
        md = _brief(f"Routerbot probes 2 CVEs. (id={ID_A})", contrast=f"- {name}")
        assert _timed_evaluate(md, synth) < 1.0
    # The bold-list look after a count noun was quadratic on a whitespace run:
    # about 5 s for 20,000 spaces.
    md = _brief(f"Routerbot ships two droppers{' ' * 20_000}today. (id={ID_A})")
    assert _timed_evaluate(md, SYNTH) < 1.0
    # Stripping a quote's trailing punctuation reads a space run in it once: an
    # unanchored "[\s,.;:!?]+$" takes about 5 s for 40,000 spaces.
    md = _brief(f'Routerbot ships "APT28{" " * 40_000}x". (id={ID_A})')
    assert _timed_evaluate(md, SYNTH) < 1.0


_MIMOSA_COUNT = "(301 indicators, the largest pulse this week)"


def test_items_named_in_the_sentence_support_an_unknown_count_noun() -> None:
    passing = [
        # Two bold names after the number: Operation GitPower, Funhouse ransomware.
        ("appears in two pulses:", "runs two operations:"),
        # "observables" is an indicator word.
        (_MIMOSA_COUNT, "(301 observables, the largest pulse this week)"),
        # "makes it" is a verb, not the number's noun: 301 reads as a bare number.
        (_MIMOSA_COUNT, "(a total of 301 makes it the largest pulse this week)"),
    ]
    for original, probe in passing:
        assert CORRECTED.count(original) == 1
        assert evaluate(CORRECTED.replace(original, probe), BRIEF_INPUT).findings == (), probe
    flagged = [
        ("**Attribution confidence is low to moderate.**", "Two caveats on attribution."),
        ("with warnings issued by seven governments.", "with warnings issued by four allies."),
    ]
    for original, probe in flagged:
        assert CORRECTED.count(original) == 1
        result = evaluate(CORRECTED.replace(original, probe), BRIEF_INPUT)
        assert [f.check for f in result.findings] == ["number_unsupported"], probe
    # A list after a colon names its items; the count must match it.
    ok = _brief(f"Routerbot uses three loaders: alpha, beta and gamma. (id={ID_A})")
    bad = _brief(f"Routerbot uses four loaders: alpha, beta and gamma. (id={ID_A})")
    assert not _findings(ok, "number_unsupported")
    assert _findings(bad, "number_unsupported")


# --------------------------------------------------------------------------
# Noun-phrase stops, bare brackets, named items, hyphenated and EU compounds
# --------------------------------------------------------------------------


def _only_number_finding(original: str, probe: str) -> bool:
    assert CORRECTED.count(original) == 1, original
    result = evaluate(CORRECTED.replace(original, probe), BRIEF_INPUT)
    return [f.check for f in result.findings] == ["number_unsupported"]


def _clean(original: str, probe: str) -> bool:
    assert CORRECTED.count(original) == 1, original
    return evaluate(CORRECTED.replace(original, probe), BRIEF_INPUT).findings == ()


def test_only_a_listed_verb_ends_the_noun_phrase_never_a_unit_word() -> None:
    # A unit word followed by "the" is still the number's unit.
    langflow = (
        "Separately, the **Langflow AI platform** is being probed across 16 CVEs the scanner tries."
    )
    assert _only_number_finding(_LANGFLOW, langflow)
    assert _only_number_finding(_FLAX, "with warnings issued by four governments the pulse names.")
    assert _only_number_finding(_MIMOSA_TARGETS, "Targets span nine countries the pulse names.")
    assert _only_number_finding(_FLAX, "with warnings issued by four allies the pulse names.")
    # "makes" is on the verb list: 301 reads as a bare number.
    assert _clean(_MIMOSA_COUNT, "(a total of 301 makes it the largest pulse this week)")


_CLING_LANGFLOW = "ClingSTUN (31 CVE tags) and Langflow (12) name the most CVEs."
_AI_TAGS = "None of their tags is in the corpus top-5 tags."


def test_a_bare_bracket_takes_a_plural_unit_word_before_it() -> None:
    assert _only_number_finding(_CLING_LANGFLOW, "ClingSTUN carries the most CVEs (38+).")
    langflow = "Separately, the **Langflow AI platform** is being probed for CVEs (16)."
    assert _only_number_finding(_LANGFLOW, langflow)
    of_them = "Separately, the **Langflow AI platform** is being probed for CVEs (16 of them)."
    assert _only_number_finding(_LANGFLOW, of_them)
    # Never a country (or day) unit, and a singular word before the bracket
    # ("Government") is not a unit at all.
    us = " but is absent from the corpus top-5 countries: United States (81), India (38), Brazil (32)."
    assert _clean(_UKRAINE_TAIL, us)
    eu = "Targets span seven countries (four in the EU: France, Germany, Italy, Spain)."
    assert _clean(_MIMOSA_TARGETS, eu)
    industries = (
        "The corpus top-5 industries are Technology (161), Government (152) and Finance (142)."
    )
    assert _clean(_AI_TAGS, industries)


_NEBULA = "**NEBULA** (fake AI SDK npm packages, 9 indicators)"


def test_theme_labels_and_unrelated_later_bold_names_are_not_named_items() -> None:
    # In place, the sentence goes on to bold ChainDrop / Shai-Hulud and
    # TraderTraitor: other subjects, not the "two backdoors".
    nebula = "**NEBULA** planted two backdoors (fake AI SDK npm packages, 9 indicators)"
    assert _only_number_finding(_NEBULA, nebula)
    # A bullet's theme label ("**Routers:**" or "**Routers**:") names nothing.
    for label in ("**Routers:**", "**Routers**:"):
        md = _brief(f"{label} **Routerbot** planted two backdoors. (id={ID_A})")
        assert _findings(md, "number_unsupported"), label
    # Bold names inside the list after a colon still count ...
    assert _clean("appears in two pulses:", "runs two operations:")
    # ... and so do bold names before the number.
    md = _brief(f"**APT28** and **APT29** are two groups behind routerbot. (id={ID_A})")
    assert not _findings(md, "number_unsupported")


def test_a_hyphenated_compound_of_a_country_word_is_not_a_country_unit() -> None:
    probe = "is named in three nation-state campaigns this week"
    assert _clean("is named in three of this week's pulses", probe)
    # The compound's own head still counts when it is a unit: "zero-days".
    md = _brief(f"Routerbot has three zero-days. (id={ID_A})")
    assert _findings(md, "number_unsupported")
    assert not _findings(_brief(f"Routerbot has two zero-days. (id={ID_A})"), "number_unsupported")


def test_an_eu_prefix_in_a_hyphenated_compound_still_means_eu_members() -> None:
    for prefix in ("EU-member", "EU-based"):
        fixed = f"Targets span the US, Brazil, Mexico and four {prefix} states (France, Germany, Italy, Spain)."
        assert _clean(_MIMOSA_TARGETS, fixed), prefix
        assert _only_number_finding(_MIMOSA_TARGETS, f"Targets span seven {prefix} states."), prefix


def test_an_article_ends_the_noun_phrase() -> None:
    # Without the stop, "two allies the Ukraine pulses" would reach "pulses",
    # and two synthetic pulses do mention Ukraine.
    md = _brief(f"Flax Typhoon is backed by two allies the Ukraine pulses name. (id={ID_B})")
    assert _findings(md, "number_unsupported")


def test_a_colon_list_inside_a_bracket_ends_at_the_bracket() -> None:
    # **gamma** comes after the bracket closes: it is not one of the loaders.
    md = _brief(
        f"Routerbot (three loaders: **alpha** and **beta**) shares servers with **gamma**. (id={ID_A})"
    )
    assert _findings(md, "number_unsupported")


def test_bold_names_in_a_colon_list_count_even_with_a_clause_between_them() -> None:
    # Split on commas, this list reads as three items; it names two.
    md = _brief(
        f"Routerbot runs two operations: **alpha**, which uses CHM files, and **beta**. (id={ID_A})"
    )
    assert not _findings(md, "number_unsupported")


_ATTRIBUTIONS = (
    "Actor attributions (Kimsuky, Flax Typhoon) are the submitting researcher's assessment."
)


def test_a_bare_bracket_reads_the_noun_phrase_before_it() -> None:
    # "CVE tags (31)" counts CVEs, as "31 CVE tags" would.
    assert _clean(_CLING_LANGFLOW, "ClingSTUN carries the most CVE tags (31).")
    # A bare year in a bracket is still a year, not a count of reports.
    years = "Actor attributions (Kimsuky, Flax Typhoon) come from vendor reports (2026)."
    assert _clean(_ATTRIBUTIONS, years)
    # Unchanged: a plural unit word right before the bracket still binds it,
    # and singular or country words still don't.
    assert _only_number_finding(_CLING_LANGFLOW, "ClingSTUN carries the most CVEs (38+).")
    assert _only_number_finding(
        _LANGFLOW, "Separately, the **Langflow AI platform** is being probed for CVEs (16)."
    )
    industries = (
        "The corpus top-5 industries are Technology (161), Government (152) and Finance (142)."
    )
    assert _clean(_AI_TAGS, industries)
    us = " but is absent from the corpus top-5 countries: United States (81), India (38), Brazil (32)."
    assert _clean(_UKRAINE_TAIL, us)


def test_more_verbs_after_a_bare_number_end_its_noun_phrase() -> None:
    for probe in (
        "(a total of 301 tops the list this week)",
        "(its 301 dwarfs the other pulses this week)",
        "(a total of 301 exceeds every other pulse this week)",
        "(a total of 301 includes the firmware droppers)",
    ):
        assert _clean(_MIMOSA_COUNT, probe), probe
    # A verb that also reads as a plural noun ("leads") stays a noun.
    assert _only_number_finding(_MIMOSA_COUNT, "(its 301 leads the list this week)")


_BOTNETS = "that runs ad-fraud and click-fraud botnets (EnloaderLib, Android.Joker) with system privileges."


def test_bold_names_right_after_the_noun_phrase_are_named_items() -> None:
    # A bracket or an appositive right after "two botnets" names them.
    bracket = (
        "that runs two botnets (**EnloaderLib** and **Android.Joker**) with system privileges."
    )
    assert _clean(_BOTNETS, bracket)
    appositive = (
        "that runs two botnets, **EnloaderLib** and **Android.Joker**, with system privileges."
    )
    assert _clean(_BOTNETS, appositive)
    three = (
        "that runs three botnets (**EnloaderLib** and **Android.Joker**) with system privileges."
    )
    assert _only_number_finding(_BOTNETS, three)
    # A bracket with no bold names names nothing; later bold names are other subjects.
    nebula = "**NEBULA** planted two backdoors (fake AI SDK npm packages, 9 indicators)"
    assert _only_number_finding(_NEBULA, nebula)


def test_a_theme_label_can_end_in_a_full_stop_or_take_a_dash() -> None:
    nebula = "**NEBULA** planted two backdoors (fake AI SDK npm packages, 9 indicators)"
    for label in ("**Supply chain.**", "**Supply chain** —"):
        assert _only_number_finding(f"**Supply chain:** {_NEBULA}", f"{label} {nebula}"), label
    alt = ALT_CORRECT.replace(
        "NEBULA's seven fake AI SDK packages on npm install a Windows RAT", nebula
    )
    assert alt != ALT_CORRECT
    assert [f.check for f in evaluate(alt, BRIEF_INPUT).findings] == ["number_unsupported"]


# --------------------------------------------------------------------------
# Bold lists after a count, years in brackets, labels at a line start, non-EU
# --------------------------------------------------------------------------

_NEBULA_CHAINDROP = (
    "**NEBULA** (fake AI SDK npm packages, 9 indicators) and the **ChainDrop / Shai-Hulud** "
    "compromise of the TensorLake npm SDK put a RAT and a credential-stealing worm into AI "
    "developer toolchains"
)


def test_only_a_bracket_or_comma_list_of_bold_names_names_the_items() -> None:
    # Bold names in a clause that only follows the count are other subjects.
    for sentence in (
        "Routerbot ships two droppers, while **Kimsuky** and **Lazarus** reuse its servers.",
        "Routerbot ships two droppers, which **Kimsuky** and **Lazarus** also use.",
        "Routerbot ships two droppers (unlike **Kimsuky** and **Lazarus**).",
    ):
        assert _findings(_brief(f"{sentence} (id={ID_A})"), "number_unsupported"), sentence
    probe = "**NEBULA** planted two backdoors, while **ChainDrop** and **Shai-Hulud** compromised the TensorLake npm SDK"
    assert _only_number_finding(_NEBULA_CHAINDROP, probe)
    # A list of bold names alone, over the whole comma list, still names them.
    three = f"Routerbot ships three droppers, **alpha**, **beta** and **gamma**, to routers. (id={ID_A})"
    assert not _findings(_brief(three), "number_unsupported")
    bracket = (
        "that runs two botnets (**EnloaderLib** and **Android.Joker**) with system privileges."
    )
    assert _clean(_BOTNETS, bracket)
    appositive = (
        "that runs two botnets, **EnloaderLib** and **Android.Joker**, with system privileges."
    )
    assert _clean(_BOTNETS, appositive)


def test_a_year_sized_count_after_an_indicator_or_cve_word_is_still_checked() -> None:
    base_total = evaluate(CORRECTED, BRIEF_INPUT).facts_total
    sha1 = "Corpus-wide, the top indicator types end with SHA1 hashes ({}).".format
    wrong = evaluate(CORRECTED.replace(_AI_TAGS, sha1(2071)), BRIEF_INPUT)
    assert [(f.check, "(indicator)" in f.detail) for f in wrong.findings] == [
        ("number_unsupported", True)
    ]
    right = evaluate(CORRECTED.replace(_AI_TAGS, sha1(2070)), BRIEF_INPUT)
    assert right.findings == ()
    assert right.facts_verified == right.facts_total == base_total + 1
    cves = _findings(_brief(f"Routerbot probes CVEs (2026). (id={ID_A})"), "number_unsupported")
    assert [("(cve)" in f.detail) for f in cves] == [True]
    # After any other phrase a bracketed year is still a year: not checked.
    years = "Actor attributions (Kimsuky, Flax Typhoon) come from vendor reports (2026)."
    skipped = evaluate(CORRECTED.replace(_ATTRIBUTIONS, years), BRIEF_INPUT)
    assert skipped.findings == () and skipped.facts_total == base_total


def test_only_a_bold_span_opening_its_line_and_followed_by_new_content_is_a_label() -> None:
    # A dash pair or "Inc." inside a list of names doesn't make a label.
    for sentence in (
        "**APT28** — a GRU unit — and **APT29** are two groups behind routerbot.",
        "**Integrity Tech Inc.** and **APT29** are two groups behind routerbot.",
    ):
        assert not _findings(_brief(f"{sentence} (id={ID_A})"), "number_unsupported"), sentence
    # A label followed by the bullet's content is still a label, in both briefs.
    nebula = "**NEBULA** planted two backdoors (fake AI SDK npm packages, 9 indicators)"
    for label in ("**Supply chain.**", "**Supply chain** —"):
        assert _only_number_finding(f"**Supply chain:** {_NEBULA}", f"{label} {nebula}"), label
        alt = ALT_CORRECT.replace(
            "**Supply chain.** NEBULA's seven fake AI SDK packages on npm install a Windows RAT",
            f"{label} {nebula}",
        )
        assert alt != ALT_CORRECT
        assert [f.check for f in evaluate(alt, BRIEF_INPUT).findings] == ["number_unsupported"], (
            label
        )


def test_a_non_eu_count_is_checked_against_targets_minus_eu_members() -> None:
    # Midnight Mimosa targets 7 countries: 4 EU members and 3 others.
    split = "Targets span three non-EU countries (US, Brazil, Mexico) and four EU nations (France, Germany, Italy, Spain)."
    assert _clean(_MIMOSA_TARGETS, split)
    assert _only_number_finding(_MIMOSA_TARGETS, "Targets span seven non-EU countries.")
    wrong = "Targets span four non-EU countries (US, Brazil, Mexico) and four EU nations (France, Germany, Italy, Spain)."
    result = evaluate(CORRECTED.replace(_MIMOSA_TARGETS, wrong), BRIEF_INPUT)
    assert [
        (f.check, "'four' (country)" in f.detail, "allowed: 3" in f.detail) for f in result.findings
    ] == [("number_unsupported", True, True)]
    assert _only_number_finding(_MIMOSA_TARGETS, "Targets span four non-European countries.")
    # The EU reading itself is unchanged.
    fixed = "Targets span the US, Brazil, Mexico and four EU-member states (France, Germany, Italy, Spain)."
    assert _clean(_MIMOSA_TARGETS, fixed)


def _numbered(line: str) -> str:
    """A synthetic brief whose Emerging-threats bullet is the "1)" item ``line``."""
    return _brief("PLACEHOLDER").replace("- PLACEHOLDER", line)


def test_a_dash_label_is_any_opening_dash_without_a_closing_dash() -> None:
    # The content after a label may start in lower case ...
    nebula = "**Supply chain** — the **NEBULA** campaign planted two backdoors (fake AI SDK npm packages, 9 indicators)"
    assert _only_number_finding(f"**Supply chain:** {_NEBULA}", nebula)
    one = f"**Routers** — the **Routerbot** crew ships two droppers. (id={ID_A})"
    two = f"**Routers** — the **Routerbot** and **Kimsuky** crews ship two droppers. (id={ID_A})"
    assert _findings(_brief(one), "number_unsupported")  # one name, not two
    assert not _findings(_brief(two), "number_unsupported")  # the label isn't a third
    # ... and a "1)" list item opens its line like "-" or "1." does.
    one = f"1) **Routers:** **Routerbot** planted two backdoors. (id={ID_A})"
    two = f"1) **Routers:** **Routerbot** and **Kimsuky** planted two backdoors. (id={ID_A})"
    assert _findings(_numbered(one), "number_unsupported")
    assert not _findings(_numbered(two), "number_unsupported")
    # A dash closed by a second dash in the same clause is an appositive.
    apt = f"**APT28** — Russia's GRU — and **APT29** are two groups behind routerbot. (id={ID_A})"
    assert not _findings(_brief(apt), "number_unsupported")


def test_a_bold_comma_list_may_end_at_any_list_terminator() -> None:
    # Each way the list after "two droppers," can end; "(" is the inline
    # citation the prompt asks for.
    for bullet in (
        f"Routerbot ships two droppers, **alpha** and **beta**, to routers. (id={ID_A})",
        f"Routerbot ships two droppers, **alpha** and **beta**; both are new. (id={ID_A})",
        f"Routerbot ships two droppers, **alpha** and **beta**. (id={ID_A})",
        f"Routerbot (ships two droppers, **alpha** and **beta**) is new. (id={ID_A})",
        f"(id={ID_A}) Routerbot ships two droppers, **alpha** and **beta**",
        f"Routerbot ships two droppers, **alpha** and **beta** (id={ID_A}).",
    ):
        assert not _findings(_brief(bullet), "number_unsupported"), bullet
    # Anything else after the names makes them another clause's subjects.
    clause = f"Routerbot ships two droppers, **alpha** and **beta** reuse its servers. (id={ID_A})"
    assert _findings(_brief(clause), "number_unsupported")


def test_a_full_stop_label_needs_a_bold_name_or_capital_right_after() -> None:
    # "**Routers.**" followed by a capital letter is a label: one name, not two.
    one = f"**Routers.** Routerbot and **Kimsuky** planted two backdoors. (id={ID_A})"
    assert _findings(_brief(one), "number_unsupported")
    two = f"**Routers.** Routerbot, **Kimsuky** and **Lazarus** planted two backdoors. (id={ID_A})"
    assert not _findings(_brief(two), "number_unsupported")


# --------------------------------------------------------------------------
# Which dash closes a dash label: not one in brackets, in a range or after
# the next bold name
# --------------------------------------------------------------------------

_MIMOSA_OPENING = (
    "**Mobile / firmware:** **Midnight Mimosa** (301 indicators, the largest pulse this week) "
    "describes Android devices shipped with firmware that runs ad-fraud and click-fraud botnets "
    "(EnloaderLib, Android.Joker) with system privileges."
)


def _flagged(bullet: str) -> list[str]:
    """The numbers flagged in a synthetic brief whose Emerging-threats bullet is ``bullet``."""
    return [f.detail.split("'")[1] for f in _findings(_brief(bullet), "number_unsupported")]


def test_a_dash_in_a_bracket_a_range_or_after_the_next_bold_name_leaves_a_label() -> None:
    # A dash in a bracket or a range, or after the next bold name, closes
    # nothing: the label stays a label, and one name can't support "two".
    for inner in (" —", ","):
        mimosa = (
            f"**Mobile / firmware** — **Midnight Mimosa** (301 indicators{inner} the largest "
            "pulse this week) ships two firmware droppers with system privileges."
        )
        assert _only_number_finding(_MIMOSA_OPENING, mimosa), inner
    for bullet in (
        f"**Routers** — **Routerbot** (2\u20136 indicators per host) ships two droppers. (id={ID_A})",
        f"**Routers** — **Routerbot** uses 2\u20136 indicators per host and ships two droppers. (id={ID_A})",
    ):
        assert _flagged(bullet) == ["two"], bullet
    wave = (
        "**Supply chain** — the **NEBULA** campaign \u2013 a new wave \u2013 planted two backdoors "
        "(fake AI SDK npm packages, 9 indicators)"
    )
    assert _only_number_finding(f"**Supply chain:** {_NEBULA}", wave)
    # A dash pair after the next bold name is that name's aside: the label
    # stays a label, and the two names support "two".
    forks = f"**Routers** — **Routerbot** and **Kimsuky** — both Mirai forks — ship two droppers. (id={ID_A})"
    assert _flagged(forks) == []
    apt = f"**APT28** — Russia's GRU — and **APT29** are two groups behind routerbot. (id={ID_A})"
    assert _flagged(apt) == []


def test_brackets_and_ranges_alone_keep_a_dash_label_when_no_bold_name_follows_it() -> None:
    # No bold name right after the label's dash: only the bracket or range
    # rule keeps these dashes from closing it.
    for aside in (
        " (active — per vendors)",
        " [active — per vendors]",
        ", with 2\u20136 indicators per host,",
        ", with 2 \u2013 6 indicators per host,",
        ", with 2 - 6 indicators per host,",
        ", with 2—6 indicators per host,",
    ):
        bullet = f"**Routers** — routerbot{aside} and **Kimsuky** ship two droppers. (id={ID_A})"
        assert _flagged(bullet) == ["two"], aside
    # A dash after a closed bracket still closes the aside: APT28 is a name.
    for opening, closing in ("()", "[]"):
        apt = f"**APT28** — Russia's GRU {opening}its military intelligence{closing} — and **APT29** are two groups behind routerbot. (id={ID_A})"
        assert _flagged(apt) == [], opening


def test_a_dash_next_to_only_one_number_is_not_a_range() -> None:
    # A range needs a digit on both sides of its dash. Here the dash after
    # "2004" or before "2" closes the aside, so APT28 is a name.
    since = f"**APT28** — active since 2004 — and **APT29** are two groups behind routerbot. (id={ID_A})"
    assert _flagged(since) == []
    units = f"**APT28** — Russia's GRU — 2 of its units and **APT29** are two groups behind routerbot. (id={ID_A})"
    assert _flagged(units) == ["2"]


# --------------------------------------------------------------------------
# Spaced hyphens and the ";" / ":" cut in dash labels
# --------------------------------------------------------------------------


def test_a_spaced_hyphen_opens_and_closes_a_dash_like_an_em_dash() -> None:
    # A closed hyphen pair is an aside: APT28 is a name.
    apt = f"**APT28** - Russia's GRU - and **APT29** are two groups behind routerbot. (id={ID_A})"
    assert _flagged(apt) == []
    # An open one makes a label, so Routerbot is the only name. This changed
    # when a dash label stopped needing a capital letter after its dash:
    # before that, "**Routers**" here was a name and "two" passed.
    label = f"**Routers** - the **Routerbot** crew ships two droppers. (id={ID_A})"
    assert _flagged(label) == ["two"]


def test_a_semicolon_or_colon_ends_the_search_for_a_closing_dash() -> None:
    sibling = f"**Routers** — **Routerbot** runs one loader; its sibling — a Mirai fork — ships two droppers. (id={ID_A})"
    assert _flagged(sibling) == ["two"]
    # With no bold name right after the label's dash, only the cut keeps the
    # later dash pair from closing it.
    for stop in (";", ":"):
        bullet = f"**Routers** — routerbot runs one loader{stop} its sibling — a Mirai fork — and **Kimsuky** ship two droppers. (id={ID_A})"
        assert _flagged(bullet) == ["two"], stop


# --------------------------------------------------------------------------
# Sections: only a "## " heading opens one
# --------------------------------------------------------------------------

_UNCITED = 'An uncited bullet names "Operation Nowhere".'
_RANSOMWARE = '**Ransomware:** "Operation Dark Lotus" hit Korean banks.'


def _checked_findings(md: str, brief_input: dict[str, Any] = SYNTH) -> list[tuple[str, str]]:
    found = evaluate(md, brief_input).findings
    return [(f.check, f.text) for f in found if f.check != "length_out_of_band"]


def _corrected_with_an_uncited_bullet() -> str:
    """The corrected brief plus an uncited bullet quoting an invented name."""
    end = "id=6ac7f9431e9712b6c5e2a6cd)\n"  # the last Emerging-threats bullet
    assert CORRECTED.count(end) == 1
    return CORRECTED.replace(end, f"{end}- {_RANSOMWARE}\n")


def _titled_corrected_with_an_uncited_bullet() -> str:
    """The same under an "Emerging Threats" title."""
    title = "# OTX Threat Intelligence Brief"
    return _corrected_with_an_uncited_bullet().replace(title, "# OTX Emerging Threats Brief")


def _uncited_bullets(md: str) -> list[str]:
    """The text of every "- " or "1." bullet in ``md`` that cites no pulse id."""
    bullets = [re.match(r"(?:- |\d\. )(.*)", line) for line in md.splitlines()]
    return [b.group(1) for b in bullets if b and "id=" not in b.group(1)]


_FAIL_CLOSED = (
    'bullet cites no pulse id (no "## Emerging threats" heading: every bullet is checked)'
)


def test_numbered_bold_labels_instead_of_headings_open_no_section() -> None:
    md = _titled_corrected_with_an_uncited_bullet()
    headings = (
        "## Headline",
        "## Emerging Threats",
        "## Contrast with the Corpus",
        "## Analyst Caveats",
    )
    for n, (heading, name) in enumerate(zip(headings, REQUIRED_SECTIONS, strict=True), 1):
        assert md.count(heading) == 1
        md = md.replace(heading, f"{n}. **{name}**")
    # With no "## Emerging threats" heading, every bullet is checked: the
    # numbered labels and the uncited bullets are flagged.
    assert _checked_findings(md, BRIEF_INPUT) == [
        *[("section_missing", s) for s in REQUIRED_SECTIONS],
        *[("pulse_citation_missing", b) for b in _uncited_bullets(md)],
        ("pulse_name_unknown", _RANSOMWARE),
    ]


def test_a_title_naming_a_section_does_not_open_it() -> None:
    # A bullet between the title and "## Headline" is in no section: its
    # invented "Fake Pulse" is flagged like any quoted name, but it needs no
    # citation. If the title opened Emerging threats, it would need one.
    title = "# OTX Emerging Threats Brief\n"
    fake = '"Fake Pulse" leads the week.'
    md = _titled_corrected_with_an_uncited_bullet()
    assert md.count(title) == 1
    md = md.replace(title, f"{title}\n- {fake}\n")
    assert _checked_findings(md, BRIEF_INPUT) == [
        ("pulse_citation_missing", _RANSOMWARE),
        ("pulse_name_unknown", fake),
        ("pulse_name_unknown", _RANSOMWARE),
    ]


@pytest.mark.parametrize(
    ("line", "item"),
    [
        ("**Headline risk**", None),
        ("**Analyst caveats on attribution**", None),
        ("2) **Headline risk:** Routers again.", "**Headline risk:** Routers again."),
        ("- **Headline:** Routers again.", "**Headline:** Routers again."),
    ],
)
def test_no_line_but_a_heading_switches_sections(line: str, item: str | None) -> None:
    # Inside Emerging threats a bold line or label that names another section
    # is a theme label or an item: the bullets after it are still checked.
    md = _brief("PLACEHOLDER").replace(
        "- PLACEHOLDER", f"- Routerbot probes 2 CVEs. (id={ID_A})\n{line}\n- {_UNCITED}"
    )
    assert _checked_findings(md) == [
        *[("pulse_citation_missing", text) for text in [item] if text],
        ("pulse_citation_missing", _UNCITED),
        ("pulse_name_unknown", _UNCITED),
    ]


@pytest.mark.parametrize(
    ("heading", "opens"),
    [("## Emerging threats (last 7 days)", True), ("### Emerging threats", False)],
)
def test_only_a_level_two_heading_opens_a_section(heading: str, opens: bool) -> None:
    md = _brief(f"Routerbot probes 2 CVEs. (id={ID_A})", _UNCITED).replace(
        "## Emerging threats", heading
    )
    checked = [("pulse_citation_missing", _UNCITED), ("pulse_name_unknown", _UNCITED)]
    # Without the heading every bullet is checked, the uncited ones in the
    # other sections too.
    missing = [
        ("section_missing", "Emerging threats"),
        *[("pulse_citation_missing", b) for b in _uncited_bullets(md)],
        ("pulse_name_unknown", _UNCITED),
    ]
    assert _checked_findings(md) == (checked if opens else missing)


def test_without_an_emerging_threats_heading_every_bullet_is_checked() -> None:
    # "###" headings open no section. Instead of checking no bullet, the
    # citation check then reads every bullet in the brief; the quoted-name
    # check reads every block anyway.
    md = _corrected_with_an_uncited_bullet().replace("\n## ", "\n### ")
    result = evaluate(md, BRIEF_INPUT)
    assert [(f.check, f.text) for f in result.findings] == [
        *[("section_missing", s) for s in REQUIRED_SECTIONS],
        *[("pulse_citation_missing", b) for b in _uncited_bullets(md)],
        ("pulse_name_unknown", _RANSOMWARE),
    ]
    assert (result.facts_verified, result.facts_total) == (31, 32)
    cited = {f.detail for f in result.findings if f.check == "pulse_citation_missing"}
    assert cited == {_FAIL_CLOSED}


def test_a_level_two_heading_naming_no_section_keeps_the_current_one() -> None:
    # "## Ransomware" inside Emerging threats doesn't end it.
    md = _brief("PLACEHOLDER").replace(
        "- PLACEHOLDER", f"- Routerbot probes 2 CVEs. (id={ID_A})\n## Ransomware\n- {_UNCITED}"
    )
    assert _checked_findings(md) == [
        ("pulse_citation_missing", _UNCITED),
        ("pulse_name_unknown", _UNCITED),
    ]


@pytest.mark.parametrize("line", ["### Ransomware", "# Ransomware", "**Ransomware**"])
def test_a_title_inside_emerging_threats_keeps_it_open(line: str) -> None:
    md = _brief("PLACEHOLDER").replace(
        "- PLACEHOLDER", f"- Routerbot probes 2 CVEs. (id={ID_A})\n{line}\n- {_UNCITED}"
    )
    assert _checked_findings(md) == [
        ("pulse_citation_missing", _UNCITED),
        ("pulse_name_unknown", _UNCITED),
    ]


def test_a_bold_only_line_naming_a_section_does_not_make_it_present() -> None:
    md = _brief(f"Routerbot probes 2 CVEs. (id={ID_A})").replace(
        "## Emerging threats", "**Emerging threats**"
    )
    assert ("section_missing", "Emerging threats") in _checked_findings(md)


# --------------------------------------------------------------------------
# Quoted names are checked in every block of the brief
# --------------------------------------------------------------------------

_PARAGRAPH = f'Routers again: "Operation Nowhere" hit banks this week, per the pulse (id={ID_A}).'


@pytest.mark.parametrize("level", ["## ", "### "])
def test_a_paragraph_quoting_an_invented_name_is_flagged_with_or_without_headings(
    level: str,
) -> None:
    md = _brief("PLACEHOLDER").replace(
        "- PLACEHOLDER", f"- Routerbot probes 2 CVEs. (id={ID_A})\n\n{_PARAGRAPH}"
    )
    names = [f for f in _checked_findings(md.replace("## ", level)) if f[0] == "pulse_name_unknown"]
    assert names == [("pulse_name_unknown", _PARAGRAPH)]


def test_a_prose_only_brief_quoting_an_invented_name_is_flagged() -> None:
    prose = 'Routers again: "Operation Nowhere" hit banks this week.'
    result = evaluate(prose, SYNTH)
    names = [(f.check, f.text) for f in result.findings if f.check == "pulse_name_unknown"]
    assert names == [("pulse_name_unknown", prose)]
    assert (result.facts_verified, result.facts_total) == (0, 1)


@pytest.mark.parametrize(
    "before",
    ["## Headline", "## Emerging Threats", "## Analyst Caveats", None],
    ids=["before Headline", "in Headline", "in Contrast", "after Caveats"],
)
def test_a_quoted_name_outside_emerging_threats_is_checked(before: str | None) -> None:
    # Outside Emerging threats the bullet needs no citation, but its invented
    # name is still a failed fact.
    block = f"## Ransomware\n\n- {_RANSOMWARE}\n\n"
    if before is None:
        md = CORRECTED.rstrip("\n") + "\n\n" + block
    else:
        assert CORRECTED.count(before) == 1
        md = CORRECTED.replace(before, block + before)
    result = evaluate(md, BRIEF_INPUT)
    assert [(f.check, f.text) for f in result.findings] == [("pulse_name_unknown", _RANSOMWARE)]
    assert (result.facts_verified, result.facts_total) == (31, 32)


# --------------------------------------------------------------------------
# Punctuation inside the quotes is not part of the name
# --------------------------------------------------------------------------

_ACTORS: dict[str, Any] = {
    **SYNTH,
    "emerging_pulses_7d": [
        {
            "id": ID_A,
            "name": "Active Exploitation of CVE-2026-110936 in Siemens Software Center",
            "tlp": "white",
            "tags": ["APT28", "ics"],
            "targeted_countries": ["Germany"],
            "first_seen_at": "2026-10-20T00:00:00+00:00",
            "indicator_count": 4,
        },
        {
            "id": ID_B,
            "name": "DPRK fake recruiter lures",
            "tlp": "white",
            "tags": ["Lazarus"],
            "targeted_countries": [],
            "first_seen_at": "2026-10-20T00:00:00+00:00",
            "indicator_count": 3,
        },
    ],
}
_ACTOR_TAGS = 'Pulse tags such as "APT28," "Lazarus," or "DPRK" reflect vendor attribution.'


@pytest.mark.parametrize(
    ("prose", "facts"),
    [
        (_ACTOR_TAGS, 3),
        (
            "Pulse tags such as “APT28,” “Lazarus,” or “DPRK” reflect vendor attribution.",
            3,
        ),
        (
            "Industrial/OT targeting surfaces in"
            ' "Active Exploitation of CVE-2026-110936 in Siemens Software Center."',
            2,
        ),
        ('Vendor notes read "APT28;" "Lazarus:" "DPRK!" and "APT28 ?" in turn.', 4),
        (_ACTOR_TAGS.replace("APT28,", "APT28\u00a0,").replace("Lazarus,", "Lazarus\u202f!"), 3),
    ],
    ids=["comma", "comma in curly quotes", "period", "; : ! ? and a space", "no-break spaces"],
)
def test_punctuation_inside_the_quotes_is_not_part_of_the_name(prose: str, facts: int) -> None:
    # US style puts the comma or period inside the quotes: "APT28," quotes
    # the tag APT28. In the period case the CVE id is the second fact. Any
    # Unicode space before the punctuation goes too.
    result = evaluate(prose, _ACTORS)
    assert [f for f in result.findings if f.check == "pulse_name_unknown"] == []
    assert (result.facts_verified, result.facts_total) == (facts, facts)


def test_an_invented_name_with_a_comma_inside_the_quotes_is_still_flagged() -> None:
    prose = _ACTOR_TAGS.replace('"Lazarus,"', '"Operation Dark Lotus,"')
    result = evaluate(prose, _ACTORS)
    names = [(f.text, f.detail) for f in result.findings if f.check == "pulse_name_unknown"]
    assert names == [(prose, "'operation dark lotus' is not in any pulse name or tag")]
    assert (result.facts_verified, result.facts_total) == (2, 3)


def test_a_quote_of_nothing_but_punctuation_is_no_fact() -> None:
    result = evaluate('Some pulses carry only "..." as a description.', _ACTORS)
    assert [f for f in result.findings if f.check == "pulse_name_unknown"] == []
    assert (result.facts_verified, result.facts_total) == (0, 0)


# --------------------------------------------------------------------------
# How quote marks pair
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("prose", "facts"),
    [
        ('One stray " mark here. Officials link "APT28" to it.', (1, 1)),
        ('A 27" screen shows it. Officials link "APT28" to it.', (1, 2)),
        ('One stray " mark sits next to "APT28" here.', (1, 1)),
        ('A 27" screen shows "APT28" here.', (1, 2)),
    ],
    ids=["stray mark", "inch mark", "stray mark, one sentence", "inch mark, one sentence"],
)
def test_a_straight_quote_mark_before_a_space_opens_no_quote(
    prose: str, facts: tuple[int, int]
) -> None:
    # The stray mark would pair with the quote before APT28 and check the gap
    # between them instead. The "27" count is the second fact of the inch mark.
    result = evaluate(prose, _ACTORS)
    assert [f.detail for f in result.findings if f.check == "pulse_name_unknown"] == []
    assert (result.facts_verified, result.facts_total) == facts


@pytest.mark.parametrize(
    ("prose", "found", "facts"),
    [
        (
            'Officials link "Fake Zebra to it. Vendors saw a surge. Others cite "APT28" too.',
            [("comparison_without_baseline", "Vendors saw a surge.")],
            (1, 2),
        ),
        ('Officials link "U.S. Fake Zebra to it. Others cite "APT28" too.', [], (1, 1)),
        (
            'A 27"-inch screen shows it. Officials link "APT28" to it.',
            [("number_unsupported", 'A 27"-inch screen shows it.')],
            (1, 2),
        ),
        ('He said "hi. Officials link "APT28" to it.', [], (1, 1)),
    ],
    ids=[
        "unclosed, then a trend word",
        "unclosed U.S.",
        "inch mark before a hyphen",
        "unclosed hi",
    ],
)
def test_a_straight_quote_closes_only_where_no_letter_or_digit_follows(
    prose: str, found: list[tuple[str, str]], facts: tuple[int, int]
) -> None:
    # The mark before APT28 is followed by a letter, so it can't close the
    # unclosed quote: that quote would swallow the sentences up to it, check
    # the gap text as a name, hide the trend word and leave APT28 unchecked.
    # The "27" count is the second fact of the inch mark.
    result = evaluate(prose, _ACTORS)
    assert [(f.check, f.text) for f in result.findings if f.check in FACT_CHECKS] == found
    assert (result.facts_verified, result.facts_total) == facts


@pytest.mark.parametrize(
    ("prose", "names", "trends", "facts"),
    [
        (
            'Officials link _"Fake Zebra"_ and _"APT28"_ to it.',
            [('Officials link _"Fake Zebra"_ and _"APT28"_ to it.', "fake zebra")],
            [],
            (1, 2),
        ),
        (
            'Officials link __"Fake Zebra"__ to it.',
            [('Officials link __"Fake Zebra"__ to it.', "fake zebra")],
            [],
            (0, 1),
        ),
        (
            'Officials link _"U.S. Fake Zebra"_ to it.',
            [('Officials link _"U.S. Fake Zebra"_ to it.', "u.s. fake zebra")],
            [],
            (0, 1),
        ),
        (
            'Officials link _"Fake Zebra"_ to it. Vendors saw a surge. Others cite "(APT28)" too.',
            [
                ('Officials link _"Fake Zebra"_ to it.', "fake zebra"),
                ('Others cite "(APT28)" too.', "(apt28)"),
            ],
            ["Vendors saw a surge."],
            (0, 3),
        ),
    ],
    ids=["emphasis", "strong emphasis", "emphasis around U.S.", "emphasis, then a trend word"],
)
def test_a_straight_quote_in_underscore_emphasis_is_checked(
    prose: str, names: list[tuple[str, str]], trends: list[str], facts: tuple[int, int]
) -> None:
    # Markdown's _ is a word character but not a letter or digit, so a
    # closing mark before it still closes the quote.
    result = evaluate(prose, _ACTORS)
    assert _name_findings(prose) == [
        (t, f"{q!r} is not in any pulse name or tag") for t, q in names
    ]
    assert [f.text for f in result.findings if f.check == "comparison_without_baseline"] == trends
    assert (result.facts_verified, result.facts_total) == facts


@pytest.mark.parametrize("space", [" ", "\u00a0"], ids=["space", "no-break space"])
def test_a_straight_quote_opening_with_a_space_is_not_checked(space: str) -> None:
    # Known limit, pinned: a straight quote opens only before a non-space.
    result = evaluate(f'Officials link "{space}Fake Zebra" to it.', _ACTORS)
    assert [f for f in result.findings if f.check == "pulse_name_unknown"] == []
    assert (result.facts_verified, result.facts_total) == (0, 0)


@pytest.mark.parametrize(
    "prose",
    ['Officials link "Fake Zebra"to it.', 'Officials link "Fake Zebra"s operators.'],
    ids=["letter after the close", "s after the close"],
)
def test_a_straight_quote_closed_before_a_letter_is_not_checked(prose: str) -> None:
    # Known limit, pinned: a closing mark followed by a letter or digit closes
    # nothing, and the mark itself then opens a quote that never closes.
    result = evaluate(prose, _ACTORS)
    assert [f for f in result.findings if f.check == "pulse_name_unknown"] == []
    assert (result.facts_verified, result.facts_total) == (0, 0)


def test_unclosed_straight_quotes_stay_fast() -> None:
    # No straight quote mark here can close: each is followed by a letter.
    marks = '"a' * 20_000
    md = _brief(f"Routerbot ships {marks} (id={ID_A})")
    assert _timed_evaluate(md, SYNTH) < 5.0


def test_a_curly_quote_opening_inside_a_curly_quote_starts_a_new_one() -> None:
    result = evaluate("Lures name “Fake “Zebra” Kit” again.", _ACTORS)
    names = [f.detail for f in result.findings if f.check == "pulse_name_unknown"]
    assert names == ["'zebra' is not in any pulse name or tag"]


def test_unpaired_curly_quotes_stay_fast() -> None:
    # Each “ with no ” after it used to be read to the end of the text: about
    # 10 s for 20,000 of them in one sentence.
    md = _brief(f"Routerbot ships {'“a ' * 20_000}. (id={ID_A})")
    assert _timed_evaluate(md, SYNTH) < 1.0
    # Sentences split around whole quotes, so the quote search reads the whole
    # bullet: 20,000 short sentences each opening a “ must stay linear too.
    md = _brief(f"Routerbot ships {'“a. B' * 20_000} (id={ID_A})")
    assert _timed_evaluate(md, SYNTH) < 1.0


# --------------------------------------------------------------------------
# A sentence never ends inside a quote
# --------------------------------------------------------------------------

# _ACTORS, with a pulse name and a tag that hold an abbreviation.
_ABBREV: dict[str, Any] = json.loads(json.dumps(_ACTORS))
_ABBREV["emerging_pulses_7d"][0]["name"] = "U.S. Treasury Phishing Kit"
_ABBREV["emerging_pulses_7d"][1]["tags"] = ["Acme Inc. Loader"]


def _name_findings(prose: str, brief_input: dict[str, Any] = _ACTORS) -> list[tuple[str, str]]:
    found = evaluate(prose, brief_input).findings
    return [(f.text, f.detail) for f in found if f.check == "pulse_name_unknown"]


@pytest.mark.parametrize(
    ("prose", "quote"),
    [
        (
            'Officials link "U.S. Fake Operation Zebra" to the campaign.',
            "u.s. fake operation zebra",
        ),
        (
            "Officials link “U.S. Fake Operation Zebra” to the campaign.",
            "u.s. fake operation zebra",
        ),
        ('"Acme Inc. Fake Botnet" is new.', "acme inc. fake botnet"),
        ("“Acme Inc. Fake Botnet” is new.", "acme inc. fake botnet"),
        ('Lures name "Fake Loaders e.g. Zebra" again.', "fake loaders e.g. zebra"),
    ],
    ids=["U.S.", "U.S. in curly quotes", "Inc.", "Inc. in curly quotes", "e.g."],
)
def test_a_quote_holding_an_abbreviation_is_one_name(prose: str, quote: str) -> None:
    # "U.S." before a capital used to end the sentence inside the quote, so
    # neither half held a whole quote and the invented name scored 0/0.
    result = evaluate(prose, _ACTORS)
    assert _name_findings(prose) == [(prose, f"{quote!r} is not in any pulse name or tag")]
    assert (result.facts_verified, result.facts_total) == (0, 1)


def test_a_known_name_holding_an_abbreviation_passes() -> None:
    prose = 'Lures reuse "U.S. Treasury Phishing Kit" and “Acme Inc. Loader” this week.'
    result = evaluate(prose, _ABBREV)
    assert _name_findings(prose, _ABBREV) == []
    assert (result.facts_verified, result.facts_total) == (2, 2)


def test_each_quote_in_a_list_is_read_whole() -> None:
    # Cut after "U.S.", the list used to pair the gaps: only " and " was checked.
    prose = 'Officials name "U.S. Fake Zebra", "Acme Inc. Fake Botnet" and "APT28" in turn.'
    result = evaluate(prose, _ACTORS)
    assert _name_findings(prose) == [
        (prose, "'u.s. fake zebra' is not in any pulse name or tag"),
        (prose, "'acme inc. fake botnet' is not in any pulse name or tag"),
    ]
    assert (result.facts_verified, result.facts_total) == (1, 3)


@pytest.mark.parametrize(
    ("prose", "sentence", "quote"),
    [
        (
            'Per the U.S. Treasury, "Acme Inc. Fake Botnet" is new.',
            'Treasury, "Acme Inc. Fake Botnet" is new.',
            "acme inc. fake botnet",
        ),
        (
            'Per Acme Inc. Research, "U.S. Fake Zebra" is new.',
            'Research, "U.S. Fake Zebra" is new.',
            "u.s. fake zebra",
        ),
        ('Lures (e.g. "U.S. Fake Zebra") recur.', '"U.S. Fake Zebra") recur.', "u.s. fake zebra"),
    ],
    ids=["U.S.", "Inc.", "e.g."],
)
def test_abbreviations_outside_quotes_still_end_a_sentence(
    prose: str, sentence: str, quote: str
) -> None:
    # Known limit: outside quotes the split is unchanged, so the finding's
    # text starts after the abbreviation. The quote itself is read whole.
    result = evaluate(prose, _ACTORS)
    assert _name_findings(prose) == [(sentence, f"{quote!r} is not in any pulse name or tag")]
    assert (result.facts_verified, result.facts_total) == (0, 1)


@pytest.mark.parametrize(
    ("before", "sentence"),
    [
        ('One stray " mark here.', "Officials link “U.S. Fake Operation Zebra” to it."),
        ('He said "hi.', 'Officials link "U.S. Fake Operation Zebra" to it.'),
    ],
    ids=["stray mark, curly quote", "unclosed quote, straight quote"],
)
def test_an_unpaired_quote_mark_neither_counts_nor_holds_back_later_sentences(
    before: str, sentence: str
) -> None:
    prose = f"{before} {sentence}"
    result = evaluate(prose, _ACTORS)
    assert _name_findings(prose) == [
        (sentence, "'u.s. fake operation zebra' is not in any pulse name or tag")
    ]
    assert (result.facts_verified, result.facts_total) == (0, 1)


def test_an_unclosed_quote_is_no_fact() -> None:
    # Pins today's rule: a quote mark with no partner is plain text.
    prose = 'Officials link "U.S. Fake Operation Zebra to the campaign.'
    result = evaluate(prose, _ACTORS)
    assert _name_findings(prose) == []
    assert (result.facts_verified, result.facts_total) == (0, 0)


def test_a_trend_word_in_a_quote_holding_an_abbreviation_is_ignored() -> None:
    md = _brief(f"Routerbot. (id={ID_A})", contrast='- Vendors call it "U.S. Surge Campaign" now.')
    assert _findings(md, "comparison_without_baseline") == []


def test_id_and_cve_findings_show_the_whole_sentence_around_a_quoted_abbreviation() -> None:
    sentence = f'"U.S. Fake Zebra" exploits CVE-2099-0001 (id={"f" * 24}).'
    result = evaluate(_brief(sentence), SYNTH)
    checks = {"pulse_id_unknown", "pulse_name_unknown", "cve_unknown"}
    assert sorted((f.check, f.text) for f in result.findings if f.check in checks) == [
        ("cve_unknown", sentence),
        ("pulse_id_unknown", sentence),
        ("pulse_name_unknown", sentence),
    ]


def test_bold_names_before_a_quoted_abbreviation_still_count_as_named_items() -> None:
    # "two botnets" is the two bold names before it, past the quoted "U.S.".
    md = _brief(f'**Routerbot** and **Kimsuky** ride "U.S. Fake Kit" as two botnets. (id={ID_A})')
    assert _findings(md, "number_unsupported") == []
