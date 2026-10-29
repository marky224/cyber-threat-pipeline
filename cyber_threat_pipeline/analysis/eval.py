"""Deterministic faithfulness checks for the analyst brief.

Pure: no I/O, stdlib only. ``evaluate(brief_md, brief_input)`` checks one
provider's markdown against the ``brief_input`` row it was written from and
returns an ``EvalResult``. The checks warn; nothing here blocks the publish.

Checks (``Finding.check`` codes are stable; Grafana and tests key on them):

- ``section_missing``: Headline / Emerging threats / Contrast with the corpus /
  Analyst caveats each need a level-2 markdown heading whose text contains the
  name, case aside ("## Emerging threats (last 7 days)"); the prompt asks for
  exactly these four. Only a "## " heading opens or switches a section: a "# "
  title, a "###" heading, a bold-only line or a bold label ("1. **Headline**",
  "- **Headline:** ...") never does, even when it names one, so inside
  Emerging threats "**Analyst caveats on attribution**" is a theme label. A
  "## " heading that names no section ("## Ransomware") keeps the current one.
- ``length_out_of_band``: words outside 250-400. Words are
  ``[A-Za-z0-9][\\w'.\\-/]*`` tokens (curly apostrophes too) after removing ``id=<pulse id>``
  citations, ``* _ ` #`` and ``---`` rules; headings count.
- ``pulse_id_unknown``: every 24-hex token is an ``emerging_pulses_7d`` id.
- ``pulse_citation_missing``: every bullet under Emerging threats cites an id.
  It fails closed: with no "## " heading naming Emerging threats, it reads
  every bullet in the brief instead of none. Bullets in other sections need no
  citation.
- ``pulse_name_unknown``: every double-quoted string in the brief, in any
  section, bullet or paragraph, is a substring of an input pulse name or tag
  (case-insensitive). Trailing ``, . ; : ! ?`` and whitespace (any Unicode
  space, a no-break space too) inside the quotes are ignored: "APT28,"
  quotes the tag APT28. A quote of nothing but those is no fact. A straight
  quote mark opens a quote only before a non-space and closes it only before
  a non-word character, so the inch mark in 'a 27" screen' opens none, and in
  'He said "hi. Officials link "APT28"' the unclosed "hi. pairs with nothing
  and APT28 is checked. A straight quote that opens with a space (any Unicode
  space: " Fake Zebra") is not checked. A curly quote ends at its first ” and
  can't hold another “. A quote mark left unpaired is plain text, no fact.
- ``cve_unknown``: every CVE id appears in an input pulse name or tag.
- ``number_unsupported``: every number is in the allowed set for its scope and
  unit (rules below).
- ``comparison_without_baseline``: a sentence uses trend words (spike, surge,
  prior/previous/last week, week-over-week, increase, decrease, rise,
  "jumped"/"a jump in", "dropped to/by/in", decline, shift, trend, unusual).
  "Drops a RAT", the vendor Trend Micro, JumpServer/JumpCloud, a jump host
  and surgery are not trend words. ``brief_input`` has no previous-period
  figures, so no such comparison can be supported. Quoted text is ignored, so
  a pulse name like "the rise of Midnight Mimosa" can be quoted.

Sentences: a bullet or paragraph splits after ``. ! ?`` and whitespace
before a capital, digit, ``*``, a quote or ``(``, never inside a quote, so
every check reads "U.S. Fake Operation Zebra" whole. Outside quotes an
abbreviation still ends a sentence: "the U.S. Treasury" splits after "U.S.".

Number rules (``number_unsupported``):

- Parsing: digits (``1,234``, ``4.5``), ``N+``, ``N%``, ranges ``a-b`` (hyphen or
  en dash) / ``a to b``, and number words two to ninety-nine ("one" is skipped:
  it is usually a pronoun). Skipped entirely: CVE ids, pulse ids, ISO dates and
  times, "top-5", digits glued to letters (``UAC-0099``, ``x64``, ``C2``), and
  a bare year (1990-2099 with no unit, as in "in 2026"). Headings and bold-only
  lines are not checked.
- Scope: the bullet or paragraph holding the number. Its cited pulses are the
  ids in it plus pulses whose unique tag (a tag of 4+ characters that belongs
  to exactly one emerging pulse) appears in it.
- Unit: read from the noun phrase after the number: same clause (a clause
  ends at ``, ; : ( ) [ ] .`` or a dash), up to four words, ending at a
  preposition, article, pronoun, or one of a few verbs (makes, puts, gives,
  keeps, leaves, takes, brings, tops, exceeds, dwarfs, includes: "a total of
  301 makes it the largest"; verbs that also read as plural nouns, such as
  "leads", are left out); a unit word never ends it ("16 CVEs the scanner
  tries" is 16 CVEs). An "of
  the / of this week's" lead-in is skipped. A hyphenated compound is one word
  ("nation-state", "state-sponsored" are not country words; "zero-days" is a
  CVE word). Its first unit word picks the allowed set; day/week units count
  only as the very next word ("7 days", "7-day"). If the phrase has no unit
  word but ends in a plural noun ("four allies", "16 extensions"), it matches
  only a count the cited pulse's own name or tags state for that same noun, or the
  number of items the same sentence names: bold names before the number, a
  list of nothing but bold names and separators (commas, "and", "or") in a
  bracket or between commas right after its noun phrase ("two botnets (**A**
  and **B**)", "two botnets, **A** and **B**,"), or the bold names or items of a list
  after a colon that follows it ("two operations: **A** ... and **B**",
  "three loaders: a, b and c"). Other bold text after the number belongs to
  other subjects, and a bullet's theme label names nothing: a bold span that
  opens its line (after any "-", "1." or "1)" marker) and ends in or is
  followed by ":" ("**Supply chain:**"); or is followed by a dash that no
  second dash closes ("**Supply chain** — the **NEBULA** campaign ..."; a
  closing dash comes before the next bold span and the next ";" or ":",
  outside brackets and not inside a range (``a-b`` with a hyphen, en dash
  or em dash): nothing closes the first dash in "**Routers** — **Routerbot** and
  **Kimsuky** — both forks —" or "**Routers** — **Routerbot** (9
  indicators — per host)"); or ends in "." with a bold name or capital
  letter right after ("**Supply chain.** **NEBULA** ..."). Bold text
  elsewhere, a closed dash pair ("**APT28** — Russia's GRU — and") or
  "**Integrity Tech Inc.** and" is a name. Never corpus totals or the
  pulse's indicator, CVE or country counts. When nothing
  follows the number, a unit right before it (within 40 characters) counts,
  but only in these shapes: a bracket right after a noun phrase that ends in
  a plural word, read like the phrase after a number ("CVEs (38+)" is CVEs,
  "the most CVE tags (31)" is 31 CVEs; a 1990-2099 number binds only after an
  indicator or CVE word, so "SHA1 hashes (2070)" is a count and "vendor
  reports (2026)" a year), "indicators (e.g., 2-6)" (a range), "a CVE count of
  16", "CVEs: 16". A phrase ending in a singular word ("Government (152)")
  binds nothing, a verb before the number ("tags another 12") doesn't either,
  and this backward look never gives the country or day class ("United
  States (81)", "seven countries (four in the EU: ...)").

  ===================  ==========================================================
  unit words           allowed values
  ===================  ==========================================================
  indicators, IOCs,    corpus header totals, top-type and emerging-type counts,
  observables, hashes, every emerging pulse's indicator_count
  domains, URLs, IPv4,
  MD5 ...
  CVEs, vulnerabil-    per cited pulse: its CVE count (cve-* tags plus CVE ids in
  ities, zero-days,    its name); the emerging CVE type count. Never a sum across
  flaws                pulses.
  countries, nations,  per cited pulse: its number of targeted countries; of
  states (plural only; EU-27 members when "EU"/"European" (alone or as part of
  singular "state" is  a compound like "EU-member") sits between the number
  a compound like      and the noun; non-EU rule: after "non" ("non-EU",
  "state-sponsored")   "non European") its targeted countries minus its EU-27
                       members
  governments, govts,  only a count the cited pulse's own name or tags state for
  agencies             the same kind of noun ("7 govts")
  any other plural     a count the cited pulse's own name or tags state for that
  noun                 noun ("Seven Fake AI SDK Packages" -> 7 packages), or the
                       number of items the sentence names (see Unit above)
  pulses, reports,     number of emerging pulses; top-5 country/tag/industry
  campaigns            pulse counts; ids cited in the sentence; for each word of
                       4+ letters in the sentence (stopwords like "this" and
                       "week" aside), how many emerging pulses mention it in
                       their name, tags or countries
  tags                 top-5 tag counts
  days, weeks          7
  %                    100*a/b at the stated precision, a from the other sets,
                       b one of: total pulses, total/active indicators, emerging
                       pulses, emerging indicators, a cited pulse's indicators
  (no unit at all)     all of the global values above, plus the cited pulses'
                       own numbers (indicators, CVEs, countries, any number in
                       their name or tags)
  ===================  ==========================================================

- Matching: an exact value matches. ``N+`` and "over/more than/at least N"
  mean at least N, read at N's leading-digit precision: they match a value v
  with ``N <= v < N + 10**(digits(N) - 1)``. So "16+" accepts 16-25 and "300+"
  accepts 300-399, but "38+" rejects 31 and 49. "about/around/roughly/nearly/
  approximately/~ N", or N ending in zeros, match when v rounded to N's
  trailing zeros equals N ("about 25,000" accepts 25,215). A range matches when
  both ends do.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

REQUIRED_SECTIONS = ("Headline", "Emerging threats", "Contrast with the corpus", "Analyst caveats")
WORDS_MIN, WORDS_MAX = 250, 400

# Checks whose findings count against ``facts_verified``.
FACT_CHECKS = frozenset(
    {
        "pulse_id_unknown",
        "pulse_name_unknown",
        "cve_unknown",
        "number_unsupported",
        "comparison_without_baseline",
    }
)

EU27 = frozenset(
    {
        "austria", "belgium", "bulgaria", "croatia", "cyprus", "czechia", "czech republic",
        "denmark", "estonia", "finland", "france", "germany", "greece", "hungary",
        "ireland", "italy", "latvia", "lithuania", "luxembourg", "malta", "netherlands",
        "poland", "portugal", "romania", "slovakia", "slovenia", "spain", "sweden",
    }
)  # fmt: skip

_HEX_ID = re.compile(r"\b[0-9a-f]{24}\b")
_ID_CITATION = re.compile(r"\bid=[0-9a-f]{24}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_WORD = re.compile(r"[A-Za-z0-9][\w'\u2019.\-/]*")
_HEADING = re.compile(r"^\s*#{1,6}\s+(.*)$")
# The only line that opens or switches a section: "## Emerging threats".
_SECTION_HEADING = re.compile(r"^\s*##\s+(.*)$")
_BOLD_LINE = re.compile(r"^\s*\*\*([^*]+)\*\*:?\s*$")
_BULLET = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(.*)$")
# A straight quote opens only before a non-space, so the inch mark in 'a 27"
# screen' opens none, and closes only before a non-word character, so in
# 'He said "hi. Officials link "APT28"' the mark before APT28 opens a quote
# instead of closing "hi. A curly quote can't hold another opening one, so a
# “ with no ” after it is read up to the next “ (to the end: quadratic).
_QUOTED = re.compile(r"\"(?=\S)([^\"]+)\"(?!\w)|“([^“”]+)”")
# Trailing punctuation and whitespace (any Unicode space) inside a quote are
# not part of the name: a US-style brief writes "APT28," "Lazarus." The
# lookbehind starts a match only where such a run starts, so a long space run
# is read once (unanchored, the search retries at every space: quadratic).
_QUOTE_TAIL = re.compile(r"(?<![\s,.;:!?])[\s,.;:!?]+$")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9*\"“(])")
# A quote or a sentence end. A split falls only on a sentence end, so a quote
# is never cut: "U.S. Fake Operation Zebra" is one quote. Quotes pair as in
# ``_QUOTED``; an unpaired quote mark is plain text.
_SENTENCE_OR_QUOTE = re.compile(rf"{_QUOTED.pattern}|{_SENTENCE_END.pattern}")
_MASK = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b"
    r"|\b[0-9a-f]{24}\b"
    r"|\b\d{4}-\d{2}-\d{2}(?:[T ][\d:.+]+)?"
    r"|\b\d{1,2}:\d{2}(?::\d{2})?\b"
    r"|\btop[- ]\d+\b",
    re.IGNORECASE,
)
_NUM = r"\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?"
_NUMBER = re.compile(
    rf"(?<![\w.\-/])(~\s*)?({_NUM})(\+)?(%)?"
    rf"(?:\s*(?:\u2013|-|to)\s*({_NUM})(%)?)?"
    r"(?!\w|\.\w)"
)
_UNITS_1_9 = ["one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
_TEENS = ["ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen"]
_TEENS += ["sixteen", "seventeen", "eighteen", "nineteen"]
_TENS = ["twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]
_WORD_VALUES: dict[str, int] = {w: i + 1 for i, w in enumerate(_UNITS_1_9)}
_WORD_VALUES |= {w: i + 10 for i, w in enumerate(_TEENS)}
_WORD_VALUES |= {w: (i + 2) * 10 for i, w in enumerate(_TENS)}
_NUMBER_WORD = re.compile(
    r"\b(" + "|".join(_TENS) + r")(?:[- ](" + "|".join(_UNITS_1_9) + r"))?\b"
    r"|\b(" + "|".join(w for w in _UNITS_1_9 + _TEENS if w != "one") + r")\b",
    re.IGNORECASE,
)
_CLAUSE_STOP = re.compile(r"[,;:()\[\]\u2013\u2014]|\.(?!\w)")
# A word of a number's noun phrase; a hyphenated compound ("nation-state",
# "zero-days") is one word, so its parts don't count as units on their own.
_UNIT_WORD = re.compile(r"[A-Za-z][\w'\u2019]*(?:-[A-Za-z][\w'\u2019]*)*")
_APPROX_BEFORE = re.compile(
    r"(?:about|around|roughly|nearly|approximately|almost|some|~)\s*$", re.IGNORECASE
)
_PLUS_BEFORE = re.compile(r"(?:over|more than|at least|upwards of)\s*$", re.IGNORECASE)
_TREND = re.compile(
    r"\b(?:spik\w*|surg(?:e|es|ed|ing)|(?:prior|previous|last)[- ]weeks?\b|week[- ]over[- ]week"
    r"|increas\w*|decreas\w*|rise[sn]?|rising|rose|jump(?:s|ed|ing)|jump\s+(?:in|of)"
    r"|drop(?:s|ped)?\s+(?:to|by|in)"
    r"|declin\w*|shift\w*|trend(?!\s*micro\b)\w*|unusual\w*|compared (?:with|to) last)\b",
    re.IGNORECASE,
)

# Words too common to name what a pulse count is about ("this", "week").
_STOPWORDS = frozenset(
    {
        "this", "that", "these", "those", "with", "from", "have", "were", "their",
        "there", "which", "while", "week", "weeks", "pulse", "pulses", "report",
        "reports", "campaign", "campaigns", "also", "into", "over", "more", "most",
        "some", "many", "each", "both", "only", "than", "them", "they", "named",
        "appear", "appears", "seen", "across", "among",
    }
)  # fmt: skip

# After a number, the words that end its noun phrase ("12 CVEs in", "four
# allies who") or, right after it, open an "of the/this week's ..." lead-in.
_PHRASE_STOP = frozenset(
    {
        "of", "in", "on", "at", "by", "for", "from", "to", "with", "and", "or", "but",
        "that", "which", "who", "is", "are", "was", "were", "be", "been", "has", "have",
        "had", "as", "than", "into", "per", "so", "while", "then", "it", "they", "them",
        "there", "about", "across", "against", "among", "between", "since", "after",
        "before", "over", "under", "like", "each", "thus", "this", "these", "those",
        "ones", "others", "the", "a", "an",
    }
)  # fmt: skip
# Verbs that can follow a bare number and end its noun phrase ("a total of 301
# makes it the largest"). None is a unit word. Verbs that also read as plural
# nouns ("leads", "marks") are left out: there the noun reading wins.
_PHRASE_VERBS = frozenset(
    {"makes", "puts", "gives", "keeps", "leaves", "takes", "brings", "tops", "exceeds",
     "dwarfs", "includes"}
)  # fmt: skip
_LEAD_IN = frozenset({"of", "the", "this", "these", "those", "its", "their", "all", "a", "an"})
# A unit word written before the number when none follows it:
# "CVEs (16)", "a CVE count of 16", "CVEs: 16", "indicators (e.g., 2-6)".
# Group 2 is a bare "(" (only after a plural word), group 3 an "(e.g., " (only
# before a range).
_UNIT_BEFORE = re.compile(
    r"([A-Za-z][\w'\u2019-]*)\s*(?:(\(\s*)|(\(\s*(?:e\.g|i\.e)\.,?\s*)"
    r"|\s+(?:count|total|number|tally)\s+(?:of|is|was|at)\s+|:\s*)$",
    re.IGNORECASE,
)
_BOLD = re.compile(r"\*\*[^*]+\*\*")
# A dash after a bold span ("**Supply chain** — "); a hyphen only counts with
# spaces around it.
_DASH = re.compile(r"\s*[\u2014\u2013]\s*|\s+-\s+")
# Read after that dash: a range ("2-6" with a hyphen, en dash or em dash,
# spaces allowed), a bracket, or a dash that may close an appositive
# ("— Russia's GRU —").
_ASIDE = re.compile(
    r"(?P<range>\d\s*[\u2014\u2013-]\s*(?=\d))|(?P<open>[(\[])|(?P<close>[)\]])"
    r"|(?P<dash>[\u2014\u2013]|\s-\s)"
)
# Bold names joined only by list separators: "**A**, **B** and **C**".
_BOLD_LIST = re.compile(
    r"\s*\*\*[^*]+\*\*(?:\s*(?:,\s*(?:and|or)\s+|,|\band\b|\bor\b)\s*\*\*[^*]+\*\*)*\s*"
)

_UNIT_CLASSES: dict[str, str] = {}
for _cls, _words in {
    "indicator": "indicator indicators ioc iocs hash hashes domain domains hostname hostnames "
    "url urls ip ips ipv4 ipv6 address addresses md5 sha1 sha256 filehash observable observables",
    "cve": "cve cves vulnerability vulnerabilities zero-day zero-days flaw flaws",
    # Plural "states" only: singular "state" is nearly always a compound
    # ("state-sponsored", "state-linked"), not a count of countries.
    "country": "country countries nation nations states",
    "gov": "government governments govt govts agency agencies",
    "pulse": "pulse pulses report reports campaign campaigns",
    "tag": "tag tags",
    "day": "day days week weeks",
}.items():
    for _w in _words.split():
        _UNIT_CLASSES[_w] = _cls


@dataclass(frozen=True)
class Finding:
    """One failed check: its code, the sentence (or section) and why."""

    check: str
    text: str
    detail: str


@dataclass(frozen=True)
class EvalResult:
    """Result of ``evaluate`` for one provider's brief."""

    words: int
    facts_total: int
    facts_verified: int
    findings: tuple[Finding, ...]

    def grounding_line(self, extra: str | None = None) -> str:
        """Plain markdown for the page. No braces: Evidence would parse them."""
        tail = f" {extra}" if extra else ""
        return (
            f"_Grounding: {self.facts_verified}/{self.facts_total} facts verified "
            f"by automated checks.{tail}_"
        )


@dataclass(frozen=True)
class _Pulse:
    id: str
    name: str
    tags: tuple[str, ...]
    countries: tuple[str, ...]
    indicators: int
    cves: int
    eu_countries: int
    text: str  # lowercased name + tags + countries
    stated: tuple[tuple[float, str | None], ...]  # numbers in name/tags + unit class


@dataclass
class _Block:
    section: str | None
    text: str
    is_bullet: bool
    cited: list[_Pulse] = field(default_factory=list)


@dataclass(frozen=True)
class _Number:
    low: float
    high: float | None  # set for ranges
    raw: str
    unit: str | None
    region: str | None  # "eu" or "non-eu" when the noun phrase says so
    plus: bool
    approx: bool
    percent: bool
    start: int = 0  # position in the sentence (``**`` count as characters)
    end: int = 0


def evaluate(brief_md: str, brief_input: dict[str, Any]) -> EvalResult:
    """Run every check on ``brief_md`` against ``brief_input``."""
    pulses = _pulses(brief_input)
    blocks, headings = _blocks(brief_md, pulses)
    globals_ = _global_values(brief_input, pulses)

    findings: list[Finding] = []
    facts = 0
    words = _count_words(brief_md)

    emerging = _emerging(blocks, headings)
    findings += _check_sections(headings)
    findings += _check_length(words)
    findings += _check_citations(emerging)
    for check, scope in (
        (_check_pulse_ids, blocks),
        (_check_quoted_names, blocks),
        (_check_cves, blocks),
        (_check_numbers, blocks),
    ):
        checked, found = check(scope, pulses, globals_)
        facts += checked
        findings += found
    comparisons = _check_comparisons(blocks)
    facts += len(comparisons)
    findings += comparisons

    failed_facts = sum(1 for f in findings if f.check in FACT_CHECKS)
    return EvalResult(
        words=words,
        facts_total=facts,
        facts_verified=facts - failed_facts,
        findings=tuple(findings),
    )


# --------------------------------------------------------------------------
# Input model
# --------------------------------------------------------------------------


def _pulses(brief_input: dict[str, Any]) -> list[_Pulse]:
    out: list[_Pulse] = []
    for p in brief_input.get("emerging_pulses_7d") or []:
        tags = tuple(str(t) for t in p.get("tags") or [])
        countries = tuple(str(c) for c in p.get("targeted_countries") or [])
        name = str(p["name"])
        cve_ids = {t.lower() for t in tags if _CVE.fullmatch(t)}
        cve_ids |= {m.lower() for m in _CVE.findall(name)}
        stated = tuple((n.low, n.unit) for n in _numbers(name)) + tuple(
            (n.low, n.unit) for t in tags for n in _numbers(t)
        )
        out.append(
            _Pulse(
                id=str(p["id"]),
                name=name,
                tags=tags,
                countries=countries,
                indicators=int(p.get("indicator_count") or 0),
                cves=len(cve_ids),
                eu_countries=sum(1 for c in countries if c.lower() in EU27),
                text=" ".join((name, *tags, *countries)).lower(),
                stated=stated,
            )
        )
    return out


def _global_values(brief_input: dict[str, Any], pulses: list[_Pulse]) -> dict[str, set[float]]:
    header = brief_input.get("corpus_header") or {}
    header_vals = {float(v) for v in header.values() if isinstance(v, int | float)}
    types = {float(t["count"]) for t in brief_input.get("top_types") or []}
    emerging = {
        str(t["type"]): float(t["count"]) for t in brief_input.get("emerging_indicators_7d") or []
    }
    top_pulse_counts = {
        float(i["pulse_count"])
        for key in ("top_countries", "top_tags", "top_industries")
        for i in brief_input.get(key) or []
    }
    tags = {float(t["pulse_count"]) for t in brief_input.get("top_tags") or []}
    pulse_inds = {float(p.indicators) for p in pulses}
    totals = {
        float(header.get(k, 0)) for k in ("total_pulses", "total_indicators", "active_indicators")
    }
    totals |= {float(len(pulses)), float(sum(emerging.values()))}
    return {
        "indicator": header_vals | types | set(emerging.values()) | pulse_inds,
        "cve": {emerging["CVE"]} if "CVE" in emerging else set(),
        "pulse": {float(len(pulses))} | top_pulse_counts,
        "tag": tags,
        "day": {7.0},
        "totals": {t for t in totals if t > 0},
        "bare": header_vals | types | set(emerging.values()) | top_pulse_counts | pulse_inds
        | {float(len(pulses)), 7.0},
    }  # fmt: skip


# --------------------------------------------------------------------------
# Markdown model
# --------------------------------------------------------------------------


def _section_of(heading: str) -> str | None:
    """The required section whose name ``heading`` contains, if any.

    Case doesn't count, and digits and punctuation read as spaces.
    """
    norm = re.sub(r"[^a-z ]+", " ", heading.lower())
    norm = " ".join(norm.split())
    for name in REQUIRED_SECTIONS:
        if name.lower() in norm:
            return name
    return None


def _blocks(brief_md: str, pulses: list[_Pulse]) -> tuple[list[_Block], list[str]]:
    """Split markdown into bullet/paragraph blocks tagged with their section."""
    blocks: list[_Block] = []
    headings: list[str] = []
    section: str | None = None
    current: _Block | None = None
    for line in brief_md.splitlines():
        stripped = line.strip()
        heading = _SECTION_HEADING.match(line)
        if heading:
            # The prompt asks for exactly four "## " headings. Only such a
            # heading opens or switches a section; one that names none, like
            # "## Ransomware" inside Emerging threats, keeps the current one.
            headings.append(heading.group(1))
            section = _section_of(heading.group(1)) or section
            current = None
            continue
        if _HEADING.match(line) or _BOLD_LINE.match(line):
            # A "# " title, a "###" heading or a bold-only line (often a theme
            # label inside Emerging threats) is a title: not checked, and never
            # a section, even when it names one.
            current = None
            continue
        if not stripped or re.fullmatch(r"-{3,}|\*{3,}|_{3,}", stripped):
            current = None
            continue
        bullet = _BULLET.match(line)
        if bullet or current is None:
            current = _Block(section, bullet.group(1) if bullet else stripped, bool(bullet))
            blocks.append(current)
        else:
            current.text += " " + stripped

    unique = _unique_tags(pulses)
    by_id = {p.id: p for p in pulses}
    for b in blocks:
        low = b.text.lower()
        cited = {by_id[i].id: by_id[i] for i in _HEX_ID.findall(b.text) if i in by_id}
        for tag, p in unique.items():
            if re.search(rf"(?<!\w){re.escape(tag)}(?!\w)", low):
                cited[p.id] = p
        b.cited = list(cited.values())
    return blocks, headings


def _emerging(blocks: list[_Block], headings: list[str]) -> list[_Block]:
    """The blocks the citation check reads.

    The Emerging threats section's; with no "## " heading naming it, every
    bullet in the brief, so a brief without the section fails closed instead
    of checking nothing.
    """
    if any(_section_of(h) == "Emerging threats" for h in headings):
        return [b for b in blocks if b.section == "Emerging threats"]
    return [b for b in blocks if b.is_bullet]


def _unique_tags(pulses: list[_Pulse]) -> dict[str, _Pulse]:
    owners: dict[str, list[_Pulse]] = {}
    for p in pulses:
        for t in {t.lower() for t in p.tags}:
            owners.setdefault(t, []).append(p)
    return {t: ps[0] for t, ps in owners.items() if len(ps) == 1 and len(t) >= 4}


def _sentences(text: str) -> list[str]:
    """``text`` split at sentence ends, never inside a quoted string."""
    out: list[str] = []
    start = 0
    for m in _SENTENCE_OR_QUOTE.finditer(text):
        if m.lastindex is None:  # a sentence end; a quote sets group 1 or 2
            out.append(text[start : m.start()])
            start = m.end()
    out.append(text[start:])
    return [s for s in out if s.strip()]


def _count_words(brief_md: str) -> int:
    text = _ID_CITATION.sub(" ", brief_md)
    text = re.sub(r"^\s*-{3,}\s*$", " ", text, flags=re.MULTILINE)
    text = re.sub(r"[*_`#]", " ", text)
    return len(_WORD.findall(text))


# --------------------------------------------------------------------------
# Structural checks
# --------------------------------------------------------------------------


def _check_sections(headings: list[str]) -> list[Finding]:
    present = {_section_of(h) for h in headings}
    return [
        Finding("section_missing", name, f'no "## " heading names {name!r}')
        for name in REQUIRED_SECTIONS
        if name not in present
    ]


def _check_length(words: int) -> list[Finding]:
    if WORDS_MIN <= words <= WORDS_MAX:
        return []
    return [
        Finding("length_out_of_band", f"{words} words", f"asked for {WORDS_MIN}-{WORDS_MAX} words")
    ]


def _check_citations(blocks: list[_Block]) -> list[Finding]:
    return [
        Finding(
            "pulse_citation_missing",
            b.text,
            "Emerging threats bullet cites no pulse id"
            if b.section == "Emerging threats"
            else 'bullet cites no pulse id (no "## Emerging threats" heading: every bullet is checked)',
        )
        for b in blocks
        if b.is_bullet and not _HEX_ID.search(b.text)
    ]


# --------------------------------------------------------------------------
# Fact checks: each returns (facts checked, findings)
# --------------------------------------------------------------------------

_Check = tuple[int, list[Finding]]


def _check_pulse_ids(blocks: list[_Block], pulses: list[_Pulse], _g: object) -> _Check:
    known = {p.id for p in pulses}
    checked, found = 0, []
    for b in blocks:
        for s in _sentences(b.text):
            for i in _HEX_ID.findall(s):
                checked += 1
                if i not in known:
                    found.append(Finding("pulse_id_unknown", s, f"{i} is not an emerging pulse id"))
    return checked, found


def _check_quoted_names(blocks: list[_Block], pulses: list[_Pulse], _g: object) -> _Check:
    haystack = [p.name.lower() for p in pulses] + [t.lower() for p in pulses for t in p.tags]
    checked, found = 0, []
    for b in blocks:
        for s in _sentences(b.text):
            for m in _QUOTED.finditer(s):
                quote = _QUOTE_TAIL.sub("", (m.group(1) or m.group(2)).strip()).lower()
                if not quote:
                    continue
                checked += 1
                if not any(quote in h for h in haystack):
                    found.append(
                        Finding(
                            "pulse_name_unknown", s, f"{quote!r} is not in any pulse name or tag"
                        )
                    )
    return checked, found


def _check_cves(blocks: list[_Block], pulses: list[_Pulse], _g: object) -> _Check:
    known = {c.lower() for p in pulses for c in _CVE.findall(p.text)}
    checked, found = 0, []
    for b in blocks:
        for s in _sentences(b.text):
            for c in _CVE.findall(s):
                checked += 1
                if c.lower() not in known:
                    found.append(Finding("cve_unknown", s, f"{c} is not in the input"))
    return checked, found


def _check_comparisons(blocks: list[_Block]) -> list[Finding]:
    found = []
    for b in blocks:
        for s in _sentences(b.text):
            words = sorted({m.group(0).lower() for m in _TREND.finditer(_QUOTED.sub(" ", s))})
            if words:
                found.append(
                    Finding(
                        "comparison_without_baseline",
                        s,
                        f"{', '.join(words)}: the input has no previous-period figures",
                    )
                )
    return found


def _check_numbers(
    blocks: list[_Block], pulses: list[_Pulse], globals_: dict[str, set[float]]
) -> _Check:
    checked, found = 0, []
    for b in blocks:
        for s in _sentences(b.text):
            for n in _numbers(s):
                checked += 1
                allowed = _allowed(n, s, b.cited, pulses, globals_)
                ends = [n.low] if n.high is None else [n.low, n.high]
                if not all(_matches(v, n, allowed) for v in ends):
                    shown = ", ".join(_fmt(v) for v in sorted(allowed)[:12]) or "none"
                    found.append(
                        Finding(
                            "number_unsupported",
                            s,
                            f"{n.raw!r} ({n.unit or 'no unit'}) is not supported; allowed: {shown}",
                        )
                    )
    return checked, found


def _numbers(text: str) -> list[_Number]:
    """Parse the numbers in one sentence (see the module docstring)."""
    masked = _MASK.sub(lambda m: " " * len(m.group(0)), text.replace("**", "  "))
    out: list[_Number] = []
    spans: list[tuple[int, int, float, float | None, bool, bool]] = []
    for m in _NUMBER.finditer(masked):
        low = float(m.group(2).replace(",", ""))
        high = float(m.group(5).replace(",", "")) if m.group(5) else None
        spans.append(
            (m.start(), m.end(), low, high, bool(m.group(3)), bool(m.group(4) or m.group(6)))
        )
    for m in _NUMBER_WORD.finditer(masked):
        if m.group(1):
            value = _WORD_VALUES[m.group(1).lower()] + (
                _WORD_VALUES[m.group(2).lower()] if m.group(2) else 0
            )
        else:
            value = _WORD_VALUES[m.group(3).lower()]
        spans.append((m.start(), m.end(), float(value), None, False, False))
    for start, end, low, high, plus, percent in sorted(spans):
        before = masked[max(0, start - 20) : start]
        unit, region = _unit_after(masked[end:])
        raw = masked[start:end].strip()
        if unit is None:
            unit = _unit_before(
                _window_before(masked, start),
                is_range=high is not None,
                is_year=high is None and not (plus or percent) and _is_year(raw),
            )
        if unit is None and high is None and not (plus or percent) and _is_year(raw):
            continue
        out.append(
            _Number(
                low=low,
                high=high,
                raw=raw,
                unit="percent" if percent else unit,
                region=region,
                plus=plus or bool(_PLUS_BEFORE.search(before)),
                approx=bool(_APPROX_BEFORE.search(before)) or masked[start] == "~",
                percent=percent,
                start=start,
                end=end,
            )
        )
    return out


def _is_year(raw: str) -> bool:
    """A bare 4-digit 1990-2099 with no unit reads as a year, not a count."""
    return raw.isdigit() and len(raw) == 4 and 1990 <= int(raw) <= 2099


def _unit_after(rest: str) -> tuple[str | None, str | None]:
    """The unit of the number that ``rest`` follows, and its region if any.

    The region is "eu" for "EU nations" / "EU-member states" and "non-eu" for
    "non-EU countries" / "non European countries", else None.

    Reads the noun phrase after the number (same clause, up to four words,
    ending at a preposition, article, pronoun or listed verb; an "of the ..."
    lead-in is skipped). The first unit-table word in it wins; day/week only as the very
    next word. With none, a plural head noun ("four allies") gives
    ``"noun:<word>"``: only a count the cited pulse itself states for that
    noun can support it.
    """
    stop = _CLAUSE_STOP.search(rest)
    clause = rest[: stop.start()] if stop else rest
    words = [w.lower() for w in _UNIT_WORD.findall(clause)[:8]]
    lead = 0
    if words[:1] == ["of"]:
        while lead < len(words) and (
            words[lead] in _LEAD_IN or words[lead].endswith(("'s", "\u2019s"))
        ):
            lead += 1
    phrase: list[str] = []
    for w in words[lead:]:
        if w in _PHRASE_STOP or w in _PHRASE_VERBS or len(phrase) == 4:
            break
        phrase.append(w)
    # "EU-member states" is one word of the phrase; test each hyphen part.
    # A part after "non" ("non-EU", "non European") means the non-EU targets.
    parts = [part for w in phrase for part in w.split("-")]
    region = next(
        (
            "non-eu" if i and parts[i - 1] == "non" else "eu"
            for i, part in enumerate(parts)
            if part in {"eu", "european"}
        ),
        None,
    )
    for i, w in enumerate(phrase):
        cls = _UNIT_CLASSES.get(w) or _UNIT_CLASSES.get(
            f"{w}-{phrase[i + 1]}" if i + 1 < len(phrase) else ""
        )
        if cls == "day" and (i > 0 or lead):
            continue
        if cls:
            return cls, region
    plural = [w for w in phrase if len(w) >= 4 and w.endswith("s") and not w.endswith("ss")]
    return (f"noun:{plural[-1]}" if plural else None), region


def _window_before(text: str, start: int, width: int = 40) -> str:
    """The ``width`` characters before ``start``, minus a word the cut split.

    Bounded so the backward unit look stays linear: scanning everything
    before each number is quadratic on one very long token.
    """
    cut = max(0, start - width)
    window = text[cut:start]
    if cut and (text[cut - 1].isalnum() or text[cut - 1] in "'\u2019-_"):
        window = re.sub(r"^[\w'\u2019-]+", "", window)
    return window


def _unit_before(before: str, *, is_range: bool, is_year: bool) -> str | None:
    """A unit written right before the number, in the few shapes that bind it.

    "CVE tags (31)" (a bare bracket after a noun phrase ending in a plural
    word: its first unit word counts, as the forward look would read "31 CVE
    tags"; a 1990-2099 number binds only after an indicator or CVE word, so
    "SHA1 hashes (2070)" is a count and "vendor reports (2026)" a year), "indicators
    (e.g., 2-6)" (a range only), "a CVE count of 16", "CVEs: 16". Never the
    country or day class: in "United States (81)" or "seven countries (four in
    the EU: ...)" the words before the bracket are not the number's unit.
    """
    m = _UNIT_BEFORE.search(before)
    if m is None:
        return None
    if m.group(2) is not None:
        phrase = _phrase_before(before[: m.start(2)])
        if not phrase or not phrase[-1].endswith("s") or phrase[-1].endswith("ss"):
            return None
        cls = next((_UNIT_CLASSES[w] for w in phrase if w in _UNIT_CLASSES), None)
        # Indicator and CVE counts reach the thousands: "SHA1 hashes (2070)" is
        # a count. After any other phrase a 1990-2099 number is a year.
        if is_year and cls not in ("indicator", "cve"):
            return None
    else:
        if m.group(3) is not None and not is_range:
            return None
        cls = _UNIT_CLASSES.get(m.group(1).lower())
    return None if cls in ("day", "country") else cls


def _phrase_before(text: str) -> list[str]:
    """The noun phrase ``text`` ends with: up to four words, back to a stop word."""
    stops = list(_CLAUSE_STOP.finditer(text))
    segment = text[stops[-1].end() :] if stops else text
    phrase: list[str] = []
    for w in reversed([w.lower() for w in _UNIT_WORD.findall(segment)]):
        if w in _PHRASE_STOP or w in _PHRASE_VERBS or len(phrase) == 4:
            break
        phrase.insert(0, w)
    return phrase


def _allowed(
    n: _Number,
    sentence: str,
    cited: list[_Pulse],
    pulses: list[_Pulse],
    g: dict[str, set[float]],
) -> set[float]:
    cited_vals = {float(v) for p in cited for v in (p.indicators, p.cves, len(p.countries))}
    cited_vals |= {v for p in cited for v, _ in p.stated}
    unit = n.unit
    if unit == "indicator":
        return g["indicator"] | {float(p.indicators) for p in cited}
    if unit == "cve":
        return g["cve"] | {float(p.cves) for p in cited}
    if unit == "country":
        if n.region == "eu":
            return {float(p.eu_countries) for p in cited}
        if n.region == "non-eu":
            return {float(len(p.countries) - p.eu_countries) for p in cited}
        return {float(len(p.countries)) for p in cited}
    if unit == "gov":
        return {v for p in cited for v, u in p.stated if u == unit}
    if (unit or "").startswith("noun:"):
        stated = {v for p in cited for v, u in p.stated if u == unit}
        return stated | _named_items(sentence, n.start, n.end)
    if unit == "pulse":
        words = {w.lower() for w in re.findall(r"[A-Za-z]{4,}", sentence)} - _STOPWORDS
        counts = {float(sum(1 for p in pulses if w in p.text)) for w in words}
        return g["pulse"] | counts | {float(len(_HEX_ID.findall(sentence)))}
    if unit == "tag":
        return g["tag"]
    if unit == "day":
        return g["day"]
    if unit == "percent":
        numerators = g["bare"] | cited_vals
        denominators = g["totals"] | {float(p.indicators) for p in cited if p.indicators}
        decimals = len(n.raw.split(".")[1].rstrip("%")) if "." in n.raw else 0
        return {
            round(100 * a / b, decimals) for a in numerators for b in denominators if 0 < a <= b
        }
    return g["bare"] | cited_vals


def _named_items(sentence: str, start: int, end: int) -> set[float]:
    """How many items the sentence names around a number.

    Bold names before it; a list of nothing but bold names in a bracket or
    between commas right after its noun phrase ("two botnets (**A** and
    **B**)", "two botnets, **A** and **B**,"); and, in a list after a colon that follows it, that
    list's bold names or its items ("two operations: **A** ... and **B**",
    "three loaders: alpha, beta and gamma"). Each is counted on its own. Other
    bold text after the number belongs to other subjects, and a bullet's theme
    label is not a name. Zero is never a count of named items.
    """
    before, after = sentence[:start], sentence[end:]
    counts = {_bold_names(before, line_start=True), _bold_names(_right_after_phrase(after))}
    colon = after.find(":")
    if colon >= 0:
        listed = _list_span(after[colon + 1 :])
        counts |= {_bold_names(listed), _list_items(listed)}
    return {float(c) for c in counts if c}


def _right_after_phrase(after: str) -> str:
    """The list of bold names right after the noun phrase that ``after`` opens.

    "" unless one to four phrase words (no stop word or listed verb) lead
    straight to "(" or ",", and what follows is nothing but bold names and
    list separators (commas, "and", "or"): a whole bracket ("two botnets
    (**A** and **B**)"), or a comma list that ends at a comma, semicolon,
    full stop, closing bracket, an opening bracket (an inline citation, as in
    "two droppers, **A** and **B** (id=...)") or the sentence end ("two
    botnets, **A** and **B**, with").
    A clause such as ", while **A** and **B** reuse its servers" names
    other subjects.
    """
    # Greedy, so a long whitespace run is read once (a lazy group with \s* on
    # both sides backtracks quadratically).
    m = re.match(r"([^(),.;:*]*)([(,])", after)
    if m is None:
        return ""
    words = [w.lower() for w in _UNIT_WORD.findall(m.group(1))]
    if not 1 <= len(words) <= 4 or any(w in _PHRASE_STOP or w in _PHRASE_VERBS for w in words):
        return ""
    rest = after[m.end() :]
    if m.group(2) == "(":
        span = _list_span(rest)
        return span if _BOLD_LIST.fullmatch(span) else ""
    listed = _BOLD_LIST.match(rest)
    terminators = ("", ",", ";", ".", ")", "(")
    if listed is None or rest[listed.end() : listed.end() + 1] not in terminators:
        return ""
    return listed.group(0)


def _bold_names(text: str, *, line_start: bool = False) -> int:
    """Bold spans in ``text``, minus a theme label when ``text`` opens a line.

    Only a bold span at the very start of its bullet, line or sentence can be
    a theme label (see ``_is_theme_label``); bold text anywhere else is a name.
    """
    spans = list(_BOLD.finditer(text))
    opens_line = line_start and spans and not text[: spans[0].start()].strip()
    if opens_line and _is_theme_label(text, spans[0]):
        return len(spans) - 1
    return len(spans)


def _is_theme_label(text: str, m: re.Match[str]) -> bool:
    """Whether the bold span ``m`` that opens ``text`` is a bullet's theme label.

    - It ends in ":" or is followed by ":" ("**Supply chain:**", "**Supply
      chain**:").
    - Or it is followed by a dash that no second dash closes (see
      ``_closes_dash``): "**Supply chain** — the **NEBULA** campaign ...". A
      closed pair is an appositive: in "**APT28** — Russia's GRU — and
      **APT29**", APT28 is a name.
    - Or it ends in "." and the bullet's content starts right after with a
      bold name or a capital letter ("**Supply chain.** **NEBULA** ...",
      "**Supply chain.** NEBULA's ..."), unlike "**Integrity Tech Inc.** and".
    """
    inner = m.group(0)[2:-2].rstrip()
    follow = text[m.end() :]
    if inner.endswith(":") or follow.startswith(":"):
        return True
    dash = _DASH.match(follow)
    if dash:
        return not _closes_dash(follow[dash.end() :])
    if inner.endswith("."):
        content = follow.lstrip()
        return content.startswith("**") or content[:1].isupper()
    return False


def _closes_dash(text: str) -> bool:
    """Whether ``text``, read after a bold span's dash, holds a second dash closing it.

    Only a dash before the next bold span and the next ";" or ":" counts, and
    only outside brackets and not inside a range (``a-b`` with a hyphen, en
    dash or em dash). So in "**Routers** — **Routerbot** and **Kimsuky** — both
    Mirai forks —" and "**Routers** — **Routerbot** (9 indicators — per
    host)" nothing closes the first dash.
    """
    bold = _BOLD.search(text)
    clause = re.split(r"[;:]", text[: bold.start()] if bold else text, maxsplit=1)[0]
    depth = 0
    for m in _ASIDE.finditer(clause):
        if m.lastgroup == "open":
            depth += 1
        elif m.lastgroup == "close":
            depth -= 1
        elif m.lastgroup == "dash" and not depth:
            return True
    return False


def _list_span(text: str) -> str:
    """``text`` up to a closing bracket it didn't open, where the list ends."""
    depth = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return text[:i]
    return text


def _list_items(text: str) -> int:
    """Items in "a, b and c"; commas inside brackets don't split."""
    parts, depth, current = [], 0, ""
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch in ",;" and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    parts.append(current)
    items = [p.strip().rstrip(".") for p in parts if p.strip().rstrip(".")]
    if not items:
        return 0
    last = items[-1].lower()
    if not last.startswith(("and ", "or ")) and (" and " in last or " or " in last):
        return len(items) + 1
    return len(items)


def _matches(value: float, n: _Number, allowed: Iterable[float]) -> bool:
    allowed = set(allowed)
    if value in allowed:
        return True
    if n.plus:
        step = 10 ** (len(str(int(value))) - 1)
        return any(value <= v < value + step for v in allowed)
    zeros = len(str(int(value))) - len(str(int(value)).rstrip("0")) if value >= 10 else 0
    if n.approx or zeros:
        return any(round(v, -zeros) == value for v in allowed)
    return False


def _fmt(v: float) -> str:
    return str(int(v)) if v == int(v) else str(v)
