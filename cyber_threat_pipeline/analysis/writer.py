"""Render the analyst brief to markdown for Evidence to consume.

Spec: _private/specs/04-analysis-llm.md §5, extended to N providers.

The page accepts an arbitrary number of provider results; the writer:
  - dedupes by (provider, model) so two slots pointing at the same local
    model collapse to one block (the dev/CI default),
  - renders a single plain block when one provider remains after dedupe,
  - renders ``<Tabs>``/``<Tab>`` blocks when two or more remain,
  - round-trips the prompt verbatim inside a ``<details>`` element so the
    artifact is auditable.

Deterministic for a given (generated_at, prompt, results) tuple.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

PAGE_PATH = Path("reporting/pages/analyst-brief.md")


@dataclass(frozen=True)
class ProviderResult:
    """One provider's contribution to the page.

    ``text`` is either the rendered brief, or the visible-failure placeholder
    ``_<provider> brief unavailable: <error>_`` the orchestrator produces on
    per-provider error (spec §4.3).
    """

    name: str
    label: str
    model: str
    text: str


def _dedupe(results: list[ProviderResult]) -> list[ProviderResult]:
    """Keep the first occurrence of each (name, model) pair."""
    seen: set[tuple[str, str]] = set()
    out: list[ProviderResult] = []
    for r in results:
        key = (r.name, r.model)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _render_provider_block(r: ProviderResult) -> str:
    return f"### {r.label} — `{r.model}`\n\n{r.text.rstrip()}"


def _render_body(results: list[ProviderResult]) -> str:
    if len(results) == 1:
        return _render_provider_block(results[0])
    parts = ["<Tabs>"]
    for r in results:
        parts.append(f'  <Tab label="{r.label} — {r.model}">')
        parts.append("")
        parts.append(r.text.rstrip())
        parts.append("")
        parts.append("  </Tab>")
    parts.append("</Tabs>")
    return "\n".join(parts)


def render_markdown(
    *,
    generated_at: datetime,
    prompt: str,
    results: list[ProviderResult],
) -> str:
    """Return the full markdown page as a string. Pure; no I/O."""
    if not results:
        raise ValueError("render_markdown requires at least one provider result")

    unique = _dedupe(results)
    body = _render_body(unique)
    multi = len(unique) > 1

    intro = (
        "Multiple large-language models, **same payload, side by side.** This "
        "page is the output of `cyber_threat_pipeline/analysis`; the data "
        "behind it is the `brief_input` mart (regenerated weekly by dbt). "
        "Every model receives an identical prompt — differences are "
        "interpretive, not informational."
        if multi
        else (
            "This page is the output of `cyber_threat_pipeline/analysis`; the "
            "data behind it is the `brief_input` mart (regenerated weekly by "
            "dbt). When a second provider is configured, the side-by-side "
            "comparison appears here automatically."
        )
    )

    md = f"""\
---
title: Analyst Brief
description: "Two-model brief on this week's emerging threats."
---

# Analyst Brief — {generated_at:%Y-%m-%d}

{intro}

{body}

## Prompt context

<details>
<summary>Show the prompt sent to every model</summary>

```code
{prompt}
```

</details>
"""
    return md.rstrip() + "\n"


def write_brief(
    *,
    generated_at: datetime,
    prompt: str,
    results: list[ProviderResult],
    path: Path | None = None,
) -> Path:
    """Render the markdown page and write it to ``path``. Returns the path.

    ``path`` defaults to ``PAGE_PATH`` at call time (NOT import time) so test
    monkeypatching of ``PAGE_PATH`` works.
    """
    target = path if path is not None else PAGE_PATH
    md = render_markdown(generated_at=generated_at, prompt=prompt, results=results)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(md, encoding="utf-8")
    return target
