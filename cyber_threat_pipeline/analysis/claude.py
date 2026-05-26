"""Anthropic (Claude) provider wrapper. Cloud surface — ships in code for production.

Spec: _private/specs/04-analysis-llm.md §4.1.

The model id is loaded from the ``CLAUDE_MODEL`` env var so swaps stay config-side.
The wrapper raises on transport errors; the orchestrator turns those into a
visibly-degraded "_<provider> brief unavailable_" placeholder rather than
silently embedding error strings in the rendered brief.
"""

from __future__ import annotations

import os

import anthropic
from anthropic.types import TextBlock

DEFAULT_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
DEFAULT_MAX_TOKENS = int(os.environ.get("CLAUDE_MAX_TOKENS", "1200"))


def query_claude(
    prompt: str,
    *,
    api_key: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> str:
    """Run a single prompt through the Anthropic Messages API. Returns the text body."""
    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=0.3,
        messages=[{"role": "user", "content": prompt}],
    )
    # Anthropic returns a list of typed content blocks. Plain prompts produce
    # a single text block, but a future model could lead with thinking or
    # tool-use blocks — defensively pick the first text block.
    for block in response.content:
        if isinstance(block, TextBlock):
            return block.text.strip()
    raise RuntimeError("Anthropic response contained no text block")
