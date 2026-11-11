"""Anthropic (Claude) provider wrapper. Cloud surface — ships in code for production.

Spec: phase 04 §4.1.

The model id is **pinned in code** as ``claude-sonnet-4-6`` (overridable
via the ``CLAUDE_MODEL`` env var). It is forwarded explicitly to the
Anthropic Messages API in every request; Anthropic does NOT auto-select
a model on the backend — the field is required and the API would return
HTTP 400 if it were omitted. To change models, set ``CLAUDE_MODEL`` in
the environment (preferred) or edit ``DEFAULT_MODEL`` below.

The wrapper raises on transport errors; the orchestrator turns those into a
visibly-degraded "_<provider> brief unavailable_" placeholder rather than
silently embedding error strings in the rendered brief.

The output limit is ``CLAUDE_MAX_TOKENS`` (default 4000, about three times a
400-word brief with its citations; the model never sees the limit). The
scheduled workflow doesn't pass ``CLAUDE_MAX_TOKENS``, so production uses this
default. Each call logs its stop reason and output tokens. A ``max_tokens``
stop also logs a warning, and the cut text is returned as is: the page
publishes it and the grounding checks report what it lacks.

The request sends no ``temperature``: anthropic 1.x dropped ``temperature``,
``top_p`` and ``top_k`` from ``messages.create()``, and Anthropic's migration
guide for API version 2026-10-21, which anthropic 2.x sends, says that version
rejects them. Claude samples at the API's default.
"""

from __future__ import annotations

import logging
import os

import anthropic
from anthropic.types import TextBlock

logger = logging.getLogger(__name__)

# Pinned model id. Sent literally in every API request body — see
# `client.messages.create(model=...)` below. The Anthropic SDK does not
# substitute a default if this field is missing; the API responds 400.
DEFAULT_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
DEFAULT_MAX_TOKENS = int(os.environ.get("CLAUDE_MAX_TOKENS", "4000"))


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
        messages=[{"role": "user", "content": prompt}],
    )
    logger.info(
        "Claude stop_reason=%s: %d of %d output tokens",
        response.stop_reason,
        response.usage.output_tokens,
        max_tokens,
    )
    if response.stop_reason == "max_tokens":
        logger.warning("Claude stopped at max_tokens (%d): the brief is cut off", max_tokens)
    # Anthropic returns a list of typed content blocks. Plain prompts produce
    # a single text block, but a future model could lead with thinking or
    # tool-use blocks — defensively pick the first text block.
    for block in response.content:
        if isinstance(block, TextBlock):
            return block.text.strip()
    raise RuntimeError("Anthropic response contained no text block")
