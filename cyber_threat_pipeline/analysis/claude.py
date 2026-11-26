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

``complete_claude`` makes the same request and returns a ``Completion`` with the
reply's tokens, for the threat-data analyst. Its ``input_tokens`` adds the cache
reads and cache writes to Anthropic's ``input_tokens``, which leaves them out.
It passes ``timeout`` and ``max_retries`` to the client only when given: the SDK
reads ``timeout=None`` as no timeout at all. ``query_claude`` makes the same
request and logs the stop reason before it reads the text, so a reply with no
text block still logs why the brief failed.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import anthropic
from anthropic.types import Message, TextBlock

from cyber_threat_pipeline.analysis.completion import Completion

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
    response = _create(prompt, api_key=api_key, model=model, max_tokens=max_tokens)
    logger.info(
        "Claude stop_reason=%s: %d of %d output tokens",
        response.stop_reason,
        response.usage.output_tokens,
        max_tokens,
    )
    if response.stop_reason == "max_tokens":
        logger.warning("Claude stopped at max_tokens (%d): the brief is cut off", max_tokens)
    return _first_text(response.content)


def complete_claude(
    prompt: str,
    *,
    api_key: str,
    model: str,
    max_tokens: int,
    timeout: float | None = None,
    max_retries: int | None = None,
) -> Completion:
    """Run a single prompt and return the reply with its tokens."""
    response = _create(
        prompt,
        api_key=api_key,
        model=model,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=max_retries,
    )
    usage = response.usage
    cache_read = usage.cache_read_input_tokens or 0
    cache_write = usage.cache_creation_input_tokens or 0
    return Completion(
        text=_first_text(response.content),
        model=response.model,
        stop_reason=response.stop_reason,
        input_tokens=usage.input_tokens + cache_read + cache_write,
        cached_input_tokens=cache_read,
        output_tokens=usage.output_tokens,
        reasoning_tokens=None,
        raw=response.model_dump(mode="json"),
    )


def _create(
    prompt: str,
    *,
    api_key: str,
    model: str,
    max_tokens: int,
    timeout: float | None = None,
    max_retries: int | None = None,
) -> Message:
    options: dict[str, Any] = {}
    if timeout is not None:
        options["timeout"] = timeout
    if max_retries is not None:
        options["max_retries"] = max_retries
    client = anthropic.Anthropic(api_key=api_key, **options)
    return client.messages.create(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )


def _first_text(content: list[Any]) -> str:
    # Anthropic returns a list of typed content blocks. Plain prompts produce
    # a single text block, but a future model could lead with thinking or
    # tool-use blocks — defensively pick the first text block.
    for block in content:
        if isinstance(block, TextBlock):
            return block.text.strip()
    raise RuntimeError("Anthropic response contained no text block")
