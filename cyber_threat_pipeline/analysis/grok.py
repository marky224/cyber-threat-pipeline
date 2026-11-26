"""xAI (Grok) provider wrapper. Cloud surface — ships in code for production.

Spec: phase 04 §4.2.

The model id is **pinned in code** as ``grok-4`` (overridable via the
``GROK_MODEL`` env var). It is forwarded explicitly in every request body
to the xAI chat-completions API; xAI does NOT auto-select a model on the
backend — the field is required and the API would return HTTP 400 if it
were omitted. To change models, set ``GROK_MODEL`` in the environment
(preferred) or edit ``DEFAULT_MODEL`` below.

Uses raw ``requests`` against the OpenAI-compatible chat-completions endpoint.
The xai-sdk has shifted shape often enough that keeping this as a thin HTTP
client keeps the dep tree minimal and the call site stable. If the SDK
stabilises and we want to swap in, the public ``query_grok`` signature is the
facade — replacing the body is a one-file change.

``complete_grok`` sends the same body with the ``temperature`` it is given and
returns a ``Completion`` with the reply's tokens, for the threat-data analyst.
``query_grok`` is ``complete_grok`` at temperature 0.3, as the brief has always
sent, returning the text.

What ``complete_grok`` relies on, read 2026-11-26 in xAI's REST API reference
for chat completions (docs.x.ai, developers, REST API reference, inference,
chat completions) and its best-practices page, with no API call:

- ``usage.prompt_tokens`` (total prompt tokens),
  ``usage.prompt_tokens_details.cached_tokens`` (tokens cached from earlier
  requests and reused), ``usage.completion_tokens``,
  ``usage.completion_tokens_details.reasoning_tokens`` and
  ``usage.total_tokens``, documented as the sum of prompt and completion
  tokens. The reference's Responses example reports reasoning apart
  (32 + 9 + 110 = 151), so the sum check below decides how to bill each reply:
  ``total = prompt + completion`` bills ``completion``;
  ``total = prompt + completion + reasoning`` bills ``completion + reasoning``;
  any other total, or no usage, leaves every token field ``None`` (unpriced).
- ``choices[0].finish_reason``: the reference shows ``"stop"``; its legacy
  completions page defines ``"length"`` as reaching the model's limit or
  ``max_tokens``.
- ``max_tokens`` is deprecated in favour of ``max_completion_tokens``, which
  bounds only visible output tokens, not reasoning tokens. The body still sends
  ``max_tokens``, as ``query_grok`` always has.
- ``temperature`` is accepted from 0 to 2 (sampling uses at most 1). The
  best-practices page recommends 0.7 with ``top_p`` 0.95 for its reasoning
  models.
"""

from __future__ import annotations

import os
from typing import Any

import requests

from cyber_threat_pipeline.analysis.completion import Completion

# Pinned model id. Sent literally in every API request body — see the
# `body["model"] = model` line below. The xAI API does not substitute a
# default if this field is missing; it responds 400.
DEFAULT_MODEL = os.environ.get("GROK_MODEL", "grok-4")
DEFAULT_MAX_TOKENS = int(os.environ.get("GROK_MAX_TOKENS", "1200"))
DEFAULT_ENDPOINT = os.environ.get("GROK_ENDPOINT", "https://api.x.ai/v1/chat/completions")
DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("GROK_TIMEOUT_SECONDS", "60"))


def query_grok(
    prompt: str,
    *,
    api_key: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Run a single prompt through xAI's chat-completions API. Returns the text body."""
    return complete_grok(
        prompt,
        api_key=api_key,
        model=model,
        max_tokens=max_tokens,
        temperature=0.3,
        endpoint=endpoint,
        timeout=timeout,
    ).text


def complete_grok(
    prompt: str,
    *,
    api_key: str,
    model: str,
    max_tokens: int,
    temperature: float,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Completion:
    """Run a single prompt and return the reply with its tokens."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    r = requests.post(endpoint, json=body, headers=headers, timeout=timeout)
    r.raise_for_status()
    payload = r.json()
    choice = payload["choices"][0]
    input_tokens, cached, output, reasoning = _usage(payload.get("usage"))
    return Completion(
        text=str(choice["message"]["content"]).strip(),
        model=str(payload.get("model", model)),
        stop_reason=choice.get("finish_reason"),
        input_tokens=input_tokens,
        cached_input_tokens=cached,
        output_tokens=output,
        reasoning_tokens=reasoning,
        raw=payload,
    )


def _usage(usage: Any) -> tuple[int | None, int | None, int | None, int | None]:
    """(input, cached input, billed output, reasoning) tokens, by the sum check."""
    unpriced: tuple[None, None, None, None] = (None, None, None, None)
    if not isinstance(usage, dict):
        return unpriced
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    total = usage.get("total_tokens")
    cached = (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
    reasoning = (usage.get("completion_tokens_details") or {}).get("reasoning_tokens", 0)
    counts = (prompt, completion, total, cached, reasoning)
    if not all(isinstance(n, int) and not isinstance(n, bool) for n in counts):
        return unpriced
    assert isinstance(prompt, int) and isinstance(completion, int)
    if total == prompt + completion:
        return prompt, cached, completion, reasoning
    if total == prompt + completion + reasoning:
        return prompt, cached, completion + reasoning, reasoning
    return unpriced
