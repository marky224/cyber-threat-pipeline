"""xAI (Grok) provider wrapper. Cloud surface — ships in code for production.

Spec: _private/specs/04-analysis-llm.md §4.2.

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
"""

from __future__ import annotations

import os
from typing import Any

import requests

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
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    r = requests.post(endpoint, json=body, headers=headers, timeout=timeout)
    r.raise_for_status()
    payload = r.json()
    return str(payload["choices"][0]["message"]["content"]).strip()
