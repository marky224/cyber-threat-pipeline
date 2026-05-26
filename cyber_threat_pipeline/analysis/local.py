"""Local-LLM provider wrapper. Default for dev / CI / offline runs.

Talks to an OpenAI-compatible chat-completions endpoint — Ollama exposes one
at ``http://localhost:11434/v1/chat/completions`` out of the box, and so do
llama.cpp's server, LM Studio, and vLLM. The base URL is configurable so the
same code drives whichever local stack the operator runs.

This provider takes **no API key** — local LLMs are unauthenticated. The
orchestrator's "fail-fast on missing credential" path skips this provider.
"""

from __future__ import annotations

import os
from typing import Any

import requests

DEFAULT_MODEL = os.environ.get("LOCAL_MODEL", "llama3.1")
DEFAULT_MAX_TOKENS = int(os.environ.get("LOCAL_MAX_TOKENS", "1200"))
DEFAULT_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("LOCAL_TIMEOUT_SECONDS", "300"))


def query_local(
    prompt: str,
    *,
    base_url: str = DEFAULT_BASE_URL,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Run a single prompt through a local OpenAI-compatible LLM server."""
    url = f"{base_url.rstrip('/')}/v1/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    r = requests.post(url, json=body, timeout=timeout)
    r.raise_for_status()
    payload = r.json()
    return str(payload["choices"][0]["message"]["content"]).strip()
