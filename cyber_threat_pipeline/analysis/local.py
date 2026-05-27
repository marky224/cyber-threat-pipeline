"""Local-LLM provider wrapper. Default for dev / CI / offline runs.

Talks to Ollama's native /api/chat endpoint at
``http://localhost:11434/api/chat``. The base URL is configurable. Other
local OpenAI-compatible servers (llama.cpp, LM Studio, vLLM) speak a
subset of this shape; if you swap them in, you may need to map fields.

This provider takes **no API key** — local LLMs are unauthenticated. The
orchestrator's "fail-fast on missing credential" path skips this provider.
"""

from __future__ import annotations

import os
from typing import Any

import requests

DEFAULT_MODEL = os.environ.get("LOCAL_MODEL", "llama3.1")
DEFAULT_MAX_TOKENS = int(os.environ.get("LOCAL_MAX_TOKENS", "2400"))
DEFAULT_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("LOCAL_TIMEOUT_SECONDS", "300"))

# Ollama's default context window is 2048 tokens, even for models capable
# of 32k+. The analyst-brief prompt (corpus stats + every emerging pulse's
# tags/countries + instructions) is ~5-8k tokens, so the prompt gets
# silently truncated before the "## What to produce" instructions reach
# the model — the model emits only a heading and stops. 16384 covers our
# prompt growth headroom; operators with smaller models or tight VRAM can
# override via LOCAL_NUM_CTX.
DEFAULT_NUM_CTX = int(os.environ.get("LOCAL_NUM_CTX", "16384"))


def query_local(
    prompt: str,
    *,
    base_url: str = DEFAULT_BASE_URL,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    num_ctx: int = DEFAULT_NUM_CTX,
) -> str:
    """Run a single prompt through Ollama's native chat endpoint.

    Native /api/chat (rather than the OpenAI-compat /v1/chat/completions
    shim) lets us pass ``options.num_ctx``; the OpenAI-compat path
    silently drops the field and runs at Ollama's 2048-token default —
    which truncates this project's prompt and the model returns just a
    heading.
    """
    url = f"{base_url.rstrip('/')}/api/chat"
    body: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_ctx": num_ctx,
            "num_predict": max_tokens,
        },
    }
    r = requests.post(url, json=body, timeout=timeout)
    r.raise_for_status()
    payload = r.json()
    return str(payload["message"]["content"]).strip()
