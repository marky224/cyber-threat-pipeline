"""Google (Gemini) provider wrapper. Cloud surface — ships in code for production.

Uses raw ``requests`` against the Generative Language REST API rather than the
Google SDK — Google's Python SDK story has churned more than once (the older
``google-generativeai`` package vs. the newer ``google-genai``), and the REST
endpoint is the stable contract. If/when the SDK stabilises, ``query_gemini``
is the facade — swapping the body is a one-file change.
"""

from __future__ import annotations

import os
from typing import Any

import requests

DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
DEFAULT_MAX_TOKENS = int(os.environ.get("GEMINI_MAX_TOKENS", "1200"))
DEFAULT_BASE_URL = os.environ.get(
    "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
)
DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("GEMINI_TIMEOUT_SECONDS", "60"))


def query_gemini(
    prompt: str,
    *,
    api_key: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    base_url: str = DEFAULT_BASE_URL,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Run a single prompt through the Gemini ``generateContent`` REST API."""
    url = f"{base_url.rstrip('/')}/models/{model}:generateContent"
    body: dict[str, Any] = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": max_tokens,
        },
    }
    headers = {"Content-Type": "application/json", "x-goog-api-key": api_key}
    r = requests.post(url, json=body, headers=headers, timeout=timeout)
    r.raise_for_status()
    payload = r.json()
    # Defensive extraction — Gemini may return safety-blocked responses with
    # no candidates, or with empty parts. Surface those as RuntimeError so the
    # orchestrator renders the visible-failure placeholder.
    candidates = payload.get("candidates") or []
    if not candidates:
        raise RuntimeError(f"Gemini returned no candidates: {payload!r}")
    parts = candidates[0].get("content", {}).get("parts") or []
    texts = [p["text"] for p in parts if "text" in p]
    if not texts:
        raise RuntimeError(f"Gemini candidate contained no text parts: {candidates[0]!r}")
    return "".join(texts).strip()
