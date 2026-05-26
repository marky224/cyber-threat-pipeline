"""OpenAI (GPT) provider wrapper. Cloud surface — ships in code for production.

Named ``gpt.py`` (not ``openai.py``) so the module name doesn't shadow the
PyPI ``openai`` package at the package level. The SDK is imported normally
inside this file because absolute imports resolve via ``sys.path``.
"""

from __future__ import annotations

import os

from openai import OpenAI

DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
DEFAULT_MAX_TOKENS = int(os.environ.get("OPENAI_MAX_TOKENS", "1200"))


def query_gpt(
    prompt: str,
    *,
    api_key: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> str:
    """Run a single prompt through OpenAI's chat-completions API. Returns the text body."""
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        temperature=0.3,
        messages=[{"role": "user", "content": prompt}],
    )
    content = response.choices[0].message.content
    if content is None:
        raise RuntimeError("OpenAI response contained no message content")
    return content.strip()
