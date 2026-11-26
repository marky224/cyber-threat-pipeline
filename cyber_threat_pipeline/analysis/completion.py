"""A provider's reply with the tokens it used, for the threat-data analyst's calls.

``Completion`` is its own module so ``claude.py`` and ``grok.py`` can import it
without a cycle through ``providers.py``. Each token field means the same thing
for every provider, and ``None`` means the reply didn't report it (or its usage
didn't add up), so the call can't be priced:

- ``input_tokens``: every prompt token, cached ones included;
- ``cached_input_tokens``: the part of ``input_tokens`` read from a cache;
- ``output_tokens``: billed output tokens, reasoning tokens included;
- ``reasoning_tokens``: the reasoning part of ``output_tokens``.

``raw`` is the reply body, with no headers, so it never holds a key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    stop_reason: str | None
    input_tokens: int | None
    cached_input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    raw: dict[str, Any]
