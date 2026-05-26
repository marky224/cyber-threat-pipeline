"""Provider registry — names → callable + default-model + credential shape.

Single source of truth for "which LLM providers exist." The orchestrator looks
up by env-var name (e.g. ``ANALYSIS_PRIMARY_PROVIDER=claude``); each entry
describes what credential the slot needs (an API key, a base URL, or nothing).

Adding a new provider is: write ``foo.py`` with a ``query_foo`` function +
``DEFAULT_MODEL``, then add an entry here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from cyber_threat_pipeline.analysis import claude, gemini, gpt, grok, local

ProviderName = Literal["claude", "grok", "gpt", "gemini", "local"]

# What kind of credential the slot consumes.
#   "api_key"  — a SecretStr key from Settings (must be present at orchestrate-time)
#   "base_url" — a URL string from Settings (a local server; no auth)
CredentialKind = Literal["api_key", "base_url"]


@dataclass(frozen=True)
class Provider:
    """Static metadata describing one configurable LLM slot."""

    name: ProviderName
    # The function that runs the prompt. Signature varies by provider (some take
    # ``api_key=``, some take ``base_url=``); the orchestrator dispatches via
    # this entry's ``credential_kind`` so the call site stays uniform.
    query: Callable[..., str]
    default_model: str
    credential_kind: CredentialKind
    # The ``Settings`` attribute name holding the credential. Resolves to a
    # ``SecretStr | None`` for api_key kinds, a plain ``str`` for base_url.
    credential_attr: str
    # Pretty label rendered into the markdown brief.
    display_label: str


PROVIDERS: dict[ProviderName, Provider] = {
    "claude": Provider(
        name="claude",
        query=claude.query_claude,
        default_model=claude.DEFAULT_MODEL,
        credential_kind="api_key",
        credential_attr="anthropic_api_key",
        display_label="Claude (Anthropic)",
    ),
    "grok": Provider(
        name="grok",
        query=grok.query_grok,
        default_model=grok.DEFAULT_MODEL,
        credential_kind="api_key",
        credential_attr="xai_api_key",
        display_label="Grok (xAI)",
    ),
    "gpt": Provider(
        name="gpt",
        query=gpt.query_gpt,
        default_model=gpt.DEFAULT_MODEL,
        credential_kind="api_key",
        credential_attr="openai_api_key",
        display_label="GPT (OpenAI)",
    ),
    "gemini": Provider(
        name="gemini",
        query=gemini.query_gemini,
        default_model=gemini.DEFAULT_MODEL,
        credential_kind="api_key",
        credential_attr="google_api_key",
        display_label="Gemini (Google)",
    ),
    "local": Provider(
        name="local",
        query=local.query_local,
        default_model=local.DEFAULT_MODEL,
        credential_kind="base_url",
        credential_attr="ollama_base_url",
        display_label="Local LLM",
    ),
}


def resolve(name: str) -> Provider:
    """Look up a provider by name; raise a clear error if unknown."""
    key = name.strip().lower()
    for known_name, provider in PROVIDERS.items():
        if known_name == key:
            return provider
    known_csv = ", ".join(sorted(PROVIDERS))
    raise ValueError(f"Unknown analysis provider {name!r}; known: {known_csv}")
