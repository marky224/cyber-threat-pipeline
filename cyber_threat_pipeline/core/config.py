"""Pipeline configuration — env-var-driven typed settings.

Spec: _private/specs/02-ingestion.md §3.
"""

from __future__ import annotations

from pydantic import Field, PostgresDsn, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Pipeline configuration. Populated from env / .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    neon_database_url: PostgresDsn = Field(..., alias="NEON_DATABASE_URL")

    otx_api_key: SecretStr = Field(..., alias="OTX_API_KEY")

    # Analyst-brief providers. Two slots; each accepts 'claude' | 'grok' | 'local'.
    # Defaults to a single local Ollama call (slots collapse when (provider, model)
    # match). Production sets primary=claude + secondary=grok.
    analysis_primary_provider: str = Field("local", alias="ANALYSIS_PRIMARY_PROVIDER")
    analysis_secondary_provider: str = Field("local", alias="ANALYSIS_SECONDARY_PROVIDER")

    # Cloud-provider API keys — OPTIONAL at Settings construction. The orchestrator
    # raises fail-fast if a *selected* slot requires a missing key.
    anthropic_api_key: SecretStr | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    xai_api_key: SecretStr | None = Field(default=None, alias="XAI_API_KEY")
    openai_api_key: SecretStr | None = Field(default=None, alias="OPENAI_API_KEY")
    google_api_key: SecretStr | None = Field(default=None, alias="GOOGLE_API_KEY")

    # Local LLM (Ollama by default). Used by the 'local' provider; HTTP server with
    # an OpenAI-compatible /v1/chat/completions endpoint.
    ollama_base_url: str = Field("http://localhost:11434", alias="OLLAMA_BASE_URL")

    stale_running_threshold_minutes: int = Field(60, alias="STALE_RUNNING_THRESHOLD_MINUTES")
    upsert_batch_size: int = Field(500, alias="UPSERT_BATCH_SIZE")

    trigger: str = Field("local", alias="PIPELINE_TRIGGER")

    force_full_backfill: bool = Field(False, alias="FORCE_FULL_BACKFILL")
