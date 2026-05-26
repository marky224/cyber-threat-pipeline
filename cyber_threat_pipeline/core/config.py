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

    stale_running_threshold_minutes: int = Field(60, alias="STALE_RUNNING_THRESHOLD_MINUTES")
    upsert_batch_size: int = Field(500, alias="UPSERT_BATCH_SIZE")

    trigger: str = Field("local", alias="PIPELINE_TRIGGER")

    force_full_backfill: bool = Field(False, alias="FORCE_FULL_BACKFILL")
