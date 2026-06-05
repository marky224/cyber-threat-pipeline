"""Settings env-var parsing — regression coverage for empty-string values.

Schedule-triggered CI runs inject ``FORCE_FULL_BACKFILL=""`` because
``workflow_dispatch`` input defaults don't apply to the ``schedule`` event.
Empty env vars must fall back to field defaults (``env_ignore_empty=True``)
rather than crash ``Settings()`` at construction. No DB required.
"""

from __future__ import annotations

import pytest

from cyber_threat_pipeline.core.config import Settings

# Minimal required fields so Settings() constructs without a DB or a real .env.
_REQUIRED = {
    "NEON_DATABASE_URL": "postgresql://u:p@localhost:5432/db",
    "OTX_API_KEY": "test-key",
}


def _build(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    for key, value in _REQUIRED.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("FORCE_FULL_BACKFILL", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    # _env_file=None keeps the test hermetic against a developer's local .env.
    return Settings(_env_file=None)


def test_empty_force_full_backfill_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression: a blank value (as injected on `schedule`) must not crash.
    settings = _build(monkeypatch, FORCE_FULL_BACKFILL="")
    assert settings.force_full_backfill is False


def test_force_full_backfill_unset_defaults_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _build(monkeypatch)
    assert settings.force_full_backfill is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("false", False),
        ("true", True),
        ("FALSE", False),
        ("TRUE", True),
        ("0", False),
        ("1", True),
    ],
)
def test_force_full_backfill_parses_explicit_values(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
    expected: bool,
) -> None:
    settings = _build(monkeypatch, FORCE_FULL_BACKFILL=value)
    assert settings.force_full_backfill is expected
