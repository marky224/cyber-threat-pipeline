"""Smoke test: package + subpackages import cleanly. Keeps CI green from day one."""

from __future__ import annotations

import cyber_threat_pipeline
from cyber_threat_pipeline import analysis, core, ingestion


def test_package_version_is_defined() -> None:
    assert isinstance(cyber_threat_pipeline.__version__, str)
    assert cyber_threat_pipeline.__version__


def test_subpackages_import() -> None:
    assert core.__name__ == "cyber_threat_pipeline.core"
    assert ingestion.__name__ == "cyber_threat_pipeline.ingestion"
    assert analysis.__name__ == "cyber_threat_pipeline.analysis"
