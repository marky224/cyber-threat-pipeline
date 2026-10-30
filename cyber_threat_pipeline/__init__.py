"""cyber_threat_pipeline — AlienVault OTX → Neon → dbt → Evidence + Grafana.

Subpackages
-----------
core        Cross-cutting helpers (config, db, logging) shared by ingestion + analysis.
ingestion   Extract from OTX, transform with pandas, idempotent upsert into Neon raw schema.
enrichment  CISA KEV catalog + FIRST EPSS scores for the corpus's CVE ids into Neon raw schema
            (bounded downloads, validated whole, warn-only).
analysis    Post-dbt LLM analyst brief (Grok + Claude side-by-side).

The build-grade specs in ``_private/specs/`` govern each subpackage.
"""

__version__ = "0.1.0"
