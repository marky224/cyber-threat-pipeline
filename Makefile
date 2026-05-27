# cyber-threat-pipeline — Makefile
#
# Single source of truth for stage commands. Local dev and CI both invoke
# these targets. The legacy main.py entrypoint is retired per Q11.
#
# Phase-status legend:
#   [ready]  — works today, exercised by CI.
#   [phaseN] — wired but depends on code that lands in build phase N.
#              The target will fail with a clear error until that phase
#              ships; the matching spec lives in _private/specs/.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Help — print available targets
# ---------------------------------------------------------------------------
.PHONY: help
help:
	@echo "cyber-threat-pipeline — make targets"
	@echo ""
	@echo "  Setup & quality (ready)"
	@echo "    install         uv sync the dev env (Python 3.12)"
	@echo "    lint            ruff check + format check"
	@echo "    typecheck       mypy (strict)"
	@echo "    test            pytest"
	@echo "    ci              lint + typecheck + test"
	@echo "    precommit       run pre-commit on all files"
	@echo ""
	@echo "  Pipeline stages (each wired to its phase)"
	@echo "    ingest          [phase 2] OTX → Neon raw schema"
	@echo "    transform       [phase 3] dbt build (isolated transform/ env)"
	@echo "    analysis        [phase 4] LLM analyst brief (Grok + Claude)"
	@echo "    report          [phase 5] build Evidence site + deploy to S3/CloudFront"
	@echo "    all             ingest → transform → analysis → report"
	@echo ""
	@echo "  Housekeeping"
	@echo "    clean           remove caches and build artifacts"

# ---------------------------------------------------------------------------
# Setup & quality — [ready]
# ---------------------------------------------------------------------------
.PHONY: install
install:
	uv sync --frozen

.PHONY: lint
lint:
	uv run ruff check .
	uv run ruff format --check .

.PHONY: typecheck
typecheck:
	uv run mypy

.PHONY: test
test:
	uv run pytest

.PHONY: ci
ci: lint typecheck test

.PHONY: precommit
precommit:
	uv run pre-commit run --all-files

# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

# [phase 2] Ingestion — spec: _private/specs/02-ingestion.md
# Reads NEON_DATABASE_URL + OTX_API_KEY from the environment.
.PHONY: ingest
ingest:
	uv run python -m cyber_threat_pipeline.ingestion

# [phase 3] Transform — spec: _private/specs/03-dbt-transform.md
# dbt lives in its own isolated env under transform/ (own pyproject + venv).
# The transform/ directory's Makefile-or-uv project owns the dbt invocation;
# this top-level target shells out to it so the contract stays one command.
.PHONY: transform
transform:
	$(MAKE) -C transform build

# [phase 4] Analyst brief — spec: _private/specs/04-analysis-llm.md
# Reads NEON_DATABASE_URL + ANTHROPIC_API_KEY + XAI_API_KEY.
# Writes markdown into reporting/pages/.
.PHONY: analysis
analysis:
	uv run python -m cyber_threat_pipeline.analysis

# [phase 5] Reporting + deploy — spec: _private/specs/05-reporting-evidence.md
# Evidence is a Node project; build is `npm run build` inside reporting/.
# Deploy is `aws s3 sync` + CloudFront invalidation (creds via OIDC in CI;
# AWS_PROFILE locally).
.PHONY: report
report:
	# Subshell so .ONESHELL doesn't leak `cd reporting` into the
	# following aws lines (which would resolve `reporting/build/` to
	# `reporting/reporting/build/` and fail with "path does not exist").
	(cd reporting && npm ci && npm run build)
	aws s3 sync reporting/build/ "s3://$$REPORT_BUCKET/" --delete
	aws cloudfront create-invalidation \
		--distribution-id "$$CLOUDFRONT_DISTRIBUTION_ID" \
		--paths "/*"

.PHONY: all
all: ingest transform analysis report

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -rf .ruff_cache .mypy_cache .pytest_cache .coverage htmlcov build dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +
	rm -rf transform/target transform/logs transform/dbt_packages
	rm -rf reporting/build reporting/.evidence reporting/node_modules
