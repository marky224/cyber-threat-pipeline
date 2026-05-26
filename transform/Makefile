# transform/ — dbt Core build for cyber-threat-pipeline.
#
# Invoked by the top-level `make transform`; lives in its OWN uv env so dbt
# deps never bleed into the app env (locked decision Q3).

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := build

DBT_PROFILE := cyber_threat_pipeline
DBT_TARGET  := prod
DBT_FLAGS   := --profile $(DBT_PROFILE) --target $(DBT_TARGET) --profiles-dir .

.PHONY: install
install:
	uv sync --frozen

.PHONY: deps
deps: install
	uv run dbt deps

.PHONY: build
build: deps
	uv run dbt build $(DBT_FLAGS)

.PHONY: test
test: deps
	uv run dbt test $(DBT_FLAGS)

.PHONY: docs
docs: deps
	uv run dbt docs generate $(DBT_FLAGS)

.PHONY: clean
clean:
	rm -rf target logs dbt_packages
