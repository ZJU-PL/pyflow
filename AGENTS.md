# AGENTS.md

This file is for coding agents working in the `pyflow` repository. It is not a
general project introduction; it is an execution guide for making safe,
high-signal changes in this codebase.

## Repository Summary

PyFlow is a research-oriented static analysis framework for Python. The repository includes:

- analysis infrastructure such as CFG, call graph, IFDS, IPA, CPA, shape, and
  lifetime analysis
- optimization passes and pipeline orchestration
- a public API for entrypoint declarations and semantic queries
- CLI commands for optimization, call graph generation, IR dumping, security,
  and dataflow
- a large test suite with both focused unit tests and slower integration tests

## Environment

- Python: `>=3.10`
- Main package root: `src/pyflow`
- Test root: `tests`
- Package install:
  - `pip install -e .`
  - `pip install -e ".[dev]"`

## Primary Repo Layout

- `src/pyflow/analysis`
  Core analysis engines and graph/dataflow infrastructure.
- `src/pyflow/application`
  Program context, pass manager, pipeline wiring, and high-level orchestration.
- `src/pyflow/api`
  Public API for entrypoint declarations and query services.
- `src/pyflow/checker`
  Pattern-based and semantic security analysis.
- `src/pyflow/cli`
  User-facing command-line entrypoints.
- `src/pyflow/frontend`
  Source extraction, dependency resolution, and object loading.
- `src/pyflow/language`
  Python IR/AST support and module utilities.
- `src/pyflow/optimization`
  Optimization passes and dataflow rewrites.
- `tests`
  Subsystem-focused tests plus integration and API regression coverage.

## Existing Tooling

The repo already defines common commands in `Makefile`:

- `make install`
- `make install-dev`
- `make test`
- `make test-integration`
- `make test-cov`
- `make format`
- `make lint`
- `make type-check`
- `make docs`

Equivalent direct commands commonly used in CI:

- `pytest`
- `pytest -m integration tests/integration`
- `pytest --cov=pyflow --cov-report=xml --cov-report=term`
- `flake8 src/ tests/`
- `mypy src/`

## Testing Guidance

Start with the smallest relevant suite.

Examples:

- API query changes:
  - `pytest -q tests/api/test_query_api_regressions.py`
  - `pytest tests/api`
- CLI behavior:
  - `pytest tests/cli`
- IFDS/dataflow changes:
  - `pytest tests/ifds`
  - `pytest tests/cli/test_dataflow.py`
- frontend/module resolution:
  - `pytest tests/frontend`
  - `pytest tests/modules`
- optimization passes:
  - `pytest tests/optimization`
- security checker changes:
  - `pytest tests/checker`

Run broader coverage when the change crosses subsystem boundaries.

Integration tests are excluded by default in `pytest` config. Run them
explicitly when needed:

- `pytest -m integration tests/integration`


## CLI Notes

CLI entrypoints live under `src/pyflow/cli`. If you change CLI flags or output:

- update or add focused tests in `tests/cli`
- keep help text and default behavior consistent across subcommands
- avoid breaking machine-consumable output silently


## Documentation and Build Notes

- `README.md` is the primary top-level user document.
- Docs live in `docs/`.

## Change Checklist

Before finishing a change, do the relevant subset of the following:

- run focused tests for the edited subsystem
- run broader tests if the change spans multiple layers
- update regression tests for bug fixes
- update docs for user-visible changes