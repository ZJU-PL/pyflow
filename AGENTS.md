# AGENTS.md

Execution guide for coding agents working on PyFlow, a Python static analysis
framework. Python >=3.10; install development dependencies with
`python -m pip install -e ".[dev]"` in the project virtual environment.

## Layout

Code lives in `src/pyflow`; tests live in `tests`.

- `ir`, `language`: intermediate representations and Python language support.
- `analysis`: CFG, call graph, IFDS, IPA, CPA, shape, and lifetime analysis.
- `application`: program context, pass manager, and pipelines.
- `api`: entrypoint declarations and semantic queries.
- `frontend`: source extraction, dependency resolution, and object loading.
- `checker`: pattern-based and semantic security analysis.
- `cli`: command-line entrypoints.

## Validation

Start with the smallest relevant suite; broaden coverage for changes spanning
subsystems. Add regression tests for bug fixes and document user-visible changes.

| Change | Focused tests |
| --- | --- |
| API queries | `pytest -q tests/api/test_query_api_regressions.py`, then `pytest tests/api` |
| CLI | `pytest tests/cli` |
| IFDS/dataflow | `pytest tests/ifds tests/cli/test_dataflow.py` |
| Frontend/modules | `pytest tests/frontend tests/modules` |
| Optimization | `pytest tests/optimization` |
| Security checkers | `pytest tests/checker` |

`pytest` runs the default non-integration suite. Run integration tests explicitly
with `pytest -m integration tests/integration`.

Use the Black version pinned in `pyproject.toml`: `make format` formats `src` and
`tests`; `black --check src tests` checks formatting. Other Makefile targets:
`install`, `install-dev`, `test`, `test-integration`, `test-cov`, `lint`,
`type-check`, and `docs`.

For CLI changes, update focused tests, keep help text and defaults consistent,
and preserve machine-consumable output compatibility.

## Releases

Follow [RELEASING.md](RELEASING.md). Publish through the existing GitHub Actions
Trusted Publishing workflow by pushing a version tag. Prefer this workflow over
local Twine uploads; never republish an existing PyPI version.
