# Checker tests

The checker tests mirror the package layout under `src/pyflow/checker`:

- `ast_dataflow/` follows the frontend, domain, modeling, semantics, solver,
  and detector packages.
- `ast_rules/` separates framework tests in `core/` from individual security
  rules in `checkers/`.
- `ifds/` covers IFDS taint analysis, shadow scanning, and class pollution.
- `cpg/` covers CPG security analysis.
- `capability/` and `supply_chain/` follow their complete checking subsystems.
- `formatters/` and `llm/` correspond directly to their source packages.
- `taint_engines/` checks behavioral agreement between AST dataflow, CPG, and
  IFDS taint implementations.
- `external_corpora/` contains attributed cases adapted from other security
  analyzers; each upstream project gets its own named subdirectory.

Shared fixtures for the checker tree remain in `conftest.py`.

Run all checker tests with:

```console
pytest tests/checker
```

For a focused subsystem, pass its mirrored directory, for example:

```console
pytest tests/checker/ast_dataflow
pytest tests/checker/ast_rules
pytest tests/checker/ifds
pytest tests/checker/cpg
pytest tests/checker/taint_engines
pytest tests/checker/supply_chain
```
