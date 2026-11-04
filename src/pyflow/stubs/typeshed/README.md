# Vendored typeshed

This directory is a snapshot of the typeshed bundled with **mypy 2.5.0+dev**,
copied on 2026-11-04.  It provides PyFlow's default stdlib and bundled
third-party type information.

- Upstream: <https://github.com/python/typeshed>
- Layout: `stdlib/` and `stubs/`
- License: Apache-2.0, see [`LICENSE`](LICENSE)

PyFlow consumes this through `pyflow.language.modules.type_stubs`:
`default_typeshed_roots()` points here, `StubResolver` selects version-specific
declarations for the active Python version, and `TypeInfoService` parses stubs
lazily.

## Updating

Replace this directory with the typeshed snapshot from the target mypy
release, keep `LICENSE`, then run:

```bash
pytest -q tests/analysis/typeinfo/test_vendored_typeshed_models.py
pytest -q tests/analysis/typeinfo
```

Do not edit the vendored files individually.  PyFlow-specific behavior belongs
in the stub parser/service layers, not in the snapshot.
