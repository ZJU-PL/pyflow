# Migration Notes: PythonStAn -> PyFlow Pointer Analysis

The implementation under `_pythonstan/` is vendored from PythonStAn. Import-path
rewrites and other mechanical relocation changes are omitted here. This document
summarizes only intentional behavioral, structural, and compatibility changes.

## Analysis behavior

- Attribute lookup follows the Python MRO when resolving inherited fields and
  methods, including multiple inheritance. Class-hierarchy updates now invalidate
  cached MRO information correctly.
- Generator and coroutine wrapper objects are unwrapped when resolving their
  underlying callable.
- Global, closure, cell, and class-local variables are resolved in their proper
  scopes. Per-class variable tracking prevents bindings from leaking between
  class bodies.
- Module attributes use global-variable semantics, and missing globals fall back
  to the defining module scope.
- Heap identities use the immediate scope rather than collapsing allocations to
  module scope.
- Name-to-name stores emit copy constraints so points-to information is not lost.
- `**kwargs` entries are preserved throughout IR translation and call
  constraints.
- Closure analysis runs for each module before pointer analysis consumes its
  results.

## Python semantic coverage

- Added allocation modeling for `object()`.
- Added models for `dict(iterable)`, named keyword construction, and
  `dict(**kwargs)`.
- Added standard-library stubs that preserve important dataflow, call-graph, and
  aliasing behavior for commonly used modules.
- Added a function-object `name` property used by the public query bridge.

## Solver and infrastructure

- Class-hierarchy information is wired into the solver state.
- Builtin initialization is centralized in the solver.
- Module-field handling compares `FieldKind` enum values correctly.
- The processor base class uses boolean fallback implementations instead of
  ellipsis bodies.
- Configuration supports JSON and treats YAML support as optional.
- Stub discovery accounts for the vendored package layout.
- The unavailable abstract-interpretation driver now fails explicitly with
  `NotImplementedError`.
- A no-op debug monitor preserves the expected solver interface.
- Missing package initializers and SPDX headers were added where required.

## Main affected areas

| Area | Main changes |
|---|---|
| `state.py`, `class_hierarchy.py` | MRO resolution, callable unwrapping, global fallback |
| `solver.py`, `analysis.py` | hierarchy wiring, builtin setup, variable-kind fixes |
| `ir_translator.py`, `constraints.py` | class-local tracking, copy flow, `**kwargs` |
| `builtin_api_handler.py` | `object()` and `dict()` models |
| `heap_model.py` | scope-sensitive heap identity |
| `pipeline.py` | per-module closure ordering |
| `world/` | optional dependencies and vendored-path compatibility |
| `stubs/stdlib/` | standard-library dataflow models |

Focused regression tests cover inheritance and MRO behavior, dictionary
construction, standard-library resolution, module attributes, closures, and
context-sensitive pointer propagation.
