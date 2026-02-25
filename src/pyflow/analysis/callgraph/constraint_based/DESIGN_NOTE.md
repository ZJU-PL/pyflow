# Constraint-Based Call Graph Design

## Overview
The implementation is split into a subpackage with a mixin-based architecture:

- `model.py`: abstract values, scope metadata, and analysis options.
- `engine.py`: fixed-point solver orchestrating the mixins.
- `api.py`: public API entry points and file helpers.
- `_loader.py`: module loading and import path resolution.
- `_collector.py`: symbol collection (functions, classes) and scope initialization.
- `_analyzer.py`: fixpoint iteration and per-scope/block control-flow analysis.
- `_evaluator.py`: AST expression evaluation to abstract value sets.
- `_resolver.py`: call target invocation, argument binding, MRO computation.

The `ConstraintCallGraphBuilder` class in `engine.py` composes these mixins:

```python
class ConstraintCallGraphBuilder(
    _LoaderMixin,
    _CollectorMixin,
    _AnalyzerMixin,
    _EvaluatorMixin,
    _ResolverMixin,
):
    ...
```

The analysis propagates abstract values (functions, classes, instances, bound
methods, modules) through assignments, calls, and returns.

## Context Modes
- Context-insensitive mode (`context_sensitive=False`):
  - single global context per scope.
  - faster, but can merge flows from unrelated call sites.
- Context-sensitive mode (`context_sensitive=True`):
  - call-site contexts (k-limited call strings, controlled by
    `context_depth`).
  - improves precision by keeping parameter/return facts separated by call
    context.

## Tradeoffs
- Precision:
  - improved for higher-order and indirect call flows in context-sensitive
    mode.
- Recall:
  - maintained for direct calls, aliases, dynamic dispatch, module indirection,
    and `getattr(obj, "name")`.
- Performance:
  - context-sensitive mode increases state space (`scope x contexts`) and
    fixpoint iterations.

## Complexity
Let `S` be number of scopes, `C` discovered contexts, `N` AST size, and `V`
abstract values per symbol:

- Approximate solve cost: `O(iterations * N * alpha)`, where `alpha` is local
  set/join work.
- Context-sensitive upper bound scales roughly with `S * C`.

## Implemented Precision/Recall Upgrades
- Full C3 MRO linearization for class method lookup.
- Richer descriptor behavior:
  - class-field descriptor binding via `__get__`,
  - callable-object invocation via `__call__`.
- Better container/comprehension tracking:
  - list/tuple/set/dict literal containers,
  - list/set/dict/generator comprehensions,
  - subscript read/write propagation for tracked containers.
- Closure-captured values:
  - nested function symbol collection,
  - capture propagation from defining scopes to nested scopes.
- Explainability for dynamic uncertainty:
  - explicit summary nodes `<dynamic>.<scope>@line:col` when unresolved call
    targets remain.

## Current Limitations
- Container precision is intentionally coarse (element sets are merged).
- Descriptor semantics are partial (no full metaclass/descriptor edge cases).
- Dynamic constructs such as `exec` and fully dynamic imports remain approximate.
