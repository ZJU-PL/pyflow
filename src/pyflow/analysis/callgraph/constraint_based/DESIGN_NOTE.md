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
- Reflection-aware attribute recovery:
  - dynamic string propagation for reflective names,
  - `setattr`/`delattr` heap updates,
  - `importlib.import_module`/`__import__` module abstraction recovery.
- Closure-captured values:
  - nested function symbol collection,
  - capture propagation from defining scopes to nested scopes.
- Type-directed pruning:
  - parameter and annotated assignment filtering from resolvable hints,
  - runtime guard refinement for `isinstance`, `issubclass`, `TypeGuard`, and `None` checks,
  - expression-level narrowing via `typing.cast`,
  - protocol-aware structural matching for annotated parameters.
- Python protocol/library hooks:
  - explicit and zero-argument `super(...)` receiver recovery,
  - dict dispatch helpers via `get`, `setdefault`, and `pop`,
  - higher-order builtin callback modeling for `map`, `filter`, `sorted`, and `reduce`,
  - exception-handler name refinement for declared exception types,
  - lightweight registry/callback installation via `register("key")(fn)` and decorator-style registrations,
  - `functools.singledispatch` plus `.register(...)` implementation dispatch.
- Explainability for dynamic uncertainty:
  - explicit summary nodes `<dynamic>.<scope>@line:col` when unresolved call
    targets remain.
- Async/control-flow support:
  - `await` expressions and `async with` blocks are analyzed,
  - `match/case` branch bodies are included in scope/block analysis.
- Solver safety controls:
  - configurable fixpoint iteration cap (`fixpoint_max_iterations`),
  - optional truncation warning (`warn_on_fixpoint_truncation`).
  - deterministic scheduling (`requeue_policy=fifo|priority`),
  - bounded widening (`max_values_per_binding`, `max_contexts_per_scope`),
  - precision-safe bypass (`strict_precision_mode=True`),
  - solver telemetry (`emit_solver_stats=True`).

## Solver Telemetry
The builder exposes `solver_stats` with:
- `iterations`
- `states_analyzed`
- `states_requeued`
- `max_queue_size`
- `bindings_capped`
- `contexts_capped`
- `dynamic_summary_edges`
- `closure_context_fallbacks`

When `extract_value_flow_graph_constraint(..., emit_solver_stats=True)` is used,
stats are also emitted in a `__solver_stats__` debug entry.

## Current Limitations
- Container precision is intentionally coarse (element sets are merged).
- Descriptor semantics are partial (no full metaclass/descriptor edge cases).
- Dynamic constructs such as `exec` and fully dynamic imports remain approximate.
