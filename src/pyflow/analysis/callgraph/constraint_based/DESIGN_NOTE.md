# Constraint-Based Call Graph Design

## Overview
The implementation is split into a subpackage with a mixin-based architecture
and an IR publication bridge (`../publication.py`):

- `model.py`: abstract values (`AbstractValue`), scope/class/function metadata,
  `AnalysisOptions`, `SolverStats`, and `CallSiteEdgeIndex`.
- `engine.py`: `ConstraintCallGraphBuilder` orchestrating the mixins and public
  result extraction (`build`, `call_site_edge_index`, `to_value_flow_graph`).
- `api.py`: public API entry points (`extract_call_graph_constraint`,
  `analyze_file_constraint`, `extract_value_flow_graph_constraint`, directory
  and recursive scan helpers).
- `_modules.py` (`_ModuleAnalysisMixin`): module loading, monorepo/`src`/`lib`
  import-root discovery, PEP 263 decoding, and bounded transitive import loading.
- `_symbols.py` (`_SymbolAnalysisMixin`): symbol collection (functions, classes,
  lambdas, decorators, module re-exports) and scope initialization.
- `_solver.py` (`_FixpointSolverMixin`): worklist fixpoint scheduling, 5-tier
  entry-module scope priority, iteration/wall-clock budgets
  (`fixpoint_max_iterations`, `fixpoint_max_seconds`), and truncation metadata.
- `_semi_naive.py`: incremental delta tracking and dependency-driven requeuing
  for semi-naive fixpoint propagation.
- `_statements.py` (`_StatementAnalysisMixin`): statement/block evaluation
  (assignments, control flow, `try`/`except*`, `match`/`case`, `with`/`async with`,
  imports, deletions, decorators).
- `_expressions.py` (`_ExpressionAnalysisMixin`): AST expression evaluation to
  abstract value sets (calls, attributes, subscripts, containers, comprehensions,
  f-strings, slices, lambdas).
- `_types.py` (`_TypeAnalysisMixin`): annotation, protocol, `TypeGuard`/`TypeIs`,
  registry, and `singledispatch` resolution, with lazy fallback to `TypeInfo`
  facts via `TypeFactBridge`.
- `_call_binding.py` (`_CallBindingMixin`): positional/keyword/`*args`/`**kwargs`
  parameter binding, default evaluation, and descriptor binding.
- `_state.py` (`_StateAnalysisMixin`): scope/context state joins, widening caps,
  and container/field heap state.
- `_call_targets.py` (`_CallTargetMixin`): call dispatch, C3 MRO resolution,
  dynamic summary nodes, and builtin/stdlib callback models.
- `../publication.py`: publishes resolved call-site targets into `IRCatalog`
  (`Capabilities.CALL_TARGETS` / `Capabilities.CALL_TARGET_CODES`) matched by
  source span for IFDS and query consumers.

The `ConstraintCallGraphBuilder` class in `engine.py` composes nine mixins:

```python
class ConstraintCallGraphBuilder(
    _ModuleAnalysisMixin,
    _SymbolAnalysisMixin,
    _FixpointSolverMixin,
    _StatementAnalysisMixin,
    _ExpressionAnalysisMixin,
    _TypeAnalysisMixin,
    _CallBindingMixin,
    _StateAnalysisMixin,
    _CallTargetMixin,
):
    ...
```

The analysis propagates abstract values (functions, classes, instances, bound
methods, modules) through assignments, calls, and returns. Within a
scope-context it is flow-insensitive: assignments accumulate may-values, and
the scope is revisited until values discovered later in the body are visible at
earlier uses. This deliberately trades ordering precision for recall and a
monotone soundness story.

Type annotations, `typing.cast`, and recognized type guards remain trusted
refinement contracts. They may prune values that violate those contracts; this
is intentional for typed-code analysis rather than a claim about untyped
Python runtime enforcement.

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
  - local reassignments are merged, so an individual call site may contain
    targets assigned before or after it.
- Recall:
  - maintained for direct calls, aliases, dynamic dispatch, module indirection,
    and `getattr(obj, "name")`.
  - loop-carried, exceptional-path, and deletion-sensitive bindings are kept as
    may-values rather than strongly killed.
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
- Type-directed pruning and TypeInfo enrichment:
  - parameter and annotated assignment filtering from resolvable hints,
  - runtime guard refinement for `isinstance`, `issubclass`, `TypeGuard`, `TypeIs`, and `None` checks,
  - expression-level narrowing via `typing.cast`,
  - protocol-aware structural matching for annotated parameters,
  - lazy `TypeInfo` fact bridge (`use_typeinfo_facts=True`) for resolving type
    aliases, `TYPE_CHECKING` annotations, cross-module typed returns, and
    annotated class attributes when raw local AST lookup is insufficient.
- Python protocol/library hooks:
  - explicit and zero-argument `super(...)` receiver recovery,
  - dict dispatch helpers via `get`, `setdefault`, and `pop`,
  - higher-order builtin callback modeling for `map`, `filter`, `sorted`, and `reduce`,
  - exception-handler name refinement for declared exception types,
  - lightweight registry/callback installation via `register("key")(fn)` and decorator-style registrations,
  - `functools.singledispatch` plus `.register(...)` implementation dispatch.
- Explainability for dynamic uncertainty:
  - explicit summary nodes `<dynamic>.<scope>@line:col` when unresolved call
    targets remain, separated from concrete edges in unified JSON reports.
- Async/control-flow support:
  - `await` expressions, `async with`, `try`/`except*`, f-string format specs,
    slice expressions, and `match`/`case` (preserving subsequent cases after
    refutable patterns) are analyzed.
- Solver safety controls:
  - semi-naive incremental propagation (`_semi_naive.py`) and 5-tier entry-module
    scope priority so entry scopes converge ahead of transitively imported modules,
  - configurable fixpoint iteration cap (`fixpoint_max_iterations`) and
    wall-clock solver/import budget (`fixpoint_max_seconds`),
  - optional truncation warning (`warn_on_fixpoint_truncation`) and explicit
    `converged` / `termination_reason` / `diagnostics` reporting,
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
