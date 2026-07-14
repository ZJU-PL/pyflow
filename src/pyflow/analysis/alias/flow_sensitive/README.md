# Flow-Sensitive Heap Analysis Module

`pyflow.analysis.alias.flow_sensitive` provides PyFlow's standalone heap, alias, escape, and
points-to model. It is used by optimization passes, semantic queries, CLI
debugging, and IFDS-style clients that need operation-level heap effects.

The analysis is flow-sensitive and path-insensitive. It preserves precise
attribute and literal container paths when possible, falls back to wildcard
selectors for dynamic accesses, and uses abstract cardinality, path precision,
and receiver ambiguity to decide whether writes can be strong or must be weak.

Flow state includes both heap contents and the local binding environment.
Branches are analyzed from independent snapshots and join each local's possible
roots, escape state, and live-reference metadata before subsequent operations.
Abrupt exits (`return`, `raise`, `break`, and `continue`) are carried separately
from normal successors, including through `try`/`except`/`finally`.

For bounded, closed-world IR, resolved direct calls preserve per-result return
slots, short-circuit expressions join skipped and executed side effects, and
nested collection/function values retain their element, default, and closure
reachability. Calls are analyzed against the caller's current heap, call-site
allocation contexts distinguish repeated callee allocations, and dead callee
locals do not leak into caller reference counts. Unconstrained parameters and
unknown return roots conservatively may alias live value objects.

The transfer follows Python evaluation order for assignments, calls, dynamic
attributes/subscripts, short-circuit expressions, annotations, yields, awaits,
and definition headers. It models lexical class scopes, closure-cell identity,
global/nonlocal declarations, packed and spread arguments, exception prefixes,
and the lifetime of exception-handler targets. Exact writes to one singleton
root are strong even when that object escapes; writes through a branch-joined
set of possible receivers are weak.

The soundness scope excludes unknown or reflective calls, recursive cycles, and
loops that fail to converge within the configured iteration bound. Native or
dynamic Python behavior not represented by an IR operation needs an explicit
model. The points-to domain tracks reference-bearing heap objects; scalar
values such as integers and strings are evaluated for ordering and effects but
are not represented as mutable heap roots.

## flow_sensitive vs kcfa

`pyflow.analysis.alias.flow_sensitive` and `pyflow.analysis.alias.kcfa` both answer points-to style
questions, but they target different consumers.

| Area | `analysis.alias.flow_sensitive` | `analysis.alias.kcfa` |
| --- | --- | --- |
| Primary goal | Heap effects, aliases, escapes, and strong/weak update safety for PyFlow passes | General k-CFA pointer/call-graph analysis migrated from PythonStAn |
| Flow model | Flow-sensitive over PyFlow IR, path-insensitive at joins | Effectively flow-insensitive points-to solving: constraints and pointer-flow edges are solved to a monotone union fixpoint |
| Context model | Optional allocation/context sensitivity through `HeapPolicy` | k-CFA context sensitivity, configured by `k` / `context_policy` |
| Updates | Tracks strong vs weak writes, deletes, local unaliasing, and wildcard contamination | Points-to sets only grow; stores add flow edges from source variables to fields |
| Query surface | `PointsToGraph` with `may_alias`, `aliased`, escape, ref-count, and update-policy queries | `PointerAnalysisResult.points_to(name)` and call edges, with raw PythonStAn result access |
| Integration | Uses PyFlow program/code objects and feeds optimization/query APIs | Starts from source text and runs the PythonStAn lowering pipeline |

Use the analysis when a PyFlow pass needs order-aware heap state, escape facts,
or proof that a write can overwrite previous facts. Use pointer analysis when
you need a source-level, context-sensitive over-approximation of possible
objects/callees and do not need per-program-point update semantics.

## Module Layout

```text
flow_sensitive/
├── __init__.py          # Public exports
├── model.py             # Heap objects, locations, selectors, policies, writes
├── abstraction.py       # Canonicalization, alias classes, escape/update policy
├── heap_effects.py      # IR operation -> read/write/delete/escape effects
├── heap_state.py        # Flow-sensitive value state for transfer
├── heap_summary.py      # Procedure-level summary helpers
├── transfer.py          # Standalone forward transfer engine
├── points_to_graph.py   # Read-only query snapshot
├── intrinsics.py        # Built-in call and collection mutation models
├── heap_analysis.py     # High-level HeapAnalysis facade
└── README.md            # This file
```

## Main Entry Points

- `HeapAnalysis`: high-level engine. Run this when a pass or CLI command needs a
  reusable points-to graph.
- `PointsToGraph`: read-only query surface for alias, escape, reference-count,
  and strong-update checks.
- `HeapAbstraction`: mutable canonical heap model shared by transfer and effect
  extraction.
- `HeapEffectBuilder`: converts Python IR operations into analysis-neutral heap
  effects for IFDS clients.
- `HeapPolicy`: precision and conservatism knobs for allocation, field,
  container, context, recency, and escape behavior.

## Basic Usage

```python
from pyflow.analysis.alias.flow_sensitive import HeapAnalysis, HeapPolicy

analysis = HeapAnalysis(policy=HeapPolicy.precise())
graph = analysis.analyze(compiler, program)

if graph.may_alias(loc_a, loc_b):
    ...

if graph.strong_update_possible(loc):
    ...

# Final-state heap contents.
values = graph.values_at(object_field)

# Operation-specific pre/post state.
before = graph.values_at(object_field, operation, before=True)
after = graph.values_at(object_field, operation)
```

The application pass registers the result under the `"heap"` analysis key:

```python
from pyflow.application.passes import HeapAnalysisPass
```

CLI-oriented inspection lives in `pyflow.cli.alias`.

## Core Model

The heap model separates storage roots from access paths:

- `HeapObject` is an abstract root such as a local, global, parameter,
  allocation, return value, or external object.
- `HeapLocation` is a root plus zero or more selectors.
- `HeapSelector` represents an attribute, item, index, or wildcard path segment.
- `HeapWrite` records the target location and whether the write is strong or
  weak.

Alias classes are tracked at root allocation sites. Nested paths inherit root
alias information and compare selectors to answer must-alias and may-alias
queries.

## Precision Rules

`HeapPolicy` controls how much structure the model keeps:

- allocation sensitivity: none, site, procedure, or context
- field sensitivity: none, named fields, or bounded paths
- container sensitivity: none, wildcard, literal keys, or bounded indices
- escape handling for returns and unresolved calls
- whether fresh nested locations can receive strong updates

Default settings strongly update exact paths under a singleton root. Imprecise
selectors, summary roots, and writes through multiple possible receiver roots
remain weak. Use `HeapPolicy.fast()` for coarse analysis and
`HeapPolicy.precise()` when downstream consumers benefit from unbounded paths
and context sensitivity.

## Important Invariants

- Canonicalize raw storage through `HeapAbstraction.location_for_raw()` before
  creating heap facts.
- Treat `PointsToGraph` as a snapshot. It contains final heap values and
  immutable pre/post snapshots for analyzed IR nodes; mutate live metadata
  through `HeapAnalysis.heap` or `HeapAbstraction`, then extract a new graph.
- Unknown locations are conservative for `may_alias()`, escape, and
  reference-count queries; callers that require proof should first check
  membership in the graph.
- Dynamic attribute/subscript writes use wildcard selectors and can contaminate
  overlapping precise paths.
- Control-flow joins must combine both `HeapState` values and the corresponding
  `HeapEnvironment`; restoring only heap contents loses branch-local aliases.
- Strong nested updates require a precise singleton root and one possible
  receiver for that operation. Escape and the number of access paths do not
  change the cardinality of a singleton abstract object.

## Tests

Focused heap tests live under `tests/analysis/alias/flow_sensitive`:

```bash
pytest tests/analysis/alias/flow_sensitive
```
