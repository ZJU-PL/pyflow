# Heap Analysis Module

`pyflow.analysis.alias.flow_sensitive` provides PyFlow's standalone heap, alias, escape, and
points-to model. It is used by optimization passes, semantic queries, CLI
debugging, and IFDS-style clients that need operation-level heap effects.

The analysis is flow-sensitive and path-insensitive. It preserves precise
attribute and literal container paths when possible, falls back to wildcard
selectors for dynamic accesses, and uses escape/reference-count facts to decide
whether writes can be strong or must be weak.

## Heap vs Pointer Analysis

`pyflow.analysis.alias.flow_sensitive` and `pyflow.analysis.alias.kcfa` both answer points-to style
questions, but they target different consumers.

| Area | `analysis.heap` | `analysis.pointer` |
| --- | --- | --- |
| Primary goal | Heap effects, aliases, escapes, and strong/weak update safety for PyFlow passes | General k-CFA pointer/call-graph analysis migrated from PythonStAn |
| Flow model | Flow-sensitive over PyFlow IR, path-insensitive at joins | Effectively flow-insensitive points-to solving: constraints and pointer-flow edges are solved to a monotone union fixpoint |
| Context model | Optional allocation/context sensitivity through `HeapPolicy` | k-CFA context sensitivity, configured by `k` / `context_policy` |
| Updates | Tracks strong vs weak writes, deletes, local unaliasing, and wildcard contamination | Points-to sets only grow; stores add flow edges from source variables to fields |
| Query surface | `PointsToGraph` with `may_alias`, `aliased`, escape, ref-count, and update-policy queries | `PointerAnalysisResult.points_to(name)` and call edges, with raw PythonStAn result access |
| Integration | Uses PyFlow program/code objects and feeds optimization/query APIs | Starts from source text and runs the PythonStAn lowering pipeline |

Use heap analysis when a PyFlow pass needs order-aware heap state, escape facts,
or proof that a write can overwrite previous facts. Use pointer analysis when
you need a source-level, context-sensitive over-approximation of possible
objects/callees and do not need per-program-point update semantics.

## Module Layout

```text
heap/
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
```

The application pass registers the result under the `"heap"` analysis key:

```python
from pyflow.application.passes import HeapAnalysisPass
```

CLI-oriented inspection lives in `pyflow.cli.heap`.

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

Default settings favor useful precision without making every nested write
strong. Use `HeapPolicy.fast()` for coarse analysis and `HeapPolicy.precise()`
when downstream consumers benefit from more structure.

## Important Invariants

- Canonicalize raw storage through `HeapAbstraction.location_for_raw()` before
  creating heap facts.
- Treat `PointsToGraph` as a snapshot. Mutate/query live state through
  `HeapAnalysis.heap` or `HeapAbstraction`, then extract a new graph.
- Unknown locations are conservative for `may_alias()` and local-leaning for
  `never_escapes()`; callers that require proof should first check membership
  in the graph.
- Dynamic attribute/subscript writes use wildcard selectors and can contaminate
  overlapping precise paths.
- Strong updates require a precise, non-escaped, singleton-like root unless the
  policy explicitly allows strong updates for fresh nested locations.

## Tests

Focused heap tests live under `tests/analysis/alias/flow_sensitive`:

```bash
pytest tests/analysis/alias/flow_sensitive
```
