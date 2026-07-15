# Flow-Sensitive Heap Analysis Soundness Contract

## Goal and contract

The primary goal is bug finding, not whole-Python verification. Precision work
is accepted when it improves detector recall, false-positive rate,
explainability, or scalability. The supported bounded fragment still follows
the may-analysis contract below; behavior outside it must degrade explicitly.

For bounded PyFlow IR with resolved calls, no recursive activation, and no
loop requiring widening, the analysis is a may analysis:

- `may_alias(a, b)` includes every concrete alias pair.
- `must_alias(a, b)` is true only for a stable singleton/symbolic identity and
  an identical precise selector path. Summary identities never prove must-alias.
- `possible_values_at(location)` includes every known concrete reference and
  reports `includes_unknown` when the value cannot be enumerated.
- `strong_update_possible(location)` requires one precise receiver whose
  abstract root has cardinality `ONE`.
- escape is a may-escape property.

Scalar results are outside the heap domain. They are represented as
explicit non-reference presence and are not conflated with a missing location
or an unknown reference.

## Abstract domains

Heap roots carry independent properties:

- freshness: recent allocation, summary allocation, or unknown;
- cardinality: `ONE`, `MANY`, or `UNKNOWN`;
- escape: local, escaped, external, or unknown.
- identity: singleton, versioned symbolic, or summary.

Allocation-insensitive roots have cardinality `MANY`, even when recency is
enabled. Unknown reads use versioned symbolic identities keyed by the heap path
and the last overlapping mutation; repeated reads therefore remain related
until a write/delete changes that path. Heap queries return `PossibleValues`,
which separates enumerated locations, unknown inclusion, and definite absence.

## Supported bounded IR

| Area | Supported behavior |
| --- | --- |
| Locals/globals/cells | Flow-sensitive binding, deletion, global/nonlocal redirection |
| Lexical scope | Nearest-binding `nonlocal` cells, isolated across unrelated enclosing scopes |
| Fields | Named and wildcard reads/writes/deletes with receiver ambiguity |
| Containers | Literal indices/keys, wildcard elements, slices, mutation and reorder models |
| Control flow | Branch joins, identity-guard narrowing, abrupt exits, exceptions, `try`/`finally`, type switches |
| Calls | Direct and nested finite calls, functions/lambdas, bound methods, callable instances, callback-bearing known natives, common argument-error outcomes |
| Definitions | Definition-time defaults, closures, known decorators, static/class/property descriptors, type aliases |
| Classes | Root-based class aliases, known C3 order, `__new__` identity, compatible `__init__`, metaclass hooks, `super`, descriptor/subclass hooks |
| Protocols | Known attribute/item, descriptor, iteration, await, truth, unary, binary/reflected, and selected builtin special methods |
| Generators | Persistent frame environments, stable pre-yield identities, depth-specific send values, and suspension-frontier rebasing |
| Coroutines | Deferred activation and bounded await completion |
| Queries | Full-flow pre/post snapshots with locals, heap, scalar presence, returns, raises, and yields per labeled outcome |
| Summaries | Public outcome-sensitive procedure summaries with execution effects; optional direct consumption by CFG/IFDS clients |
| Diagnostics | Per-operation precision degradation reasons, alias evidence, and run-quality counters |

## Explicit exclusions

- unresolved, mixed-known/unknown, or reflective calls beyond their explicit unknown effects;
- recursive call cycles;
- loop executions beyond the configured convergence bound;
- native behavior absent from PyFlow IR and the intrinsic registry;
- precise identities for scalar immutable values.

Unsupported reference-producing behavior must produce an explicit unknown
root. It must not silently produce an empty value set.

Unsupported statements and compound nodes traverse visible children, retain
nested call/exception effects, and locally contaminate reachable objects.
`import *` and similar namespace-wide operations record an explicit precision
degradation rather than pretending to enumerate the namespace.

Generator frames retain environment and identity, but resumption is still a
bounded suspension-frontier summary rather than an exact interpreter program
counter. Detectors specializing in generator delegation, `throw`, or cleanup
ordering must account for that limitation.

## Strong-update invariant

A write is strong only when all of the following hold:

1. the selector path is precise;
2. evaluation produced exactly one possible receiver root;
3. the receiver root has cardinality `ONE`;
4. the configured path abstraction preserves the target selector.

Escape and the number of syntactic aliases do not change the cardinality of a
known singleton object. Allocation-site merging does.

## Regression requirements

Every soundness fix should add a bounded adversarial test. In particular, the
suite must retain coverage for:

- alternative generator branches yielding at the same resume depth;
- allocation-insensitive roots receiving multiple exact writes;
- exceptional effects from expression-level resolved calls;
- inherited constructor effects and known `__new__` returns;
- dynamic container writes/deletes and branch-joined receivers;
- program-point unknown versus definitely-absent queries.
- finite indirect/virtual target sets and implicit protocol side effects;
- versioned relational unknown reads and exhaustive concrete-oracle cases.
- missing/duplicate/positional-only/keyword-only argument failures and dynamic
  spread calls that retain both normal and `TypeError` outcomes;
- unrelated lexical scopes using the same `nonlocal` name;
- unsupported-node and star-import precision diagnostics;
- execution-effect summaries consumed through the CFG/IFDS adapter.
