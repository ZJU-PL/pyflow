# AST dataflow soundness and precision contract

## Analysis contract

For the supported bounded Python fragment, AST dataflow is a may-taint
analysis: every modeled concrete source-to-sink flow is represented by an
abstract flow. Unsupported behavior must introduce conservative facts and an
explicit diagnostic; it must not silently return an empty fact set.

The analysis is intended for bug finding, not whole-Python verification.
Reflection, native extensions, monkey patching, dynamic imports, and unresolved
calls require models for precise results.

## Abstract state

At each CFG program point the state is:

```text
S = <reachable, facts, guarantees, provenance, uncertainties>
```

- `facts` is a finite may-set of `(location, kind, origin)` values.
- `guarantees` is a finite must-set of sanitized `(location, kind)` values.
- `provenance` is a finite may-set of propagation edges with an explicit
  overflow top element.
- `uncertainties` is a may-set of crossed precision boundaries.

For reachable states, the order is:

```text
S1 <= S2 iff
    S1.facts          subset S2.facts
    S1.guarantees     superset S2.guarantees
    S1.provenance     subset S2.provenance, or S2.provenance is top
    S1.uncertainties  subset S2.uncertainties
```

Join unions may-properties and intersects must-guarantees. The explicit
unreachable state is bottom. Deep access paths widen to a wildcard selector at
the configured depth. If provenance exceeds its budget, it becomes a canonical
top value and emits a `CONSERVATIVE` diagnostic rather than silently dropping
arbitrary edges. These widenings make the domain finite; the worklist
additionally has an observable transfer-step limit.

## Locations and updates

A location is a root followed by selectors:

- named attribute
- literal mapping key
- literal index
- iterable element, mapping key, or mapping value
- wildcard selector
- modular index class

A write is strong only when the target is exact and the selected refinement
provider proves singleton storage. Otherwise it is weak. Strong writes remove
overwritten descendant facts and add must-guarantees that mask less precise
ancestor facts for the overwritten path.

The default source-only refiner proves local rebinding but treats object paths
as weak. When `AnalysisSession` has run the `heap` pass, the adaptive refiner
asks `PointsToGraph.strong_update_possible()` only for unresolved object paths.

## Control flow

The solver implements:

```text
IN[n]  = join(OUT[p, n] for p in predecessors(n))
OUT[n] = transfer(n, IN[n])
```

Branches have distinct successor states. Loops iterate until no successor
state grows. Return, raise, and yield are accumulated as distinct outcomes.
Exception prefixes and `finally` ordering that cannot be represented exactly
are over-approximated and labeled `CONSERVATIVE`.

## Interprocedural summaries

Summaries are finite relations between ports:

- parameter and parameter access path
- receiver
- return
- raise
- yield
- sink argument

They also contain unconditional source seeds, parameter-path writes,
parameter-path must-kills, sink sites, and uncertainty metadata. Summaries are
joined monotonically until stable. Caller-side origin tokens are retained while
relations are instantiated, avoiding the previous global "tainted parameter"
abstraction.

## Precision levels

- `PRECISE`: transfer follows the documented abstraction exactly.
- `CONSERVATIVE`: sound over-approximation that may add false positives.
- `ASSUMED`: behavior depends on a user or library contract.
- `UNSUPPORTED`: behavior is conservatively havoced because no adequate model
  exists.

A result is `complete` only when the fixed points converge and no `ASSUMED` or
`UNSUPPORTED` boundary was crossed. `CONSERVATIVE` diagnostics preserve
completion but are attached to findings as precision reasons.

## Supported source fragment

The source CFG and transfer semantics cover:

- assignments, annotated and augmented assignments, deletion
- conditionals and ternary expressions
- `for`, `async for`, and `while` loops
- `break`, `continue`, and constant branch pruning
- return, raise, yield, await, and basic exception-handler payloads
- `try`, handlers, `else`, and conservative `finally`
- `with`/`async with` entry binding with conservative exit effects
- lists, tuples, sets, dicts, comprehensions, and constant access paths
- common dict/list/set accessors and mutators
- formatted strings and expression propagation
- positional, keyword, receiver, recursive, and summary-backed calls
- kind-specific, conditional, transforming, and assumed sanitizers

## Explicit limitations

- Call resolution is name-based unless PyFlow supplies a more precise graph.
  Ambiguous suffix matches are reported and havoced.
- Unknown calls may mutate arguments and return externally tainted data; they
  are havoced using configured source kinds.
- Precise context-manager exit ordering, descriptor execution, metaclass
  behavior, arbitrary protocols, and reflective operations require PyFlow IR
  or library models.
- Provenance is intentionally bounded. Budget overflow is observable through
  `provenance-budget-exceeded` and may omit witness branches without changing
  the taint result.
- Source-level reachability uses explicit program entry points when available;
  otherwise it falls back to root functions in the local call graph.

## Regression obligations

Changes to transfer or summary semantics must retain tests for:

- lattice join laws and bottom identity
- branch-order independence and loop convergence
- scalar and heap strong-update kills
- constant-key/index separation and wildcard reads
- recursive and receiver-call summaries
- return/raise/yield outcome separation
- parameter-path writes and must-kills
- conditional sanitizer conservatism
- unknown-call havoc and partial status
- heap refinement request accounting
- source-to-sink witness emission
