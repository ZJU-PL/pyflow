# AST dataflow taint analysis

`pyflow.checker.ast_dataflow` is a lightweight interprocedural taint analysis
over Python source ASTs. Its production engine is a monotone abstract
interpretation over an explicit statement-level CFG. The older mutable
`ast.NodeVisitor` implementation remains available only as a compatibility
fallback through `formal_semantics=False`.

## Architecture

```text
source AST
   │
   ▼
frontend/ast_cfg.py       explicit branches, loops, exceptions, abrupt exits
   │
   ▼
semantics/                Python expression and statement transfer functions
   │
   ▼
solver/cfg.py             least-fixed-point worklist
   │
   ▼
solver/interprocedural.py relational, outcome-sensitive summaries
   │
   ▼
detectors/                policy matching, diagnostics, witnesses, reporting
```

The abstract domain lives in `domain/` and contains canonical access paths,
wildcard widening for recursive shapes, may-taint facts, must-sanitization
guarantees, bounded provenance with an explicit overflow top, abstract strings,
and uncertainty metadata. `modeling/` contains sanitizer transforms and
optional call-result shape contracts.

## Core properties

- Unknown branches start from independent input states and join at their CFG
  successor. Branch order cannot change the result.
- Loops iterate to a fixed point or produce a partial-result diagnostic when
  their configured step bound is reached.
- Exact local assignments are strong updates. Object-path writes remain weak
  until the flow-sensitive heap graph proves that the receiver is a singleton.
- Dict keys, attributes, constant list indices, wildcards, and modular index
  classes are separate selectors.
- Procedure summaries relate parameter paths to return, raise, yield, sink,
  and mutated parameter paths. Must-kill effects are composed at call sites.
- Sanitizers are kind transforms rather than unconditional boolean kills.
  Conditional contracts join sanitized and unsanitized outcomes unless their
  guard is proven.
- Unknown operations perform explicit conservative havoc and make the result
  partial instead of silently dropping flows.
- Findings contain bounded source-to-sink provenance. JSON and SARIF reports
  retain the trace.

The formal support boundary and lattice are specified in
[`SOUNDNESS.md`](SOUNDNESS.md).

## Optional benchmark models

Benchmark-specific behavior is never embedded in transfer code. For example,
the historical SAST-Python3 alternating-index `array.array` assumption is an
optional modular shape contract:

```python
from pyflow.checker.ast_dataflow.modeling import sast_python3_benchmark_shapes

detector = ASTDataflowTaintDetector(
    shape_contracts=sast_python3_benchmark_shapes()
)
```

Enabling such a contract records an `ASSUMED` diagnostic and therefore makes
the completion status `partial`.

## Testing

Focused tests cover lattice laws, CFG construction, fixed-point behavior,
shape sensitivity, sanitizer contracts, heap refinement, relational summaries,
outcome separation, provenance, and public detector compatibility:

```bash
PYTHONPATH=src pytest -q tests/checker/test_ast_dataflow_*.py
```
