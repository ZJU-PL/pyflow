# Security checker layout

```text
checker/
├── common/          # Shared findings, CWE types, rankings, and scan metrics
├── ast_rules/       # AST rule execution and registered security rules
├── ast_dataflow/    # Complete AST dataflow analysis and detection
├── ifds/            # IFDS taint analysis, entry points, and shadow scanning
│   └── class_pollution/  # Reflective object-write analysis using IFDS
├── cpg/             # Complete CPG security analysis, rules, and profiles
├── capability/      # Capability analysis and runtime enforcement
├── supply_chain/    # Package inventory, integrity, and policy checks
├── formatters/      # Security report output
└── llm/             # LLM-assisted report analysis
```

Each subsystem keeps its execution mechanisms, domain models, propagation,
and detection logic together. There is no separate `engines/` layer or
cross-backend `detectors/` layer. Both `ifds/` and `cpg/` can host additional
checks beyond taint analysis.

The general IFDS/IDE solver, CFG adaptation, session loading, and non-security
analyses remain in `pyflow.analysis.ifds`. Graph representation, construction,
queries, persistence, and export remain in `pyflow.ir.cpg` and `pyflow.ir.pdg`.
The checker implementations use these foundations directly.

`common/` owns the finding types and scan metrics shared by the AST rule and
AST dataflow subsystems. Engine-neutral taint policies remain in
`pyflow.analysis.taint_policy`; existing shared AST dataflow semantics stay
intact.

Use `pyflow.checker.ast_rules`, `pyflow.checker.ifds`,
`pyflow.checker.ifds.class_pollution`, `pyflow.checker.cpg`,
`pyflow.checker.capability`, and `pyflow.checker.supply_chain` for checking.
File-based IFDS taint analysis starts at
`pyflow.checker.ifds.api.run_taint_analysis`. Shared finding types live in
`pyflow.checker.common.issue`.

The former `checker.pattern`, `checker.detectors`, IFDS taint/shadow-scan
modules and exports under `analysis.ifds`, and security modules/exports under
`ir.cpg` are removed without compatibility modules. The engine-local shared
issue/constants/metrics modules are also removed. Registry loading remains
in `analysis.ifds.modeling.registry`; create an IFDS taint configuration with
`TaintConfiguration.from_registry(registry)` instead of `registry.as_config()`.

Tests mirror the checking subsystems under `tests/checker`. Mixed framework
and checking integration tests remain under `tests/analysis/ifds` and
`tests/ir/cpg`. Run the relevant suites with:

```console
pytest tests/checker tests/cli tests/analysis/ifds tests/ir/cpg tests/api
```
