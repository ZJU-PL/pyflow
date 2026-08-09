# Defensive capability analysis

This subsystem adapts defensive capability analysis to Python on top of
PyFlow's context-sensitive pointer analysis. It treats security-relevant
functions, objects, and fields as abstract objects and follows their identity
through assignments, imports, calls, returns, containers, and heap fields.

## Reports

- `direct`: analyzed code invokes, reads, or writes a modeled capability.
- `indirect`: analyzed code exposes a capability to another component through
  an argument, external carrier, public module binding, return, or yield.
- `runtime_guarded`: the operation is found statically but Python reflection or
  code loading also requires the protected-runtime backstop.
- `unsupported`: reserved for constructs whose semantics are explicitly
  rejected rather than silently approximated.

Indirect findings also expose a machine-readable `escape_kind` and `boundary`.
The unified escape vocabulary covers arguments, returns, yields, raised values,
public exports, field stores, closure capture, callback registration, spawned
tasks/processes, and serialization.

An empty result is authoritative only when `status` is `complete`. Unresolved
call targets, translation failures, and exhausted fixpoint budgets make the
result `partial` and are emitted as diagnostics.

## API

```python
from pyflow.analysis.capability import DefensiveCapabilityAnalysis

result = DefensiveCapabilityAnalysis(k=1).analyze_project(
    "src/package/__main__.py",
    project_path=".",
)
for finding in result.findings:
    print(finding.capability, finding.report_kind, finding.location)
```

The default model is the versioned JSON file
`pyflow/config/capability/stdlib.json`. A project can append its own model with
`CapabilityRegistry.from_json()` or repeated CLI `--capability-model` flags.
Models can also declare external effects:

```json
{
  "schema_version": 1,
  "patterns": [],
  "effects": [{
    "kind": "invoke_callback",
    "arguments": [0],
    "access_paths": ["plugin_manager.register"]
  }]
}
```

Supported effects are `return_argument`, `return_receiver`,
`retain_argument`, `invoke_callback`, `spawn_callback`, and
`serialize_argument`. Return effects feed the pointer solver, so subsequent
calls retain the original capability identity rather than receiving only an
opaque external return object.

## CLI

```text
pyflow capabilities PROJECT --entry app.py --format sarif
pyflow capabilities app.py --capability-model company-capabilities.json
pyflow capability-run app.py --allow file.read --allow 'network.*'
```

`capability-run` installs a permanent CPython audit hook in the child process.
It uses an allow list and exits with status 126 on a denied known operation.
Run untrusted code in a separate OS process; audit hooks are process-global.

See `SOUNDNESS.md` for the guarantee boundary and deliberately unsupported
execution environments.
