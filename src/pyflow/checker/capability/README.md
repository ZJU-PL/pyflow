# Defensive capability analysis

This subsystem adapts defensive capability analysis to Python on top of
PyFlow's context-sensitive pointer analysis. It is a static security-auditing
tool with optional runtime observation and denial of classified audit events.
It treats security-relevant functions, objects, and fields as abstract objects
and follows their identity
through assignments, imports, calls, returns, containers, and heap fields.

## Reports

- `direct`: an analyzed operation may invoke, read, or write a modeled capability.
- `indirect`: a potential capability transfer through an argument, external
  carrier, public module binding, or callback. Callable returns, yields, and
  exceptions are included only with `report_callable_boundaries=True`.
- `runtime_guarded`: a compatibility label for modeled reflection or code
  loading operations that need further review. It does not mean a runtime
  guard is installed or that the operation is securely confined.
- `unsupported`: reserved for constructs whose semantics are explicitly
  rejected rather than silently approximated.

Indirect findings also expose a machine-readable `escape_kind` and `boundary`.
The unified escape vocabulary covers arguments, returns, yields, raised values,
public exports, field stores, closure capture, callback registration, spawned
tasks/processes, and serialization.

`complete` means that no unknown, unsupported, or budget diagnostic was emitted
by this analysis. It does not certify absence of vulnerabilities or unmodeled
authority. Unresolved call targets, translation failures, and exhausted
fixpoint budgets make the result `partial` and are emitted as diagnostics.

## Security interpretation

Findings inventory potential authority use and transfer. The checker does not
assign trust to callers or callees, compare transfers against an authorization
policy, or establish that a recipient exercises the capability. A callable
boundary alone is not a trust boundary; reporting returns, yields, and
exceptions is therefore opt-in. Pointer propagation through them always
remains active, including when their transfer reports are disabled.

A transfer matters when, for example, a host shares a secret-bearing object or
resource handle with a plugin that otherwise cannot acquire that resource.
Reviewers must supply the trusted components, restricted resources, allowed
transfers, and independent confinement mechanism. Ordinary Python code can
usually import `os` itself; receiving `os.system` does not by itself increase
its ambient authority. Public exports and unanalyzed calls remain potential
exposure reports, not findings of an unauthorized transfer. Indirect SARIF
results use level `note` for this reason.

Native access-path prefix reachability is conservative. It can associate an
object with sensitive descendants without proving that those descendants
exist or are accessible. Heap fields are indexed once per analysis result;
closure cells and reachable fields are then traversed for each transfer.

## API

```python
from pyflow.checker.capability import DefensiveCapabilityAnalysis

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
pyflow capabilities app.py --report-callable-boundaries
pyflow capability-run --observe-only --audit-log observed.json app.py
pyflow capability-run --allow file.read --allow 'network.*' app.py
```

`capability-run` installs a permanent CPython audit hook in the CLI process.
It observes classified events and, by default, uses an allow list to deny known
operations. An uncaught denial exits with status 126. `--observe-only` records without denying.
Unclassified events are ignored. Python-level audit hooks are not suitable for
sandboxing malicious code, as the [Python documentation](https://docs.python.org/3/library/sys.html#sys.addaudithook)
explains. A fresh process does not itself supply an OS security boundary.

See `SOUNDNESS.md` for the analysis scope, deployment assumptions, and limitations.
