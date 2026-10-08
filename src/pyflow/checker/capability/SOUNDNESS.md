# Analysis scope and limitations

This subsystem inventories potential capability use and transfer using the
k-CFA pointer solver and a declarative API registry. It does not verify an
authorization policy, enforce API confinement, or provide a proof of whole
program soundness. Implementation complexity does not establish a new
capability abstraction or a research novelty claim.

## Threat model supplied by the deployment

Security review must identify the trusted host, less-trusted recipients,
resources those recipients cannot otherwise acquire, and permitted transfers.
These principals and permissions are not represented by the checker. A
reference transfer is not automatically a vulnerability: unrestricted Python
libraries generally have ambient authority to import the same host APIs.

The checker can help review whether a plugin receives a host-owned handle,
secret-bearing object, or callback into privileged host behavior. Establishing
an unauthorized authority increase additionally requires a deployment policy
and an independent mechanism restricting the recipient's ambient authority.

## Static coverage

Coverage depends on source reachability from the configured entrypoint,
import depth, the solver's Python models, and the capability registry. Native
extensions, generated code, reflection, import machinery, and interpreter
mutation may introduce behavior outside those models. Runtime observation
does not make the static analysis complete for such behavior.

`complete` means no unknown, unsupported, or budget diagnostic was emitted.
`partial` exposes unresolved calls, translation failures, or solver exhaustion.
An empty `complete` result is an empty modeled inventory, not a certificate
that the program is secure or has no capabilities. Disabled reporting options
also limit that inventory.

Direct findings are possible modeled operations, not proof of execution.
Indirect findings are potential reference transfers, not proof that a transfer
is unauthorized or that the recipient exercises the authority. External
arguments, stores, callback registration, spawning, serialization, and public
exports are reported by default. Returns, yields, and exceptions require
`report_callable_boundaries=True` or CLI `--report-callable-boundaries`, since
a callable boundary does not establish a trust boundary. Disabling these
reports does not disable pointer propagation through callable boundaries.

## Precision and performance choices

The default context is 1-CFA. Higher `k` separates more call chains at a cost
in time and memory. Canonical native access paths preserve identities through
aliases. Registry `reachable()` uses syntactic prefix relationships, including
potential descendants and native return paths. This may substantially
overestimate obtainable authority and does not prove member accessibility.

Heap-field adjacency is indexed once per solved result. Traversal follows
those edges and captured closure variables with cycle detection. This removes
repeated scans of the entire field environment, but repeated transfer queries
can still revisit the same reachable subgraph.

Constant positional and keyword `open` modes distinguish read from write;
update modes report both. Unknown, mixed, or expanded arguments conservatively
report both. External effect summaries refine opaque call behavior; unmodeled
external calls report relevant arguments as potential transfers. Return effects
preserve identity without establishing that the external implementation
actually returns or restricts that authority.

## Runtime observation is not confinement

The optional guard uses `sys.addaudithook()`. The official
[Python documentation](https://docs.python.org/3/library/sys.html#sys.addaudithook)
states that Python-level audit hooks are unsuitable for sandboxing malicious
code. The guard records classified events and can raise an exception for a
denied classified operation. `--observe-only` disables denial. Unclassified
events are ignored and are not logged. Static `runtime_guarded` labels do not
certify that a hook was installed, that an event was observed, or that an
operation cannot bypass the monitor.

Running the hook in a fresh process manages its permanent installation; it
does not provide hostile-code isolation. Confinement requires independently
enforced OS resource restrictions and an appropriate security boundary.
