# Soundness contract

The static result over-approximates modeled Python-level flows subject to all of these conditions:

1. Every analyzed source module is reachable from the supplied entrypoint and
   import depth.
2. A `complete` result was produced; no unknown or budget diagnostic exists.
3. Native extensions, injected bytecode, tracing/debugger mutation, and
   implementation-specific interpreter hooks cannot mutate objects without an
   event covered by the protected runtime or an outer OS sandbox.
4. The capability registry models every authority-bearing host API in the
   deployment, including application/framework-specific APIs.
5. Code executes in the same CPython audit semantics used by the runtime guard.

Within that boundary, a relevant abstract object is never silently discarded:
direct operations are reported, while values crossing unanalyzed boundaries
through arguments, stores, returns, yields, exceptions, closures, callbacks,
spawned work, or serialization are reported as indirect capabilities. Empty
callees and solver exhaustion are fail-visible and make the result partial.

## Why unrestricted CPython is not a sandbox

Python permits native extensions, `ctypes`, audit-hook installation order
attacks, debugger/tracing hooks, replacement import machinery, and direct OS
syscalls from native code. A library loaded into an already-compromised process
can bypass a Python-only monitor. Therefore the strong deployment guarantee is:

- start the guard before untrusted application code;
- deny `native.access`, loader mutation, and unmodeled imports unless required;
- execute in a fresh process with least-privilege filesystem/network/OS
  credentials; and
- use an OS sandbox for hostile native code.

The audit guard fail-closes known file, network, process, native loading,
deserialization, import, and application-launch events. Unknown CPython audit
events are recorded only when they are mapped; extending the map and the JSON
registry is part of porting the guarantee to a new interpreter or framework.

## Precision choices

The default context is 1-CFA. Higher `k` separates more call chains at a cost
in time and memory. Native modules receive canonical access-path objects, so
aliases such as `f = subprocess.run` retain identity. Constant `open` modes are
used to distinguish read from write; an unknown mode conservatively reports
both. External arguments, exports, returns, yields, and carrier stores preserve
all reachable capability classes.

External effect summaries refine opaque boundaries without making an unmodeled
call silently safe. In their absence, all arguments to an unanalyzed call are
treated as potential escapes. Argument-to-return and receiver-to-return effects
add conservative pointer-flow edges; callback, retention, spawning, and
serialization effects classify the corresponding escape boundary.
