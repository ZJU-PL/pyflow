Cross-Module Resolution
=======================

The original ``cross_module_resolution`` note documented an important
interprocedural precision fix: calls between modules in the same analyzed
project should be represented as internal call-graph edges, not left as opaque
"external" calls.

Why this matters
----------------

If cross-module calls are not resolved, several analyses lose precision:

* interprocedural taint cannot flow from one project module into another
* call summaries stop at module boundaries
* multi-file vulnerabilities are missed or downgraded
* compositional proofs cannot reuse the real callee summary

Typical example
---------------

Consider:

* a source in ``web.py``
* a wrapper in ``controller.py``
* a sink in ``database.py``

If the call graph only sees local edges and treats imported project functions as
external, the real chain

* ``web.route -> controller.process -> database.execute_query``

is broken. That prevents the taint or bug summary from reaching the sink.

Resolution strategy
-------------------

The original note described a practical multi-step strategy:

1. exact qualified-name match
2. suffix-based match for partially qualified names
3. simple-name match when the name is unambiguous

The important engineering point is that this resolution happens after the
project-wide graph has been populated, so the resolver can look across all
loaded modules.

Current implementation
----------------------

The implementation is in:

* ``cfg/call_graph.py``

and is used by project- or directory-level call-graph construction.

Related higher-level analyses that benefit from it include:

* ``semantics/interprocedural_taint.py``
* ``semantics/interprocedural_bugs.py``
* ``semantics/summaries.py``
* ``semantics/interprocedural_barriers.py``

Precision and limits
--------------------

The original note was explicit about the limits, and those limits still matter:

* dynamic dispatch can still be unresolved
* star imports remain hard to pin down precisely
* ambiguous simple names may require conservative resolution
* imported-object method calls still need richer import or type information for
  best precision

These are acceptable tradeoffs as long as the analyzer remains conservative and
sound: it is better to over-approximate a possible internal edge than to miss a
real project-local call chain entirely.

Why this page belongs in the theory docs
----------------------------------------

This might look like a plain call-graph implementation detail, but it is
actually central to the theory of the subsystem:

* summaries are only useful if call edges are real
* taint, crash propagation, and interprocedural proofs all depend on the same
  graph connectivity
* cross-module resolution is the bridge between file-local bytecode reasoning
  and project-level reachability claims

For contributors, that means call-graph quality is not a separate concern from
bug precision. It is part of the proof and counterexample pipeline.
