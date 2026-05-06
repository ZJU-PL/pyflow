Interprocedural Barrier Synthesis
=================================

The original ``INTERPROCEDURAL_BARRIER_SYNTHESIS`` note described how the
standalone project intended to connect summary-based interprocedural analysis
with barrier-certificate reasoning. That architecture is directly relevant to
the current ``pyflow.a3_python`` tree because the repository now contains an
explicit ``semantics/interprocedural_barriers.py`` module.

Core idea
---------

The goal is to lift safety reasoning from single functions to call chains:

* synthesize or infer safety conditions for individual functions
* encode those conditions as reusable preconditions or summaries
* compose them across callers and callees
* decide whether a project-level unsafe state is reachable or prevented by
  composed conditions

This is a compositional verification view of Python programs: each function can
contribute a local proof obligation or proof artifact, and callers can reuse
that information instead of re-deriving everything from scratch.

Conceptual objects
------------------

The original note called out a few key abstractions that still describe the
current design well:

* safety-property categories such as division safety, bounds safety, null
  safety, taint safety, and termination
* function preconditions that make a local safety argument valid
* per-function barrier-like certificates or proof summaries
* interprocedural barrier objects that compose those proofs across call chains

The concrete implementation lives in:

* ``semantics/interprocedural_barriers.py``
* ``analyzer.py`` for top-level integration

Barrier shapes for common crash properties
------------------------------------------

The original note documented the intended proof shapes for several recurring bug
classes.

Division by zero
~~~~~~~~~~~~~~~~

The basic local reasoning pattern is:

* if a divisor is known to be non-zero, the corresponding unsafe region is
  unreachable
* callers therefore need to establish a non-zero precondition for that
  parameter

In simplified terms, this becomes a reusable summary of the form:

* callee is safe if ``divisor != 0``
* caller obligations must imply that condition

Bounds safety
~~~~~~~~~~~~~

For indexing or subscript safety, the key shape is:

* safe access requires an index range precondition such as
  ``0 <= i < n``
* if a callee relies on that fact, the caller must preserve or establish it

Null safety
~~~~~~~~~~~

The same structure applies to ``None``-sensitive access:

* local proof: parameter is not ``None`` at dereference sites
* interprocedural composition: callers must establish non-nullness or a
  stronger invariant that implies it

Architecture in the current tree
--------------------------------

The original diagram is still a good mental model:

* function-level semantic analysis produces summaries and candidate safety facts
* barrier and verification engines attempt to turn those into proofs
* interprocedural composition combines local conditions along the call graph

In the current repository, the main integration points are:

* ``semantics/interprocedural_bugs.py``
* ``semantics/interprocedural_taint.py``
* ``semantics/interprocedural_barriers.py``
* ``cfg/call_graph.py``
* ``barriers/`` for the actual synthesis and proof sub-engines

Relation to the layered verification stack
------------------------------------------

This page sits at the meeting point of two earlier themes:

* interprocedural summaries from :doc:`architecture`
* barrier and proof machinery from :doc:`contracts-and-barriers`

The original note explicitly tied interprocedural barrier synthesis to a
portfolio of proof engines:

* SOS and SDP-based synthesis
* CEGAR and predicate abstraction
* ICE or Houdini-style learning
* IC3/PDR, CHC, interpolation, and assume-guarantee reasoning

That is why the current ``barriers/`` directory is so broad. The subsystem is
not committed to a single global proof method; it treats interprocedural
barrier construction as a coordination problem across several families of
techniques.

Why this matters for contributors
---------------------------------

When extending the subsystem, the main takeaway is this:

* an interprocedural warning should ideally be explainable as either
  reachability through summaries or failure to establish a composed safety
  precondition
* an interprocedural proof should ideally be reusable as a summary, not just as
  an end-of-run artifact

In other words, the most valuable changes are those that improve both local
proof strength and cross-function compositionality.
