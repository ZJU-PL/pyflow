Analysis Techniques
===================

This page summarizes the main analysis techniques documented in the original
``a3-python`` notes and how they show up in ``a3_python``.

Execution-centered analysis
---------------------------

The subsystem treats Python analysis as a transition-system problem over code
objects, frames, heaps, and program state. In practice that produces several
complementary execution-style analyses:

* symbolic execution over bytecode
* concrete execution and replay
* concolic or DSE-guided path exploration
* crash-summary extraction for reusable local reasoning

The key implementation modules are:

* ``semantics/symbolic_vm.py``
* ``semantics/concrete_vm.py``
* ``semantics/crash_summaries.py``
* ``dse/concolic.py``
* ``dse/selective_concolic.py``
* ``dse/hybrid.py``

Interprocedural reasoning
-------------------------

The interprocedural architecture described in the original docs is built around
three reusable artifacts:

* call graphs
* summaries
* fixpoint-style propagation

The intended flow is:

1. analyze functions intraprocedurally
2. compute summaries of parameter-to-return, parameter-to-sink, and exception
   behavior
3. connect those summaries through the call graph
4. iterate until no new cross-function facts are discovered

This style is visible in:

* ``cfg/call_graph.py``
* ``semantics/summaries.py``
* ``semantics/sota_interprocedural.py``
* ``semantics/interprocedural_taint.py``
* ``semantics/interprocedural_bugs.py``

Kitchen-sink verification pipeline
----------------------------------

One of the strongest themes in the original standalone docs is the
``kitchensink`` idea:

    use every practical source of analysis information, then reduce the final
    question to either a proof artifact or a validated counterexample.

The important point is that this is not meant as "run everything blindly". The
intended execution policy is staged and portfolio-based:

* start with cheap pruning and local reasoning
* gather slices, bounds, summaries, contracts, and candidate invariants
* try bug-finding paths such as BMC- or DSE-like witness search
* then spend higher-cost effort on barrier, invariant, ranking, or inductive
  proof search

In the original design notes, the central "glue" is a pair of coupled CEGIS
loops:

* a bug-finding loop that proposes and validates reachability witnesses
* a barrier-synthesis loop that proposes proofs and learns from failed proof
  obligations

This perspective is especially helpful when reading:

* ``barriers/cegis.py``
* ``barriers/program_analysis.py``
* ``barriers/invariants.py``
* ``barriers/pdr_spacer.py``
* ``barriers/synthesis*.py``

Precision-oriented filtering
----------------------------

The original docs also spent significant effort on precision and false-positive
reduction. Several examples are worth carrying forward because they explain why
the subsystem contains many narrowly targeted detectors.

Safe subscript detection
~~~~~~~~~~~~~~~~~~~~~~~

The ``SAFE_SUBSCRIPT_DETECTION`` notes document a semantic distinction that
matters a lot for Python:

* slicing such as ``x[i:j]`` is clamped and does not raise ``IndexError``
* indexing such as ``x[i]`` can raise
* dictionary lookup is a different exception family again

This is why the codebase distinguishes:

* true bounds/indexing hazards
* slices that are safe by Python semantics
* dictionary-style access that should not be reported as a ``BOUNDS`` bug

Type-based sanitizers
~~~~~~~~~~~~~~~~~~~~

The original ``type_based_sanitizers`` notes describe an important precision
improvement for taint analysis: conversions and validators can sanitize not by
escaping strings but by constraining the value domain.

Examples include:

* ``int()`` or ``bool()`` for narrowing attacker-controlled strings
* ``datetime.fromisoformat()`` for validated date-time formats
* ``pathlib.Path.resolve()`` for canonicalized filesystem paths
* ``ipaddress.ip_address()`` for URL or network-input validation

These ideas feed directly into:

* ``contracts/security_lattice.py``
* ``semantics/security_tracker_lattice.py``
* related taint- and sink-checking code

Object and protocol-aware taint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The original notes on file-object and socket taint tracking are useful because
they show that the system is not limited to plain string-flow analysis.

The subsystem aims to propagate semantic labels through objects and protocols:

* tainted file handles can produce tainted contents
* tainted sockets can produce tainted network input
* framework objects can carry source/sink properties across calls

That is why the analysis combines:

* object-sensitive state in the symbolic machine
* contract-aware call postprocessing
* per-sink sanitizer sets rather than one global "tainted or not" bit

Abstraction, learning, and proof search
---------------------------------------

Beyond direct execution and taint, the package includes higher-level proof and
search techniques described across the original theory notes:

* CEGAR and predicate abstraction
* ICE-style learning
* Houdini-style weakening or invariant filtering
* PDR/IC3 and CHC-oriented reasoning
* SOS/SDP-inspired barrier search
* ranking-function synthesis for termination arguments

Not every module is equally mature, but this explains the unusual breadth of
the ``barriers/`` package: it is deliberately a toolbox of cooperating
verification strategies rather than a single monolithic solver.
