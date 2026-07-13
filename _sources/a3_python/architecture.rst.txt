Architecture
============

High-level structure
--------------------

``a3_python`` is organized as a layered analysis stack rather than a single
pass. The major pieces work together roughly as follows:

* frontend and loading code discover Python files, code objects, and entry
  points
* CFG and call-graph layers build the structural program model
* semantic execution and summary layers reason about behavior inside and across
  functions
* unsafe detectors classify reachable bad states into bug types
* DSE, concolic replay, and solver-backed refinement reduce false positives
* invariant, ranking, and barrier subsystems attempt to prove safety properties

Source-level package layout
---------------------------

The most important directories under ``third-party/a3_python/a3_python`` are:

* ``frontend``: file loading, source ingestion, and entry-point discovery
* ``cfg``: control-flow and call-graph support
* ``semantics``: symbolic execution, summaries, taint tracking, and semantic
  detectors
* ``unsafe``: bug-type predicates and unsafe-state classification
* ``dse``: dynamic symbolic execution, constraint extraction, and replay logic
* ``contracts``: semantic contracts for libraries, frameworks, and relations
* ``barriers``: barrier-certificate, invariant, ranking, and verification
  machinery
* ``ci``: SARIF, baseline, and CI integration helpers
* ``evaluation``: result post-processing and dataset-oriented tooling
* ``z3model``: solver-facing symbolic value, heap, and taint abstractions

Interprocedural analysis pipeline
---------------------------------

The interprocedural path described in the original project notes can be
understood as five practical layers:

1. intraprocedural semantic analysis within a single function
2. summary computation that records parameter, return, and sink relationships
3. call-graph construction over files or projects
4. interprocedural propagation across call sites, often with fixpoint-style
   iteration
5. optional context-sensitive refinements, call-chain reasoning, and
   downstream proof generation

In the current tree, these responsibilities are primarily split across:

* ``semantics/sota_intraprocedural.py``
* ``semantics/summaries.py``
* ``semantics/sota_interprocedural.py``
* ``semantics/interprocedural_taint.py``
* ``semantics/interprocedural_bugs.py``
* ``cfg/call_graph.py``

Barrier and verification layering
---------------------------------

The original standalone docs also described a verification-oriented layering
for the barrier machinery. The exact implementation is broad, but the intended
stack is:

1. foundations: algebraic and optimization primitives
2. certificate core: barrier and safety-certificate construction
3. abstraction/refinement: CEGAR, predicate abstraction, and related filters
4. learning: ICE, Houdini, and synthesis-guided candidate generation
5. advanced proof engines: IC3/PDR-, CHC-, or interpolation-style reasoning

The corresponding code is concentrated under ``barriers/``. That directory
contains both focused components such as ``cegis.py``, ``ranking.py``,
``invariants.py``, and ``pdr_spacer.py`` and larger integration/orchestration
modules.

Design intent
-------------

Two design ideas show up repeatedly across the subsystem:

* precise-enough execution semantics first, abstraction second
* bug finding and proof finding share the same transition-system view of the
  program

That is why the package mixes symbolic execution, taint propagation, unsafe
predicates, solver models, and proof engines in a single tree: they are meant
to cooperate over a common model of Python behavior rather than act as isolated
feature checkers.
