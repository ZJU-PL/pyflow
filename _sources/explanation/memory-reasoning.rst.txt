.. _explanation-memory-reasoning:

==========================
Memory Reasoning Systems
==========================

PyFlow has **five** heap/memory analyses: three built on a shared data model
(StoreGraph) and two standalone with independent heap models.
This page explains what they are, how they relate, and when to use each.

.. contents::
   :local:
   :depth: 1


Architecture
============

.. code-block:: text

   ┌── StoreGraph (infrastructure — not an analysis) ──┐
   │  RegionNode / ObjectNode / SlotNode + union-find  │
   │  ExtendedType taxonomy, CanonicalObjects naming    │
   │                                                    │
   │  ┌── IPA   ← qualifier-based, type-sensitive       │
   │  ├── CPA   ← constraint propagation worklist       │
   │  └── Shape ← refcount k=2 + equivalence-class      │
   └────────────────────────────────────────────────────┘

   ┌── Standalone Analyses (independent heap models) ───┐
   │  flow_sensitive  ← HeapObject + HeapSelector + UF  │
   │  kcfa            ← standard k-CFA solver            │
   └─────────────────────────────────────────────────────┘

The three StoreGraph-based analyses share ``ExtendedType`` and
``CanonicalObjects``.  The two standalone analyses share **nothing** with the
StoreGraph family — different heap models, no shared types, no bridge.


StoreGraph — Shared Infrastructure (Not an Analysis)
=====================================================

:Location: ``src/pyflow/analysis/storegraph/``
:Docs:    :doc:`/analysis/storegraph`

Data model, not an analysis — it has no solver, no fixpoint loop, no ``run()``
method.  IPA and CPA both use it as their heap representation.

``SlotNode.refs`` holds ``frozenset[ExtendedType]``.  ``ExtendedType`` variant
taxonomy: ``External``, ``Existing``, ``Path`` (allocation-site), ``Method``,
``Context``, ``Indexed``.  Objects are canonicalised via ``CanonicalObjects``
so ``is``-based equality works for points-to membership.


StoreGraph-Based Analyses
==========================

IPA — Qualifier-Based Inter-Procedural Analysis
-----------------------------------------------

:Location: ``src/pyflow/analysis/ipa/``

Layers a **qualifier system** on top of StoreGraph.  Every abstract object
gets a scope/lifetime qualifier:

======  ===========  ======================================
Symbol  Meaning      Effect
======  ===========  ======================================
HZ      Heap Zone    Locally allocated, non-escaping
DN      Downward     Passed as parameter to callees
UP      Upward       Returned from callees
GLBL    Global       Pre-existing objects, constants
======  ===========  ======================================

The qualifier is part of object identity: ``ObjectName(xtype, HZ)`` and
``ObjectName(xtype, DN)`` are distinct and cannot alias.

**Qualifier → behaviour**:

* Escape initialisation: DN objects pre-mark ``escapeParam``; GLBL objects
  pre-mark ``escapeGlobal``; HZ objects start clean.
* Field strategy: GLBL bootstraps from extractor; DN copies from caller; HZ
  starts null.
* Call-boundary: ``Invocation.copyDown()`` remaps caller objects to ``DN``
  qualifier in the callee context.

**Context sensitivity**: type-parameterised via ``CPAContextSignature(code,
selfparam_type, param_types, vparam_types)``.  Types flow through
``TypeSplitConstraint`` with megamorphic fallback at ≥4 types.

**Iteration**: alternates top-down (caller→callee) and bottom-up
(callee→caller) for 5 fixed-point iterations; bottom-up computes function
summaries and applies escape analysis.

**Use IPA when**: you need inter-procedural escape analysis with directional
parameter flow, or the HZ/DN/UP/GLBL semantics provide useful precision.


CPA — Constraint-Based (Propagation) Analysis
---------------------------------------------

:Location: ``src/pyflow/analysis/cpa/``
:Docs:    :doc:`/analysis/cpa`

Worklist-based constraint solver on the StoreGraph.  Main class:
``InterproceduralDataflow``.  No qualifiers — works with ``ExtendedType``
identities directly.

Key mechanisms:

* **Constraints**: Assignment, Load, Store, Allocate, Call, SimpleCall, Is,
  Switch — standard set with Python-specific handling.
* **Context**: ``CPASignature(code, selfparam, params)`` + op-path length
  creates distinct ``AnalysisContext`` per type combination.
* **Cloning (optional)**: ``FunctionCloner`` deep-copies code for per-context
  annotation.  Controlled by ``clone`` flag — ``NullCloner`` when disabled.
* **Dynamic folding**: constant-argument functions evaluated at analysis time.

**Use CPA when**: you need constraint-based analysis on the StoreGraph, or as
the backend for ``pyflow optimize --analysis cpa``.


Shape Analysis
--------------

:Location: ``src/pyflow/analysis/shape/``
:Docs:    :doc:`/analysis/shape`

Top consumer in the StoreGraph family.  Takes pre-computed StoreGraph (via
``cpacanonical``) and ``RegionAnalysis`` results, then layers its own domain:

* **Configuration**: ``(object, region, entrySet, currentSet,
  externalReferences, allocated)`` per program point.
* **Reference counting**: k-bounded (k=2), summarised at 3=∞.
* **Equivalence-class paths**: union-find tracking of access paths with
  True/False/Maybe hit flags.

**Use Shape when**: you need bounded reference-count information per program
point — useful for object sharing analysis and optimisation safety decisions.


Standalone Analyses
===================

These analyses define their own heap model from scratch.  They share nothing
with StoreGraph.

Flow-Sensitive Heap Analysis
-----------------------------

:Location: ``src/pyflow/analysis/alias/flow_sensitive/``
:Docs:    :doc:`/analysis/alias/flow_sensitive`

Flow-sensitive, path-insensitive heap/alias analysis.  Used by optimisation
passes and IFDS clients.

**Model**: ``HeapObject`` (local/global/param/allocation/return/external) +
``[HeapSelector]`` (Attribute/Array/Dictionary/Wildcard) = ``HeapLocation``.

**Key features**:

* Alias tracking via union-find on root ``HeapObject`` identities.
* Strong vs weak updates: governed by singleton-ness, receiver count, and path
  precision.  Wildcard selectors force weak updates.
* Recency abstraction: fresh objects can receive strong updates.
* ``HeapEscapeState``: LOCAL / ESCAPED / EXTERNAL / UNKNOWN.
* ``HeapPolicy`` configures allocation/field/container/context sensitivity.

**Use flow_sensitive when**: a pass needs order-aware heap state, escape facts,
or proof that a write can overwrite previous facts.


k-CFA Pointer Analysis
-----------------------

:Location: ``src/pyflow/analysis/alias/kcfa/``
:Docs:    :doc:`/analysis/alias/kcfa`

Textbook k-CFA (Shivers '88), ported from PythonStAn.  Flow-insensitive,
context-sensitive — solves points-to constraints to a monotone union fixpoint.

**Context policies**: ``k-cfa`` (call-string), ``k-obj`` (allocation site),
``k-type``, ``k-rcv`` (receiver), ``k-param``, and hybrids (e.g., ``2c1o``).

**Use k-CFA when**: you need source-level, context-sensitive points-to or
call-graph construction without per-program-point update semantics.


Summary
=======

+-----------------+-------------+---------------------------+------------------+---------------------------+
| Analysis        | Based On    | Core Abstraction          | Context          | Best For                  |
+=================+=============+===========================+==================+===========================+
| IPA             | StoreGraph  | ObjectName(xtype, HZ/DN   | Type-param       | Escape + directional flow |
|                 |             | /UP/GLBL)                 |                  |                           |
+-----------------+-------------+---------------------------+------------------+---------------------------+
| CPA             | StoreGraph  | Constraint worklist on    | Type-param       | Optimisation backend +    |
|                 |             | StoreGraph slots          | + op-path        | constraint solving        |
+-----------------+-------------+---------------------------+------------------+---------------------------+
| Shape           | StoreGraph  | Configuration + RefCount  | (limited)        | Reference-count per       |
|                 | + IPA/CPA   | k=2 + EquivClass paths    |                  | program point             |
+-----------------+-------------+---------------------------+------------------+---------------------------+
| flow_sensitive  | standalone  | HeapObject + HeapSelector | HeapPolicy       | Pass-level heap state +   |
|                 |             | + UF aliasing             |                  | strong/weak updates       |
+-----------------+-------------+---------------------------+------------------+---------------------------+
| k-CFA           | standalone  | Variables → pts-to sets   | k-CFA / k-obj    | Source-level points-to +  |
|                 |             |                           | / hybrid         | call graph                |
+-----------------+-------------+---------------------------+---------------------------+

StoreGraph itself is **infrastructure**, not an analysis — it has no solver,
no fixpoint loop, and is never invoked directly.  It is the shared heap model
for IPA, CPA, and Shape.

Bridging between the StoreGraph-based and standalone analyses requires manual
identity mapping — there is no built-in translation layer.
