Shape Analysis
==============

Shape analysis (``pyflow.analysis.shape``) is a region-based analysis that
tracks the structure and properties of data structures.  It operates on the
**store graph** (see :doc:`/ir/storegraph`) using CPA's points-to and type results
as input.

Unlike the :doc:`alias/flow_sensitive` analysis — which is a fixed-policy model for
canonical heap locations (primarily consumed by IFDS clients) — shape
analysis answers a different question: **"what structural properties does this
data structure have, and how many references point to each field?"**

Pipeline Position
-----------------

Shape analysis consumes CPA's points-to results and the store graph's region
information::

    AST → Store Graph → CPA + IPA → Shape Analysis

Unlike IPA, CPA, and lifetime analysis it is not part of the default
``pyflow optimize`` pipeline. Run it explicitly through
``pyflow.analysis.shape.evaluate`` when shape results are needed.

How It Works
------------

Shape analysis builds a constraint system over the store graph and solves it
via a worklist algorithm to a fixed point.  Each constraint models how a
program operation affects object shapes:

* **AssignmentConstraint** — ``x = y`` propagates shape info between variables
* **CopyConstraint** — state propagation through control flow
* **ForgetConstraint** — kills shape info for overwritten variables
* **SplitConstraint** — separates caller/callee state at call sites
* **MergeConstraint** — combines callee results back into caller context

Core Concepts
-------------

Region-based Analysis
~~~~~~~~~~~~~~~~~~~~~

* **Memory Regions** — abstract groups of aliasing objects
* **Configurations** — shape state at a program point (type, region, entry refs, current refs, external refs, allocated flag)
* **Secondary Information** — path-based access information tracking which code paths reach which fields

Reference Tracking
~~~~~~~~~~~~~~~~~~

* **Reference Counts** — how many distinct references point to each field of an object
* **Field Sharing** — whether a field is accessed through multiple references (indicating aliasing)
* **Path Information** — ``(hits, misses)`` tuples tracking which access paths are observed vs absent

Constraint Solving
~~~~~~~~~~~~~~~~~~

* **Worklist Algorithm** — iteratively processes constraints until fixed point
* **Observer Pattern** — constraints register as observers of program points they depend on
* **Topological Ordering** — constraints sorted by dependency for efficient processing

Analysis Pipeline
-----------------

The ``pyflow.analysis.shape.evaluate`` function orchestrates the full shape
analysis:

1. **Region analysis** — groups aliasing objects into regions
2. **Constraint building** — generates constraints from AST operations
3. **Constraint ordering** — topological sort by dependency
4. **Entry point analysis** — binds self/args and solves per entry point
5. **Allocation handling** — processes object allocation sites
6. **Result reporting** — outputs reference counts, field shares, statistics

.. note::

   Shape analysis is a legacy subsystem. Its constraint builder covers the
   operations exercised by the constraint-level tests, but it does not yet
   lower every statement in the modern IR; in particular, module-level
   ``def`` and ``class`` statements are not handled, so ``evaluate`` fails on
   ordinary source files that define functions at module scope. No other
   analysis depends on shape results.

Key Classes
-----------

* ``RegionBasedShapeAnalysis`` — runs the region-based shape analysis.
* ``HeapInformationProvider`` — exposes heap facts to the analysis.
* ``OrderConstraints`` — orders constraints before fixed-point solving.

Relationship to Other Modules
-----------------------------

.. list-table::
   :header-rows: 1

   * - Module
     - Feeds into shape
     - Shape feeds into
   * - ``storegraph``
     - Object nodes, slots, and regions
     - —
   * - ``cpa``
     - Points-to results and canonical objects
     - —
   * - ``lifetimeanalysis``
     - — (a separate subsystem)
     - —
   * - ``alias/flow_sensitive``
     - — (a separate subsystem)
     - —
