Shape Analysis
==============

Shape analysis (``pyflow.analysis.shape``) is a region-based analysis that
tracks the structure and properties of data structures.  It operates on the
**store graph** (see :doc:`storegraph`) using CPA's points-to and type results
as input.

Unlike the :doc:`heap` abstraction — which is a fixed-policy model for IFDS
clients answering "which abstract location does this fact point to?" — shape
analysis answers a different question: **"what structural properties does this
data structure have, and how many references point to each field?"**

Pipeline Position
-----------------

Shape analysis runs late in the analysis pipeline, after CPA and IPA::

    AST → Store Graph → CPA + IPA → Shape Analysis → Lifetime Analysis

It consumes CPA's points-to results and the store graph's region information,
then feeds its own results into :doc:`lifetimeanalysis`.

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

The :func:`pyflow.analysis.shape.evaluate` function orchestrates the full shape
analysis:

1. **Region analysis** — groups aliasing objects into regions
2. **Constraint building** — generates constraints from AST operations
3. **Constraint ordering** — topological sort by dependency
4. **Entry point analysis** — binds self/args and solves per entry point
5. **Allocation handling** — processes object allocation sites
6. **Result reporting** — outputs reference counts, field shares, statistics

Key Classes
-----------

.. autosummary::

   pyflow.analysis.shape.RegionBasedShapeAnalysis
   pyflow.analysis.shape.HeapInformationProvider
   pyflow.analysis.shape.OrderConstraints

Relationship to Other Modules
-----------------------------

+------------------+---------------------------------------+----------------------------+
| Module           | Feeds into shape                      | Shape feeds into           |
+==================+=======================================+============================+
| ``storegraph``   | Object nodes, slots, regions          | —                          |
+------------------+---------------------------------------+----------------------------+
| ``cpa``          | Points-to results, canonical objects  | —                          |
+------------------+---------------------------------------+----------------------------+
| ``lifetimeanalysis`` | —                                | Shape ref-count data       |
+------------------+---------------------------------------+----------------------------+
| ``heap``         | — (separate subsystem, IFDS-based)    | —                          |
+------------------+---------------------------------------+----------------------------+

.. note::

   Shape analysis and :doc:`heap` are **independent subsystems** that serve
   different clients.  Shape runs post-CPA on the store graph; heap runs
   alongside IFDS on the CFG supergraph.  They do not feed into each other.
