Heap Abstraction
================

The heap abstraction (``pyflow.analysis.heap``) provides a canonical,
policy-driven heap model for IFDS/IDE dataflow clients such as taint,
nullness, and typestate analysis.  Unlike the storegraph-based analyses
(CPA, shape, lifetime), the heap layer operates directly on the IFDS
supergraph and expresses facts over fixed :class:`HeapLocation` values.

The package was extracted from ``pyflow.analysis.ifds`` into an independent
module so that the heap model can evolve separately from IFDS solver
machinery.  The IFDS-dependent submodules (:mod:`heap_effects`,
:mod:`heap_summary`) remain importable through the package while the core
model (:mod:`heap`) has no IFDS dependencies at all.

.. _heap-vs-shape:

How heap differs from shape and storegraph
------------------------------------------

+-----------------+--------------------------------------+----------------------------------------+
| Module          | Purpose                              | Runs on                                |
+=================+======================================+========================================+
| ``heap``        | Canonical locations, alias tracking, | IFDS supergraph (CFG-based)            |
|                 | strong/weak update policy for        |                                        |
|                 | IFDS clients.  Precision is fixed    |                                        |
|                 | before solving.                      |                                        |
+-----------------+--------------------------------------+----------------------------------------+
| ``shape``       | Region-based data-structure          | Store graph, post-CPA pipeline         |
|                 | inference.  Tracks object shapes,    |                                        |
|                 | reference counts, path information   |                                        |
|                 | via iterative fixed-point refinement |                                        |
|                 | using CPA points-to results.         |                                        |
+-----------------+--------------------------------------+----------------------------------------+
| ``storegraph``  | Foundational data model: objects,    | Shared by CPA, IPA, shape, lifetime    |
|                 | slots, regions.  Represents           |                                        |
|                 | points-to relationships.             |                                        |
+-----------------+--------------------------------------+----------------------------------------+
| ``lifetimeanalysis`` | Read/modify and variable lifetime | Store graph, post-shape pipeline       |
|                      | tracking.  Uses CPA and shape     |                                        |
|                      | results.                           |                                        |
+-----------------+--------------------------------------+----------------------------------------+

In short: **heap** answers *"which abstract locations does this IFDS fact
refer to, and can I strong-update it?"*  **shape** answers *"what structural
properties does this data structure have, and how many references point to
each field?"*  **storegraph** is the shared data layer both of the latter two
build on.

Core Model
----------

Heap facts are expressed over ``HeapLocation`` values.  A location has a root
``HeapObject`` and zero or more structural selectors.

Root kinds include:

* locals, globals, cells, modules, parameters, returns
* allocation sites and modeled call returns
* summary, external, unknown, and raw storage roots

Selectors represent object fields and container elements.  Field sensitivity
and container sensitivity are controlled by ``HeapPolicy``::

    from pyflow.analysis.heap import HeapPolicy, HeapAbstraction

    policy = HeapPolicy(
        allocation_sensitivity=AllocationSensitivity.SITE,
        field_sensitivity=FieldSensitivity.NAMED_FIELDS,
        container_sensitivity=ContainerSensitivity.LITERAL_KEYS,
        max_selector_depth=3,
    )
    heap = HeapAbstraction(raw_storage_provider, policy=policy)

Update Policy
-------------

Writes are represented as ``HeapWrite(location, policy)``.  A write is strong
only when the target is singleton-like, precise, fresh, and not escaped.
Nested field and element writes are strong only when
``allow_strong_nested_fresh`` is enabled.

Escapes are tracked for:

* values stored into object fields, containers, globals, or cells
* values returned from procedures
* values passed to unresolved calls

Escaped roots use weak updates.

Alias Tracking
--------------

``HeapAbstraction`` maintains union-find equivalence classes over allocation
sites.  When two locals are aliased (e.g., ``y = x``), their sites are
unified.  Reference counts per equivalence class gate strong updates:
singleton classes allow strong updates; aliased classes force weak updates.

Calls and Constructors
----------------------

Direct call assignments are materialized through fixed return models:

* configured fresh-return names and capitalized constructor-style calls produce
  fresh allocation roots
* configured summary-return names produce weak summary roots
* configured copy-return names such as ``list`` and ``dict`` produce fresh copy
  roots
* other direct call results remain opaque call-result roots

For constructor-style fresh calls, the callee ``self`` formal is bound to the
caller result object.  Writes through ``self.field`` are therefore projected
onto the caller's allocated object.

Heap Effects and Summaries
--------------------------

``HeapEffect`` (from :mod:`pyflow.analysis.heap.heap_effects`) is the
operation-level heap contract shared by IFDS clients.  It records reads,
writes, deletes, escapes, returns, and allocations without encoding
taint/nullness/typestate-specific facts.

``HeapSummary`` (from :mod:`pyflow.analysis.heap.heap_summary`) joins those
effects over a procedure body.  It is a monotone, fixed summary intended for
client reuse and future interprocedural heap-effect composition.

.. note::

   ``heap_effects`` and ``heap_summary`` depend on IFDS utilities
   (``cfg_adapter``, ``transfers``).  They are importable through the
   ``pyflow.analysis.heap`` package but are not auto-imported at package
   level to avoid circular imports.  Import them directly::

       from pyflow.analysis.heap.heap_effects import HeapEffect, HeapEffectBuilder
       from pyflow.analysis.heap.heap_summary import HeapSummary, HeapSummaryBuilder

Known Limits
------------

The abstraction is designed as a heap layer for IFDS clients, not a complete
Python heap analysis.  It does not fully model descriptors, metaclasses,
reflection, monkey-patching, native library behavior, or path-sensitive shape
refinement.  For those concerns, see :doc:`shape` and :doc:`storegraph`.
