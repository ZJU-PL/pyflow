Store Graph Analysis
====================

The store graph (``pyflow.analysis.storegraph``) is the **foundational data
model** for object relationships and points-to information in PyFlow.  It is
the shared base that CPA, IPA, shape, and lifetime analyses build on.

Core Concepts
-------------

Object Representation
~~~~~~~~~~~~~~~~~~~~~

* **ObjectNode** — an abstract heap object keyed by an ``ExtendedType``.
  Identity equality is meaningful; two nodes are the same object when they
  have the same canonical type.
* **Slots** — named locations within objects (fields, array elements, locals).
  Root slots are created through ``StoreGraph.root(slot_name)`` and represent
  names that exist independently of any heap object (globals, top-level locals).
* **Regions** — groups of objects that may alias each other.  Regions enable
  the store graph to summarize object sets compactly.

Graph Construction
~~~~~~~~~~~~~~~~~~

* **Allocation Tracking** — records where objects are created
* **Reference Tracking** — maintains which slots point to which objects
* **Field Access** — models attribute and subscript operations
* **Type Propagation** — infers and propagates type information through the graph

Canonical Objects
~~~~~~~~~~~~~~~~~

The store graph uses canonicalization to reduce analysis complexity:

* **Object Canonicalization** — identical types produce identical nodes
* **Set Management** — efficient handling of object sets via region grouping
* **Identity Equality** — graph code relies on ``is`` for nodes, keeping
  points-to sets compact and merge logic cheap

Relationship to Other Modules
-----------------------------

+---------------------+-----------------------------------+
| Module              | How it uses the store graph       |
+=====================+===================================+
| ``cpa``             | Constraint propagation over       |
|                     | points-to relationships           |
+---------------------+-----------------------------------+
| ``ipa``             | Interprocedural analysis across   |
|                     | store graph regions               |
+---------------------+-----------------------------------+
| ``shape``           | Region-based shape inference      |
|                     | using CPA results                 |
+---------------------+-----------------------------------+
| ``lifetimeanalysis``| Read/modify tracking using        |
|                     | shape and CPA results             |
+---------------------+-----------------------------------+
| ``heap``            | **Independent** — operates on the     |
|                     | CFG supergraph (consumed by IFDS),    |
|                     | not the store graph                   |
+---------------------+-----------------------------------+

.. note::

   The :doc:`alias/flow_sensitive` analysis uses its own model (``HeapLocation``,
   ``HeapObject``) and does not depend on the store graph.  Heap is
   primarily consumed by IFDS clients (taint, nullness, typestate);
   store graph serves CPA/shape/lifetime.  These are separate subsystems.
