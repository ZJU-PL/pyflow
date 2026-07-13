Heap Abstraction
================

The heap abstraction (``pyflow.analysis.heap``) provides a canonical,
policy-driven heap model for field-sensitive program analysis.  Its primary
consumers are IFDS/IDE dataflow clients (taint, nullness, typestate), but
the core model has no IFDS-specific dependencies — it is a standalone
analysis module.  Unlike the storegraph-based analyses (CPA, shape,
lifetime), the heap layer operates on the CFG supergraph and expresses
facts over fixed :class:`HeapLocation` values.

The package was originally part of ``pyflow.analysis.ifds`` and was
extracted into an independent module.  It now has zero IFDS imports:
shared IR utilities live in :mod:`pyflow.analysis.ir_utils`, which both
``heap`` and ``ifds`` import from.

.. _heap-vs-shape:

How heap differs from shape and storegraph
------------------------------------------

+-----------------+--------------------------------------+----------------------------------------+
| Module          | Purpose                              | Runs on                                |
+=================+======================================+========================================+
| ``heap``        | Canonical locations, alias tracking, | CFG supergraph (e.g., IFDS)            |
|                 | strong/weak update policy.  Primarily|                                        |
|                 | consumed by IFDS clients (taint,     |                                        |
|                 | nullness, typestate).  Precision is  |                                        |
|                 | fixed before solving.                |                                        |
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

In short: **heap** answers *"which abstract locations does this fact
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

Standalone Transfer Engine
--------------------------

``HeapAnalysis`` uses a standalone transfer engine over the code objects
available on a program.  The engine is **flow-sensitive** and
**path-insensitive**: it respects statement order, but it does not maintain
separate path conditions.  This keeps the heap pass lightweight and independent
from the older storegraph/lifetime pipeline.

The transfer engine owns a ``HeapState`` value map layered on top of
``HeapAbstraction``:

* local assignment binds roots and aliases
* precise field and literal-key writes record values for later reads
* strong writes replace known values; weak writes join old and new values
* wildcard writes such as ``obj[k] = value`` contaminate overlapping exact
  paths instead of flattening unrelated fields or keys
* reads from an exact path return exact values plus any overlapping wildcard
  contamination
* direct calls bind actuals to formals and route return locations back to
  assignment targets when a concrete ``Code`` object is available

Compound control flow is joined path-insensitively:

* ``Switch``/if-like nodes analyze each branch from the incoming state and join
  the resulting states
* loops iterate the body to a bounded fixed point and join the entry state with
  body effects, so zero-iteration and one-or-more-iteration outcomes are both
  represented
* ``try``/``except``/``finally`` joins possible body and handler states before
  applying ``finally``
* direct-call summaries are cached by callee and coarse actual root bindings;
  recursive call cycles fall back to conservative return roots

This improves recall for common Python heap flows such as ``obj.x = v`` followed
by ``return obj.x`` and improves precision for unrelated fields or literal
dictionary keys such as ``d["a"]`` versus ``d["b"]``.  It intentionally remains
path-insensitive: facts from different branches are joined in one state rather
than guarded by branch predicates.

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

Direct call assignments are materialized through fixed return models and a
heap-owned intrinsic table:

* configured fresh-return names and capitalized constructor-style calls produce
  fresh allocation roots
* configured summary-return names produce weak summary roots
* configured copy-return names and built-ins such as ``list``, ``dict``,
  ``copy.copy``, ``copy.deepcopy``, and ``dataclasses.replace`` produce fresh
  copy roots
* other direct call results remain opaque call-result roots

Collection mutators are also modeled in the heap package.  Value-writing
mutators such as ``append``, ``insert``, ``extend``, ``update``, and
``setdefault`` write wildcard element paths and escape inserted values.
Delete-style mutators such as ``pop`` and ``clear`` remove exact or overlapping
paths without treating removed keys as stored values.

Heap Effects and Summaries
--------------------------

``HeapEffect`` (from :mod:`pyflow.analysis.heap.heap_effects`) is the
operation-level heap contract shared by analysis clients.  It records reads,
writes, deletes, escapes, returns, and allocations without encoding
taint/nullness/typestate-specific facts.

``HeapSummary`` (from :mod:`pyflow.analysis.heap.heap_summary`) joins those
effects over a procedure body.  It is a monotone, fixed summary intended for
client reuse and future interprocedural heap-effect composition.

Known Limits
------------

The abstraction is primarily consumed by IFDS clients and is not a complete
Python heap analysis.  It does not fully model descriptors, metaclasses,
reflection, monkey-patching, native library behavior, path-sensitive branches,
or path-sensitive shape refinement.  For those concerns, see :doc:`shape` and
:doc:`storegraph`.
