Flow-Sensitive Alias Analysis
=============================

The ``pyflow.analysis.alias.flow_sensitive`` package provides a canonical,
policy-driven heap model for flow-sensitive alias analysis. Its primary
consumers are IFDS/IDE dataflow clients (taint, nullness, typestate), but
the core model has no IFDS-specific dependencies — it is a standalone
analysis module.  Unlike the storegraph-based analyses (CPA, shape,
lifetime), the heap layer operates on the CFG supergraph and expresses
facts over fixed :class:`HeapLocation` values.

The package was originally part of ``pyflow.analysis.ifds`` and was
extracted into an independent module.  It now has zero IFDS imports:
shared IR utilities live in :mod:`pyflow.analysis.ir_utils`, which both the
flow-sensitive alias analysis and ``ifds`` import from.

.. _heap-vs-shape:

How the analysis differs from shape and storegraph
--------------------------------------------------

+-----------------+--------------------------------------+----------------------------------------+
| Module          | Purpose                              | Runs on                                |
+=================+======================================+========================================+
| flow-sensitive  | Canonical locations, alias tracking, | CFG supergraph (e.g., IFDS)            |
| alias analysis  | strong/weak update policy.  Primarily|                                        |
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

In short, the flow-sensitive alias analysis answers *"which abstract
locations does this fact refer to, and can I strong-update it?"* **shape** answers *"what structural
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

    from pyflow.analysis.alias.flow_sensitive import HeapPolicy, HeapAbstraction

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

The complete flow value contains both heap field/container contents and the
local binding environment.  Consequently, assignments made on one branch are
not visible while analyzing a sibling branch, and the join retains all roots a
local may reference afterward.

The transfer engine owns a ``HeapState`` value map layered on top of
``HeapAbstraction``:

* local assignment binds roots and aliases
* precise field and literal-key writes record values for later reads
* strong writes replace known values; weak writes join old and new values
* wildcard writes such as ``obj[k] = value`` contaminate overlapping exact
  paths instead of flattening unrelated fields or keys
* reads from an exact path return exact values plus any overlapping wildcard
  contamination
* direct calls and finite, fully known function or virtual target sets bind
  actuals to formals and route return locations back to assignment targets;
  multiple result positions remain separate across control-flow joins
* nested calls, lambdas, bound methods, callable instances, recognized method
  decorators, class aliases, and known native callbacks use the same finite
  call evaluator
* collection literals retain element/key-to-value edges even when they are
  nested directly in a return or another expression
* function values retain default and closure-cell reachability
* incomplete reads produce explicit unknown-reference roots rather than
  silently empty sets

Compound control flow is joined path-insensitively:

* ``Switch``/if-like nodes analyze each branch from the incoming state and join
  the resulting states
* loops iterate the body to a bounded fixed point and join the entry state with
  body effects, so zero-iteration and one-or-more-iteration outcomes are both
  represented
* ``try``/``except``/``finally`` joins handler inputs from operation prefixes
  that may throw, then joins possible body and handler states before applying
  ``finally``; ``return``, ``raise``, ``break``, and ``continue`` are modeled as
  explicit exits, so unreachable following statements are not analyzed
* short-circuit expressions join the states where evaluation stops with states
  where later terms execute, preserving conditional calls and named-expression
  assignments
* expression evaluation carries normal and exceptional exits explicitly,
  including calls used directly in conditions and assertions
* generator resumptions join alternative branch yields at the same suspension
  depth and rebase only the delta after the preceding suspension frontier onto
  the caller heap; frame environments and allocation identities persist across
  resumes
* recursive call cycles fall back to conservative return roots

This improves recall for common Python heap flows such as ``obj.x = v`` followed
by ``return obj.x`` and improves precision for unrelated fields or literal
dictionary keys such as ``d["a"]`` versus ``d["b"]``.  It intentionally remains
path-insensitive: facts from different branches are joined in one state rather
than guarded by branch predicates.

Soundness Scope
---------------

The intended soundness contract is a may-analysis over bounded, closed-world
Python IR.  Within that contract, the transfer engine conservatively handles
ordinary assignments and deletes, fields/cells/globals, literal and dynamic
container accesses, unpacking and phi nodes, synchronous and asynchronous
expression forms, definitions, exceptions/finally, direct calls, finite known
indirect/virtual calls, known implicit special-method implementations,
descriptor binding, root-based constructors, ``super()``, and known definition
decorators.
Unconstrained parameters share an explicit unknown root so distinct parameters
are allowed to alias. Heap value queries return a ``PossibleValues`` result
that separates enumerated locations, unknown inclusion, and definite absence.

The contract deliberately excludes unresolved or reflective call targets,
recursive call cycles, and loops that do not converge within the configured
iteration bound. Native code, unknown descriptors/metaclasses, monkey-patching,
and other mutations not represented in the IR likewise require an explicit model.
For those features the result should be treated as a useful conservative model,
not as a proof of whole-Python soundness.

Update Policy
-------------

Writes are represented as ``HeapWrite(location, policy)``.  A write is strong
only when the selector is precise, evaluation produced one receiver root, and
that root has cardinality ``ONE``. Allocation-insensitive roots have
cardinality ``MANY`` even when recency is enabled. Nested field and element
writes additionally require ``allow_strong_nested_fresh``.

Escapes are tracked for:

* values reachable through object fields, containers, globals, cells,
  function defaults, or closures once their owning root escapes
* values returned from procedures
* values passed to unresolved calls

Escape and cardinality are independent: escaping a known singleton does not
turn it into multiple concrete objects.

Alias Tracking
--------------

``HeapAbstraction`` maintains union-find equivalence classes over allocation
sites.  When two locals are aliased (e.g., ``y = x``), their sites are
unified.  Reference counts per equivalence class gate strong updates:
reference counts describe live local bindings, while root cardinality and the
number of possible receivers determine strong-update safety.

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

Known class construction resolves ``__new__`` and ``__init__`` through the
recorded C3 base order. A resolved ``__new__`` controls result identity instead
of being joined with an invented fresh instance, and ``__init__`` is applied
only to results that may be instances of the constructed class.

Program-point snapshots contain the complete flow value rather than heap maps
alone: local bindings, reference values, scalar presence, return slots, yielded
values, and raised values are retained for each labeled outcome. The standalone
engine also publishes outcome-sensitive ``ProcedureHeapSummary`` values.

Collection mutators are also modeled in the heap package.  Value-writing
mutators such as ``append``, ``insert``, ``extend``, ``update``, and
``setdefault`` write wildcard element paths and escape inserted values.
Delete-style mutators such as ``pop`` and ``clear`` remove exact or overlapping
paths without treating removed keys as stored values.

Heap Effects and Summaries
--------------------------

``HeapOperationSemantics`` is the shared operation descriptor consumed by the
standalone transfer, summaries, and IFDS clients. Its ``HeapEffect`` records
reads, writes, deletes, escapes, returns, and allocations without encoding
taint/nullness/typestate-specific facts.

``HeapSummary`` (from :mod:`pyflow.analysis.alias.flow_sensitive.heap_summary`) joins those
effects over a procedure body.  It is a monotone, fixed summary intended for
client reuse and future interprocedural heap-effect composition.
