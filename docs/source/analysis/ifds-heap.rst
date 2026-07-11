IFDS Heap Abstraction
=====================

PyFlow's IFDS clients share a fixed heap abstraction for field-sensitive
facts over Python programs.  The heap layer is intentionally policy-driven:
precision is selected before solving and is not adaptively refined during an
IFDS run.

Core Model
----------

Heap facts are expressed over ``HeapLocation`` values.  A location has a root
``HeapObject`` and zero or more structural selectors.

Root kinds include:

* locals, globals, cells, modules, parameters, returns
* allocation sites and modeled call returns
* summary, external, unknown, and raw storage roots

Selectors represent object fields and container elements.  Field sensitivity
and container sensitivity are controlled by ``HeapPolicy``.

Update Policy
-------------

Writes are represented as ``HeapWrite(location, policy)``.  A write is strong
only when the target is singleton-like, precise, fresh, and not escaped.  Nested
field and element writes are strong only when ``allow_strong_nested_fresh`` is
enabled.

Escapes are tracked for:

* values stored into object fields, containers, globals, or cells
* values returned from procedures
* values passed to unresolved calls

Escaped roots use weak updates.

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

``HeapEffect`` is the operation-level heap contract shared by IFDS clients.  It
records reads, writes, deletes, escapes, returns, and allocations without
encoding taint/nullness/typestate-specific facts.

``HeapSummary`` joins those effects over a procedure body.  It is a monotone,
fixed summary intended for client reuse and future interprocedural heap-effect
composition.

Known Limits
------------

The abstraction is designed as an IFDS heap layer, not a complete Python heap
analysis.  It does not fully model descriptors, metaclasses, reflection,
monkey-patching, native library behavior, or path-sensitive shape refinement.
