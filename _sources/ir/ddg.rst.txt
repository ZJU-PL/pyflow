Data Dependence Graph (DDG)
=============================

The Data Dependence Graph module constructs data dependence graphs on top of
PyFlow's CFG and SSA infrastructure. A DDG represents which
operations produce data that is consumed by other operations.

Key Features
------------

- **Def-Use Edges**: Tracks which operations define slots and which operations
  consume them
- **Memory Dependencies**: Models RAW (read-after-write), WAR, and WAW hazards
  for heap operations
- **Program Slicing**: Enables forward and backward slicing by following
  dependence edges
- **Optimization Support**: Identifies independent operations for
  parallelization and dead code elimination

Source-backed DDGs follow CFG program points, branches, exceptional exits,
and loop back-edges. Reaching local definitions are solved to a fixed point,
so accumulators and pointer traversals have loop-carried def-use chains.
For-loop iterable evaluation precedes the header and the index is defined
only on the body edge, preserving zero-iteration bindings.

Memory RAW/WAR/WAW and opaque-call EXTERNAL ordering also follow CFG paths.
Source line numbers are display metadata and never determine execution order.
Mutually exclusive branches remain unordered unless a loop permits their
execution in different iterations. Loop-carried memory edges can point
backward in source order or connect an operation to itself. Heap writes use
conservative weak updates over abstract storage locations; alias imprecision
can still introduce extra dependences. Opaque heap effects require models for
greater precision, and ``except*`` matching remains approximate.

Precision assumptions
---------------------

Source-backed DDGs default to ``DDGConstructionOptions()`` with
``assume_primitive_intrinsics=True`` and ``assume_distinct_parameters=True``.
Known compiler arithmetic/comparison/getitem intrinsics use their modeled
effects instead of acquiring unknown read/write effects. Attribute and
subscript accesses still retain their explicit storage dependences. Ordinary
calls, including calls inside intrinsic arguments and local callables named
``isinstance``, retain unknown heap effects.

Different parameter roots remain separate, and local copy aliases are
resolved at the copy's definition using CFG reaching definitions. Reassigning
``a`` after ``b = a`` does not retarget ``b``. Joins retain all reaching origins.
Walrus reads after a binding in the same statement have explicit def-use
edges, including self-edges at statement granularity; repeated walrus bindings
retain separate local slots.

These are inspection assumptions, not proofs about arbitrary Python objects.
Overloaded operators, custom indexing and instance checks can execute user
code, and arguments can alias. Restore conservative protocol and parameter
modeling explicitly when those behaviors matter::

   from pyflow.ir.ddg import DDGConstructionOptions, construct_ddg

   ddg = construct_ddg(cfg, options=DDGConstructionOptions(
       assume_primitive_intrinsics=False,
       assume_distinct_parameters=False,
   ))

This remains an intraprocedural origin/storage model, not a complete heap
points-to analysis. Recursive origins are summarized; unknown call returns
and shared objects behind heap paths can require additional alias facts.
Text and JSON dumps record the selected assumptions.

Graph Structure
---------------

- **Nodes**: Represent operations (ops) and storage locations (slots)
- **Edges**: Def-use edges for data flow, memory edges for heap dependencies

Module Structure
----------------

- ``graph.py`` — Core data structures (``DDGNode``, ``DDGEdge``,
  ``DataDependenceGraph``)
- ``construction.py`` — CFG and raw-dataflow DDG entrypoints
- ``cfg_construction.py`` — Cyclic CFG def-use and memory dependences
- ``dump.py`` — Visualization and serialization

.. code-block:: python

   from pyflow.ir.ddg import construct_ddg, DataDependenceGraph
   from pyflow.ir.cfg import transform

   cfg = transform.evaluate(compiler, code)
   ddg: DataDependenceGraph = construct_ddg(cfg)

``construct_ddg(dataflow_graph)`` also accepts the result of the source dataflow
converter, which carries a ``control_flow`` snapshot for this purpose. Raw
client-built dataflow graphs without that snapshot retain their supplied
value/operation topology and cannot recover missing control-flow back-edges.

See Also
--------

- :doc:`dataflow` — The data flow IR that DDGs are built from
- :doc:`pdg` — Program Dependence Graph (combines CDG + DDG)
