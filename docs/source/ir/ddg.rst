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
