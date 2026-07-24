Data Dependence Graph (DDG)
=============================

The Data Dependence Graph module constructs data dependence graphs on top of
PyFlow's data flow IR and SSA infrastructure.  A DDG represents which
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

Graph Structure
---------------

- **Nodes**: Represent operations (ops) and storage locations (slots)
- **Edges**: Def-use edges for data flow, memory edges for heap dependencies

Module Structure
----------------

- ``graph.py`` — Core data structures (``DDGNode``, ``DDGEdge``,
  ``DataDependenceGraph``)
- ``construction.py`` — Algorithms for building DDGs from data flow IR
- ``dump.py`` — Visualization and serialization

.. code-block:: python

   from pyflow.ir.ddg import construct_ddg, DataDependenceGraph

   ddg: DataDependenceGraph = construct_ddg(dataflow_graph)

See Also
--------

- :doc:`dataflow` — The data flow IR that DDGs are built from
- :doc:`pdg` — Program Dependence Graph (combines CDG + DDG)
