Intermediate Representations
============================

The ``pyflow.ir`` package contains PyFlow's shared program representations and
graph infrastructure.  Analysis engines in :mod:`pyflow.analysis` consume
these structures; they are kept separate so representations are not confused
with the algorithms that operate on them.

Package Layout
==============

* :doc:`cfg` — Control Flow Graph construction, dominance, and SSA support
* :doc:`cdg` — Control Dependence Graphs
* :doc:`dataflow` — Lowered data flow intermediate representation
* :doc:`ddg` — Data Dependence Graphs
* :doc:`pdg` — Program Dependence Graphs
* :doc:`cpg` — Code Property Graphs and CPG-backed taint infrastructure
* :doc:`storegraph` — Shared heap and points-to representation

The corresponding source and test trees mirror this organization under
``src/pyflow/ir`` and ``tests/ir``.

.. toctree::
   :maxdepth: 2
   :caption: Intermediate Representations

   cfg
   cdg
   dataflow
   ddg
   pdg
   cpg
   storegraph
