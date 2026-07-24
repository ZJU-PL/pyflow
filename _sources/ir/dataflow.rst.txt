Data Flow Intermediate Representation
=====================================

PyFlow's data flow IR provides a lowered, instruction-level representation of
Python programs for data flow analysis.  It decomposes Python AST nodes into
a linear sequence of operations and storage slots, making it the foundation
for both intra- and inter-procedural data flow analyses.

Key Features
------------

- **Linearized Operations**: Python expressions are broken into primitive ops
  (load, store, call, binary, unary, etc.)
- **SSA Integration**: Converts data flow IR into Static Single Assignment
  form for precise use-def chains
- **Dependency Tracking**: Tracks data dependencies between operations for
  program slicing and optimization
- **Type Annotations**: Associates type information with operations and slots

Core Components
---------------

Graph Model
~~~~~~~~~~~

The data flow graph represents a function as a sequence of operations connected
by data dependencies.  Each operation produces a result stored in a slot, and
slots are consumed by subsequent operations.

.. code-block:: python

   from pyflow.ir.dataflow.convert import CodeToDataflow

   converter = CodeToDataflow()
   dataflow_graph = converter.convert(cfg_block)

Usage
-----

Data flow IR is used internally by many subsystems:

- **IFDS/IDE solver**: builds supergraphs from dataflow IR
- **DDG construction**: derives data dependence edges from def-use chains
- **Optimization passes**: load/store elimination, dead code elimination
- **Analysis clients**: taint, nullness, typestate tracking

See Also
--------

- :doc:`/analysis/fsdf` — Flow-Sensitive Data Flow analysis over data flow IR
- :doc:`/analysis/ifds` — IFDS/IDE interprocedural engine consuming data flow IR
- :doc:`ddg` — Data Dependence Graph built on dataflow IR
