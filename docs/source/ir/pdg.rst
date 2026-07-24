Program Dependence Graph (PDG)
==============================

The Program Dependence Graph (PDG) combines **control dependences** and **data dependences**
into a single graph that supports dependency queries and program slicing.

Overview
--------

PyFlow's PDG is an intraprocedural graph (single function) constructed from the CFG:

- **Control dependence** edges are derived using post-dominator information on the CFG.
- **Data dependence** edges are derived from local def-use sets extracted from the CFG's AST.

For higher precision data dependences, PDG construction can run SSA + phi expansion on the CFG.

Programmatic usage
------------------

.. code-block:: python

   from pyflow.ir.cfg import transform
   from pyflow.ir.pdg import construct_pdg

   cfg = transform.evaluate(compiler, code)
   pdg = construct_pdg(cfg, run_ssa=True, include_control=True, include_data=True)

   # Backward slice from a seed node
   seeds = [n for n in pdg.nodes if n.kind == "stmt"]
   slice_nodes = pdg.backward_slice(seeds)

Applications
------------

- Program slicing (forward/backward)
- Impact analysis and debugging
- Dependency-aware optimization and refactoring
- Analysis features that require both control and data context

Cypher-like queries
-------------------

The PDG supports a small in-memory Cypher-like query language (no Neo4j) for
interactive exploration.

.. code-block:: python

   rows = pdg.cypher(
       'MATCH (a:stmt)-[e:data]->(b:stmt) '
       'WHERE e.label = "y" '
       'RETURN a.node_id AS src, b.node_id AS dst '
       'LIMIT 20'
   )

Supported subset includes:

- ``MATCH`` node/edge patterns: ``(n:stmt)``, ``(a)-[:data]->(b)``, ``(a)<-[:control]-(b)``
- ``WHERE``: boolean expressions over properties (e.g. ``n.kind``, ``e.label``) and ``$params``
- ``RETURN``: variables and property access, plus ``RETURN *``
- ``ORDER BY`` and ``LIMIT``
