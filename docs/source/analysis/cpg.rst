Code Property Graph (CPG)
==========================

The Code Property Graph (CPG) unifies a program's **control flow**, **data flow**,
**call graph**, and **AST structure** into a single multi-edge graph. It is the
primary representation used by PyFlow's taint analysis engine.

Overview
--------

The CPG is constructed from one or more :doc:`pdg` instances and optionally a
:doc:`callgraph`. During :meth:`~pyflow.analysis.cpg.CodePropertyGraph.build`,
it derives layered edges on top of the raw PDG edges:

- ``AST_CHILD`` edges from parent → child AST nodes that both have PDG
  representations
- ``CFG_NEXT`` / ``CFG_BRANCH_TRUE`` / ``CFG_BRANCH_FALSE`` / ``CFG_EXCEPT``
  edges derived from the CFG block structure
- ``CALL`` and ``RETURN_EDGE`` edges derived from the attached call graph
- ``DATA`` edges passed through from the PDG (with optional SSA version
  metadata recording)
- ``CONTROL`` edges passed through from the PDG

Node Metadata
-------------

Each CPG node carries a ``meta`` dictionary (accessible via
:meth:`~pyflow.analysis.cpg.CodePropertyGraph.node_meta`) with Ansede-compatible
fields:

- ``node_type`` — AST type name or PDG node kind
- ``lineno`` / ``col`` — source location
- ``value`` — human-readable AST value
- ``func_name`` — enclosing function name
- ``kind`` — PDG node kind
- ``ssa_defs`` / ``ssa_uses`` — SSA version entries (``var``, ``name``,
  ``version``) recorded from DATA edge labels
- ``phi_vars`` — list of variables merged at phi nodes
- ``isinstance_guard`` — flag for isinstance-based type narrowing
- ``lambda_name`` — synthetic name for lambda expressions

Edge Kinds
----------

.. code-block:: python

    CPGEdgeKind.CONTROL         # Control dependence (from PDG)
    CPGEdgeKind.DATA            # Data dependence (from PDG)
    CPGEdgeKind.AST_CHILD       # Parent → child AST node
    CPGEdgeKind.CFG_NEXT        # Sequential control flow
    CPGEdgeKind.CFG_BRANCH_TRUE # True branch
    CPGEdgeKind.CFG_BRANCH_FALSE# False branch
    CPGEdgeKind.CFG_EXCEPT      # Exception edge
    CPGEdgeKind.CALL            # Caller → callee entry
    CPGEdgeKind.RETURN_EDGE     # Callee exit → call site

Programmatic Usage
------------------

.. code-block:: python

    from pyflow.analysis.cpg import CodePropertyGraph, CPGEdgeKind
    from pyflow.analysis.pdg import construct_pdg

    cpg = CodePropertyGraph()
    cpg.add_function("my_func", pdg)
    cpg.build()

    # Iterate nodes
    for node in cpg.nodes("my_func"):
        meta = cpg.node_meta(node)
        print(meta["node_type"], meta["lineno"])

    # Traverse edges
    for edge in cpg.edges():
        print(edge.kind, edge.source.node_id, "->", edge.target.node_id)

    # Export
    dot = cpg.to_dot()
    data = cpg.to_dict()

Taint Analysis
--------------

The CPG is the foundation for PyFlow's taint analysis engine:

.. code-block:: python

    from pyflow.analysis.cpg.taint import CPGTaintEngine

    engine = CPGTaintEngine(
        cpg,
        max_call_depth=5,  # context-sensitive call depth limit
    )
    engine.add_source("request.args")
    engine.add_sink("subprocess.run", cwe="CWE-78")
    findings = engine.find_taint_paths()

The engine supports:

- Context-sensitive visited state (call-context tuple in state key)
- AST-based call name resolution for source/sink matching
- Assign RHS propagation (alias, subscript, f-string, collections)
- Parameterized SQL detection
- isinstance type-guard stripping
- getattr dynamic dispatch detection
- Dict unpack (``**kwargs``) taint propagation
- Ansede-style JSON taint spec loading
- SARIF output for CI/CD integration

CLI Usage
---------

The CPG can be built from the command line:

.. code-block:: bash

    # Build CPG from a Python file and run CPG-backed security analysis
    pyflow security input.py --engine cpg

    # Export CPG as DOT for visualization
    pyflow ir input.py --dump-cpg

Related Modules
---------------

* :doc:`pdg` — Program Dependence Graph (CPG building block)
* :doc:`cfg` — Control Flow Graph (PDG building block)
* :doc:`callgraph` — Call Graph (CPG CALL edges)
