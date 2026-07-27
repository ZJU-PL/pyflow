Code Property Graph (CPG)
==========================

The Code Property Graph (CPG) unifies a program's **control flow**, **data flow**,
**call graph**, and **AST structure** into a single multi-edge graph. It is the
primary representation used by PyFlow's taint analysis engine.

Overview
--------

The CPG is constructed from one or more :doc:`pdg` instances and optionally a
:doc:`/analysis/callgraph`. During :meth:`~pyflow.ir.cpg.CodePropertyGraph.build`,
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
:meth:`~pyflow.ir.cpg.CodePropertyGraph.node_meta`) with Ansede-compatible
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

    from pyflow.ir.cpg import CodePropertyGraph, CPGEdgeKind
    from pyflow.ir.pdg import construct_pdg

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

The CPG engine is a monotone fixed-point analysis over an immutable product
lattice. It consumes the same strict-v2 typed taint policy and shared access-path
domain as the IFDS and AST-dataflow engines:

.. code-block:: python

    from pyflow.analysis.ifds.modeling.registry import load_registry
    from pyflow.ir.cpg.taint import CPGTaintEngine

    registry = load_registry()
    registry.activate("stdlib", "flask", type="taint")
    engine = CPGTaintEngine(cpg, policy=registry.as_taint_policy())
    findings = engine.find_taint_paths()

Manual ``add_source``, ``add_sink``, and ``add_sanitizer`` calls remain
available for programmatic one-off policies. They do not install hidden default
models; a newly constructed engine has an empty policy unless one is supplied.

Its formal state maps function-scoped access paths to origin- and kind-sensitive
taint facts, plus a finite may-alias relation. CFG edges define executable
order. DATA edges are consulted as dependence evidence for witness construction
and reported in run statistics; they are deliberately not treated as executable
shortcuts because doing so could jump over a strong overwrite. Local ``CALL``
and ``RETURN_EDGE`` edges use a bounded call string and returns are matched to
the active call site.
Every procedure is also analyzed as a potential public entry, so exported
library functions and recursive call-graph SCCs are not lost merely because
their external callers are absent. At recursion or the context bound, the
engine applies a finite relational procedure summary (parameter-to-return,
source-to-return, and parameter/source-to-sink dependencies).

The engine supports:

- Immutable lattice states with a monotone worklist and explicit bottom/join
- Context-sensitive call strings with matched call/return transitions
- Fixed-point relational summaries for nested and recursive local calls
- Strong local overwrites and refinement-controlled heap updates
- Shared syntactic or points-to-backed heap refinement providers
- AST-based call name resolution for source/sink matching
- Strict-v2 typed sources, sinks, sink ports, sanitizers, and flow rules
- Kind-scoped sanitizer guarantees and sanitizer provenance
- Conservative unknown-call return and side-effect havoc
- Explicit ``complete``/``partial`` status, structured precision diagnostics,
  and state/time budgets
- Executable source-to-sink witness paths in JSON and SARIF ``codeFlows``
- SARIF output for CI/CD integration

``max_loop_iterations`` is a convergence-reporting threshold, not an unsound
loop cutoff: the solver continues to the lattice fixed point and records a
conservative diagnostic if a loop needs more updates. ``max_states`` and
``max_seconds`` are explicit hard budgets and therefore make the result
``partial`` when exhausted.

Soundness boundaries are surfaced rather than hidden. Unknown external calls
produce an ``unsupported`` diagnostic and conservative havoc; AST-local PDG
dependence fallback, missing graph entry/exit structure, unmatched return edges,
and unsupported transfers likewise appear in ``result.diagnostics``. A
``complete`` result means none of the encountered boundaries were classified as
assumed or unsupported; it does not claim that the configured source, sink, and
sanitizer policy is complete for every third-party library.

CLI Usage
---------

The CPG can be built from the command line:

.. code-block:: bash

    # Build CPG from a Python file and run CPG-backed security analysis
    pyflow security input.py --engine cpg

    # Export CPG representation via IR dump (see pyflow ir for available dump options)


Related Modules
---------------

* :doc:`pdg` — Program Dependence Graph (CPG building block)
* :doc:`cfg` — Control Flow Graph (PDG building block)
* :doc:`/analysis/callgraph` — Call Graph (CPG CALL edges)
