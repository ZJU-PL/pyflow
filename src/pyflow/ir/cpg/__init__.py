"""
Code Property Graph (CPG) analysis for PyFlow.

A CPG is a unified multi-layered program graph that composes the Program
Dependence Graph (PDG), Control Flow Graph (CFG), AST structure, and call
graph into a single navigable representation.  It does **not** duplicate
data — every node is a :class:`~pyflow.ir.pdg.graph.PDGNode` and the
CPG adds structural edges (``AST_CHILD``, ``CFG_NEXT``, ``CFG_BRANCH_*``,
``CFG_EXCEPT``, ``CALL``) alongside the existing PDG dependence edges
(``control`` and ``data``).

Typical usage::

    from pyflow.ir.pdg import construct_pdg
    from pyflow.ir.cpg import CodePropertyGraph

    cpg = CodePropertyGraph()
    cpg.add_function("my_func", construct_pdg(cfg))
    cpg.add_call_graph(callgraph)

    # Navigate all layers through a single API
    for child in cpg.ast_children(node):        # AST structure
        ...
    for succ in cpg.cfg_successors(node, kind="CFG_BRANCH_TRUE"):  # CFG
        ...
    for caller in cpg.callers("my_func"):       # Call graph
        ...
    reached = cpg.forward_slice_all(seed)       # Unified slicing
"""

from .graph import (
    CodePropertyGraph,
    CPGEdge,
    CPGEdgeKind,
    CPGNodeView,
    CPGStats,
)
from .dump import to_dot, to_dot_file
from .persist import CPGStore

__all__ = [
    "CodePropertyGraph",
    "CPGEdge",
    "CPGEdgeKind",
    "CPGNodeView",
    "CPGStats",
    "to_dot",
    "to_dot_file",
    "CPGStore",
]
