"""
CPG DOT export — Graphviz visualization with color-coded edge kinds.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, Optional, Set

from pyflow.ir.cpg.graph import CodePropertyGraph, CPGEdgeKind

_EDGE_COLORS: Dict[CPGEdgeKind, str] = {
    CPGEdgeKind.CONTROL: "darkorange",
    CPGEdgeKind.DATA: "royalblue",
    CPGEdgeKind.AST_CHILD: "darkgreen",
    CPGEdgeKind.CFG_NEXT: "gray40",
    CPGEdgeKind.CFG_BRANCH_TRUE: "forestgreen",
    CPGEdgeKind.CFG_BRANCH_FALSE: "firebrick",
    CPGEdgeKind.CFG_EXCEPT: "darkorchid",
    CPGEdgeKind.CALL: "darkgoldenrod",
    CPGEdgeKind.RETURN_EDGE: "saddlebrown",
}

_NODE_SHAPES: Dict[str, str] = {
    "entry": "invhouse",
    "exit": "house",
    "block": "box",
    "stmt": "ellipse",
    "cond": "diamond",
    "phi": "hexagon",
}


def to_dot(
    cpg: CodePropertyGraph,
    *,
    kinds: Optional[Set[CPGEdgeKind]] = None,
    highlight_nodes: Optional[Set[int]] = None,
) -> str:
    """Export the CPG as a Graphviz DOT string.

    Parameters
    ----------
    cpg:
        A built :class:`CodePropertyGraph`.
    kinds:
        Edge kinds to include (all when ``None``).
    highlight_nodes:
        Node IDs to highlight with a red border.

    Returns
    -------
    str
        DOT-format graph description.
    """
    cpg._ensure_built()
    lines = ["digraph CPG {", "  rankdir=TB;", '  node [fontname="monospace",fontsize=10];',
             '  edge [fontname="monospace",fontsize=8];', ""]

    node_index: Dict[int, int] = {}
    for i, node in enumerate(cpg.nodes()):
        node_index[node.node_id] = i
        shape = _NODE_SHAPES.get(node.kind, "ellipse")
        style = ""
        if highlight_nodes and node.node_id in highlight_nodes:
            style = ' style=filled,fillcolor=lightcoral,penwidth=2'
        label = node.label or node.kind
        if len(label) > 40:
            label = label[:37] + "..."
        label = label.replace('"', '\\"')
        lines.append(
            f'  n{node.node_id} [label="{label}",shape={shape}{style}];'
        )

    lines.append("")
    for edge in cpg.all_edges(kinds=kinds):
        color = _EDGE_COLORS.get(edge.kind, "black")
        elabel = edge.label or ""
        if len(elabel) > 30:
            elabel = elabel[:27] + "..."
        elabel = elabel.replace('"', '\\"')
        lines.append(
            f'  n{edge.source.node_id} -> n{edge.target.node_id} '
            f'[color={color},label="{elabel}",fontcolor={color}];'
        )

    lines.append("")
    lines.append("  // Legend")
    for kind, color in _EDGE_COLORS.items():
        lines.append(f'  //   {kind.value}: {color}')

    lines.append("}")
    return "\n".join(lines)


def to_dot_file(
    cpg: CodePropertyGraph,
    path: str,
    **kwargs: Any,
) -> None:
    """Write a DOT file to *path*."""
    with open(path, "w") as f:
        f.write(to_dot(cpg, **kwargs))
