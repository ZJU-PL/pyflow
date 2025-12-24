"""
Dumping utilities for Data Dependence Graphs (DDG).

This module provides functionality to dump Data Dependence Graphs in various
formats for visualization, analysis, and debugging.

**Supported Formats:**
- Text: Human-readable text format with statistics and edge listings
- DOT: Graphviz DOT format for visualization
- JSON: Machine-readable JSON format for programmatic analysis

**Visualization Features:**
- Node categorization (ops vs slots) with different shapes
- Edge labeling by kind (def-use, memory)
- Statistics including node counts, edge counts, and category breakdowns
"""

import json
from typing import List

import pyflow.util.pydot as pydot
from .graph import DataDependenceGraph, DDGNode, DDGEdge


class DDGDumper(object):
    """
    Handles dumping and visualization of Data Dependence Graphs.
    
    This class provides methods to export DDGs in various formats for
    visualization, analysis, and debugging. It supports multiple output
    formats with appropriate formatting for each.
    
    **Visualization:**
    - Ops are represented as ellipses
    - Slots are represented as boxes
    - Edges are labeled by kind (def-use, memory)
    
    Attributes:
        ddg: The Data Dependence Graph to dump
    """
    __slots__ = ("ddg",)

    def __init__(self, ddg: DataDependenceGraph):
        """
        Initialize a DDG dumper.
        
        Args:
            ddg: The Data Dependence Graph to dump
        """
        self.ddg = ddg

    def dump_text(self, path: str, title: str = "Data Dependence Graph") -> None:
        """
        Dump DDG in human-readable text format.
        
        Creates a text file containing:
        - Title and header
        - Statistics (node counts, edge counts, category breakdowns)
        - List of all edges with source, target, and kind
        
        Args:
            path: Path to the output file
            title: Title for the output
        """
        with open(path, "w") as f:
            stats = self.ddg.stats()
            f.write("%s\n%s\n\n" % (title, "=" * 60))
            f.write("Nodes: %(nodes)d, Edges: %(edges)d, Ops: %(ops)d, Slots: %(slots)d\n\n" % stats)
            f.write("Edges (source -> target) [kind]:\n")
            for e in self.ddg.all_edges():
                f.write("  %d -> %d [%s]\n" % (e.source.node_id, e.target.node_id, e.kind))

    def dump_dot(self, path: str, title: str = "DDG") -> None:
        """
        Dump DDG in DOT format for visualization with Graphviz.
        
        Creates a DOT file that can be rendered using Graphviz tools.
        Nodes are shaped differently based on category (ops=ellipse, slots=box).
        
        Args:
            path: Path to the output DOT file
            title: Title for the graph
        """
        g = pydot.Dot(graph_type="digraph")
        g.set_label(title)

        # Add nodes with category-specific shapes
        for n in self.ddg.nodes:
            node_id = "n_%d" % n.node_id
            label = "%d\\n%s" % (n.node_id, n.category)
            shape = "ellipse" if n.category == "op" else "box"
            g.add_node(pydot.Node(node_id, label=label, shape=shape))

        # Add edges with kind labels
        for e in self.ddg.all_edges():
            g.add_edge(pydot.Edge("n_%d" % e.source.node_id, "n_%d" % e.target.node_id, label=e.kind))

        with open(path, "w") as f:
            f.write("// DDG\n")
            f.write(g.to_string())

    def dump_json(self, path: str, title: str = "DDG") -> None:
        """
        Dump DDG in JSON format for programmatic analysis.
        
        Creates a JSON file containing:
        - Title and statistics
        - Node information (ID, category)
        - Edge information (source, target, kind)
        
        Args:
            path: Path to the output JSON file
            title: Title for the output
        """
        data = {
            "title": title,
            "stats": self.ddg.stats(),
            "nodes": [
                {"id": n.node_id, "category": n.category}
                for n in self.ddg.nodes
            ],
            "edges": [
                {"src": e.source.node_id, "dst": e.target.node_id, "kind": e.kind}
                for e in self.ddg.all_edges()
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)


def dump_ddg(ddg: DataDependenceGraph, path: str, fmt: str = "text", title: str = "DDG") -> None:
    """
    Convenience function to dump a DDG in various formats.
    
    Args:
        ddg: The Data Dependence Graph to dump
        path: Path to the output file
        fmt: Output format ("text", "dot", or "json")
        title: Title for the output
        
    Raises:
        AttributeError: If the format is not supported
    """
    dumper = DDGDumper(ddg)
    method = getattr(dumper, "dump_%s" % fmt)
    method(path, title)


def dump_ddg_to_directory(ddg: DataDependenceGraph, directory: str, basename: str, formats: List[str] = None) -> None:
    """
    Dump DDG in multiple formats to a directory.
    
    Creates the directory if it doesn't exist and dumps the DDG in all
    specified formats with consistent naming.
    
    Args:
        ddg: The Data Dependence Graph to dump
        directory: Directory path to write files to
        basename: Base name used in filenames
        formats: List of formats to dump (default: ["text", "dot", "json"])
    """
    import os

    formats = formats or ["text", "dot", "json"]
    os.makedirs(directory, exist_ok=True)
    for fmt in formats:
        path = os.path.join(directory, "%s.%s" % (basename, fmt))
        dump_ddg(ddg, path, fmt, basename)


