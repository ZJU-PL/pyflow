"""
Control Dependence Graph visualization and dumping functionality.

This module provides functionality to visualize and dump Control Dependence Graphs
in various formats for analysis, debugging, and documentation purposes.

**Supported Formats:**
- Text: Human-readable text format with statistics and relationships
- DOT: Graphviz DOT format for visualization
- JSON: Machine-readable JSON format for programmatic analysis
- Clang-style: Output similar to Clang's CDG representation

**Visualization Features:**
- Color-coded nodes by type (Entry, Exit, Suite, Switch, etc.)
- Color-coded edges by label (true, false, normal, etc.)
- Statistics including node counts, edge counts, and distributions
- Control dependency relationships in both directions
"""

import os
import json
from typing import Dict, List, Set, Any, Optional
import pyflow.util.pydot as pydot
from pyflow.util.io import filesystem
from .graph import ControlDependenceGraph, CDGNode, CDGEdge


class CDGDumper:
    """
    Handles dumping and visualization of Control Dependence Graphs.
    
    This class provides methods to export CDGs in various formats for
    visualization, analysis, and debugging. It supports multiple output
    formats and provides color-coding for better readability.
    
    **Color Scheme:**
    - Nodes: Color-coded by CFG node type (Entry=light green, Exit=light pink, etc.)
    - Edges: Color-coded by control condition (true=green, false=red, normal=blue, etc.)
    
    Attributes:
        cdg: The Control Dependence Graph to dump
        _colors: Color mappings for nodes and edges
    """
    
    def __init__(self, cdg: ControlDependenceGraph):
        """
        Initialize a CDG dumper.
        
        Args:
            cdg: The Control Dependence Graph to dump
        """
        self.cdg = cdg
        # Color scheme for visualization
        self._colors = {
            'nodes': {'Entry': '#90EE90', 'Exit': '#FFB6C1', 'Suite': '#87CEEB', 
                     'Switch': '#DDA0DD', 'Merge': '#F0E68C', 'State': '#FFA07A', 'Yield': '#98FB98'},
            'edges': {'true': '#00FF00', 'false': '#FF0000', 'normal': '#0000FF', 
                     'fail': '#FFA500', 'error': '#800080', 'control': '#000000'}
        }
    
    def dump_text(self, output_file: str, function_name: str = ""):
        """
        Dump CDG in human-readable text format.
        
        Creates a text file containing:
        - Header with function name (if provided)
        - Statistics (node counts, edge counts, distributions)
        - Control dependency relationships (both directions)
        
        Args:
            output_file: Path to the output file
            function_name: Optional function name for the header
        """
        with open(output_file, 'w') as f:
            self._write_header(f, function_name)
            self._write_statistics(f)
            self._write_control_relations(f)
    
    def _write_header(self, f, function_name: str):
        """
        Write file header.
        
        Args:
            f: File handle to write to
            function_name: Optional function name
        """
        title = f"Control Dependence Graph{' for function: {function_name}' if function_name else ''}"
        f.write(f"{title}\n{'=' * 60}\n\n")
    
    def _write_statistics(self, f):
        """
        Write statistics section.
        
        Writes node counts, edge counts, node type distribution, and
        edge label distribution.
        
        Args:
            f: File handle to write to
        """
        stats = self.cdg.get_statistics()
        f.write(f"Statistics:\n  Total nodes: {stats['total_nodes']}\n  Total edges: {stats['total_edges']}\n  Has root: {stats['has_root']}\n\n")
        
        for section, data in [("Node types", stats['node_types']), ("Edge labels", stats['edge_labels'])]:
            f.write(f"{section}:\n")
            f.writelines(f"  {k}: {v}\n" for k, v in data.items())
            f.write("\n")
    
    def _write_control_relations(self, f):
        """
        Write control dependency relationships.
        
        Writes both directions:
        - Control Dependencies: Nodes controlled by each node
        - Control Dependents: Nodes that control each node
        
        Args:
            f: File handle to write to
        """
        for title, attr, arrow in [("Control Dependencies", 'dependents', '->'), ("Control Dependents", 'dependencies', '<-')]:
            f.write(f"{title}:\n{'-' * 40}\n")
            for cfg_node, cdg_node in self.cdg.nodes.items():
                relations = getattr(cdg_node, attr)
                if relations:
                    f.write(f"\nNode {cdg_node.node_id} ({type(cfg_node).__name__}) {title.lower().replace(' ', ' ')}:")
                    for rel in relations:
                        edge_label = (cdg_node if arrow == '->' else rel).get_control_condition(rel if arrow == '->' else cdg_node)
                        f.write(f"\n  {arrow} Node {rel.node_id} ({type(rel.cfg_node).__name__}) [{edge_label}]")
            f.write("\n\n" if title == "Control Dependencies" else "\n")
    
    def dump_dot(self, output_file: str, function_name: str = ""):
        """
        Dump CDG in DOT format for visualization with Graphviz.
        
        Creates a DOT file that can be rendered using Graphviz tools like
        dot, neato, or circo. The graph includes color-coded nodes and edges
        for better visualization.
        
        Args:
            output_file: Path to the output DOT file
            function_name: Optional function name for the graph label
        """
        graph = pydot.Dot(graph_type="digraph")
        graph.set_label(f"Control Dependence Graph{f' for {function_name}' if function_name else ''}")
        graph.set_rankdir("TB")  # Top to bottom layout
        
        # Add nodes and edges
        for cfg_node, cdg_node in self.cdg.nodes.items():
            self._add_dot_node(graph, cfg_node, cdg_node)
        
        for edge in self.cdg.get_all_edges():
            self._add_dot_edge(graph, edge)
        
        with open(output_file, 'w') as f:
            f.write(f"// Control Dependence Graph{f' for function: {function_name}' if function_name else ''}\n")
            f.write(graph.to_string())
    
    def _add_dot_node(self, graph, cfg_node, cdg_node):
        """
        Add a node to the DOT graph.
        
        Creates a DOT node with:
        - Node ID and type as label
        - Optional operation count
        - Color based on node type
        - Box shape with filled style
        
        Args:
            graph: The pydot graph to add to
            cfg_node: The CFG node
            cdg_node: The CDG node
        """
        node_id = f"node_{cdg_node.node_id}"
        label = f"{cdg_node.node_id}\\n{type(cfg_node).__name__}"
        if hasattr(cfg_node, 'ops') and cfg_node.ops:
            label += f"\\n{len(cfg_node.ops)} ops"
        
        graph.add_node(pydot.Node(node_id, label=label, shape="box", style="filled", 
                                 fillcolor=self._get_color(cfg_node), fontsize=10))
    
    def _add_dot_edge(self, graph, edge):
        """
        Add an edge to the DOT graph.
        
        Creates a DOT edge with:
        - Source and target node IDs
        - Edge label (control condition)
        - Color based on edge label
        
        Args:
            graph: The pydot graph to add to
            edge: The CDG edge to add
        """
        graph.add_edge(pydot.Edge(f"node_{edge.source.node_id}", f"node_{edge.target.node_id}",
                                 label=edge.label or "control", color=self._get_color(edge.label, 'edges'), fontsize=8))
    
    def dump_json(self, output_file: str, function_name: str = ""):
        """
        Dump CDG in JSON format for programmatic analysis.
        
        Creates a JSON file containing:
        - Function name
        - Statistics
        - Node information (ID, type, dependents, dependencies)
        - Edge information (source, target, label)
        
        Args:
            output_file: Path to the output JSON file
            function_name: Optional function name
        """
        data = {
            "function_name": function_name,
            "statistics": self.cdg.get_statistics(),
            "nodes": [self._node_to_dict(cfg_node, cdg_node) for cfg_node, cdg_node in self.cdg.nodes.items()],
            "edges": [{"source": e.source.node_id, "target": e.target.node_id, "label": e.label} 
                     for e in self.cdg.get_all_edges()]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _node_to_dict(self, cfg_node, cdg_node):
        """
        Convert a node to dictionary format for JSON serialization.
        
        Args:
            cfg_node: The CFG node
            cdg_node: The CDG node
            
        Returns:
            Dictionary containing node information
        """
        node_data = {
            "id": cdg_node.node_id,
            "type": type(cfg_node).__name__,
            "cfg_node_id": id(cfg_node),
            "dependents": [dep.node_id for dep in cdg_node.dependents],
            "dependencies": [dep.node_id for dep in cdg_node.dependencies]
        }
        
        # Add optional fields if present
        if hasattr(cfg_node, 'ops'):
            node_data["ops_count"] = len(cfg_node.ops) if cfg_node.ops else 0
        if hasattr(cfg_node, 'condition'):
            node_data["condition"] = str(cfg_node.condition) if cfg_node.condition else None
        
        return node_data
    
    def _get_color(self, obj, category='nodes') -> str:
        """
        Get color for nodes or edges based on type/label.
        
        Args:
            obj: The node or edge to get color for
            category: 'nodes' or 'edges'
            
        Returns:
            Color string in hex format (e.g., '#FF0000')
        """
        key = type(obj).__name__ if category == 'nodes' else obj
        return self._colors[category].get(key, '#E0E0E0' if category == 'nodes' else '#666666')
    
    def generate_clang_style_cdg(self) -> str:
        """
        Generate clang-style CDG representation.
        
        Creates a text representation similar to Clang's CDG output format,
        grouping nodes by their controllers and showing control relationships
        in a hierarchical structure.
        
        Returns:
            String containing the clang-style CDG representation
        """
        content = "Control Dependence Graph:\n"
        
        # Group nodes by their primary controller (minimum node ID)
        groups = {}
        for cfg_node, cdg_node in self.cdg.nodes.items():
            controller = min(cdg_node.dependencies, key=lambda x: x.node_id) if cdg_node.dependencies else None
            groups.setdefault(controller, []).append(cdg_node)
        
        # Write groups hierarchically
        for controller, dependents in groups.items():
            content += f"\n{'Root nodes' if controller is None else f'Controlled by Node {controller.node_id}'}:\n"
            for dep in dependents:
                content += f"  Node {dep.node_id} ({type(dep.cfg_node).__name__})\n"
                if dep.dependents:
                    content += "    Controls:\n"
                    content += "\n".join(f"      -> Node {d.node_id} [{dep.get_control_condition(d)}]" for d in dep.dependents) + "\n"
        
        return content


def dump_cdg(cdg: ControlDependenceGraph, output_file: str, 
            format: str = "text", function_name: str = ""):
    """
    Convenience function to dump a CDG in various formats.
    
    Args:
        cdg: The Control Dependence Graph to dump
        output_file: Path to the output file
        format: Output format ("text", "dot", or "json")
        function_name: Optional function name for headers/labels
        
    Raises:
        ValueError: If the format is not supported
    """
    dumper = CDGDumper(cdg)
    method = getattr(dumper, f"dump_{format}", None)
    if not method:
        raise ValueError(f"Unsupported format: {format}")
    method(output_file, function_name)


def dump_cdg_to_directory(cdg: ControlDependenceGraph, directory: str, 
                         function_name: str, formats: List[str] = None):
    """
    Dump CDG in multiple formats to a directory.
    
    Creates the directory if it doesn't exist and dumps the CDG in all
    specified formats with consistent naming.
    
    Args:
        cdg: The Control Dependence Graph to dump
        directory: Directory path to write files to
        function_name: Function name used in filenames
        formats: List of formats to dump (default: ["text", "dot", "json"])
    """
    formats = formats or ["text", "dot", "json"]
    os.makedirs(directory, exist_ok=True)
    
    for fmt in formats:
        output_file = os.path.join(directory, f"{function_name}_cdg.{fmt}")
        dump_cdg(cdg, output_file, fmt, function_name)
        print(f"CDG dumped to: {output_file}")
