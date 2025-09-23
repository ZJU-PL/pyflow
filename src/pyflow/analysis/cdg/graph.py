"""
Control Dependence Graph data structures.

This module defines the core data structures for representing Control Dependence Graphs,
including nodes, edges, and the main graph class.
"""

from typing import Set, Dict, List, Optional, Any
from pyflow.analysis.cfg import graph as cfg_graph


class CDGEdge:
    """Represents a control dependence edge in the CDG."""
    
    def __init__(self, source: 'CDGNode', target: 'CDGNode', label: str = ""):
        self.source = source
        self.target = target
        self.label = label  # Edge label (e.g., "true", "false", "normal")
        
    def __repr__(self):
        return f"CDGEdge({self.source} -> {self.target}, '{self.label}')"
    
    def __hash__(self):
        return hash((id(self.source), id(self.target), self.label))
    
    def __eq__(self, other):
        if not isinstance(other, CDGEdge):
            return False
        return (self.source == other.source and 
                self.target == other.target and 
                self.label == other.label)


class CDGNode:
    """Represents a node in the Control Dependence Graph."""
    
    def __init__(self, cfg_node: cfg_graph.CFGBlock, node_id: int):
        self.cfg_node = cfg_node  # Reference to the original CFG node
        self.node_id = node_id    # Unique identifier for this CDG node
        self.dependents: Set[CDGNode] = set()  # Nodes that depend on this node
        self.dependencies: Set[CDGNode] = set()  # Nodes this node depends on
        self.edges_in: Set[CDGEdge] = set()     # Incoming edges
        self.edges_out: Set[CDGEdge] = set()    # Outgoing edges
        
    def add_dependent(self, dependent: 'CDGNode', edge_label: str = ""):
        """Add a control dependent node."""
        if dependent not in self.dependents:
            edge = CDGEdge(self, dependent, edge_label)
            self.dependents.add(dependent)
            dependent.dependencies.add(self)
            self.edges_out.add(edge)
            dependent.edges_in.add(edge)
    
    def remove_dependent(self, dependent: 'CDGNode'):
        """Remove a control dependent node."""
        if dependent in self.dependents:
            # Find and remove the edge
            edge_to_remove = None
            for edge in self.edges_out:
                if edge.target == dependent:
                    edge_to_remove = edge
                    break
            
            if edge_to_remove:
                self.edges_out.remove(edge_to_remove)
                dependent.edges_in.remove(edge_to_remove)
            
            self.dependents.remove(dependent)
            dependent.dependencies.remove(self)
    
    def is_control_dependent_on(self, other: 'CDGNode') -> bool:
        """Check if this node is control dependent on another node."""
        return other in self.dependencies
    
    def controls(self, other: 'CDGNode') -> bool:
        """Check if this node controls another node."""
        return other in self.dependents
    
    def get_control_condition(self, dependent: 'CDGNode') -> Optional[str]:
        """Get the control condition label for a dependent node."""
        for edge in self.edges_out:
            if edge.target == dependent:
                return edge.label
        return None
    
    def __repr__(self):
        return f"CDGNode({self.node_id}, {type(self.cfg_node).__name__})"
    
    def __hash__(self):
        return self.node_id
    
    def __eq__(self, other):
        if not isinstance(other, CDGNode):
            return False
        return self.node_id == other.node_id


class ControlDependenceGraph:
    """Main Control Dependence Graph class."""
    
    def __init__(self, cfg: cfg_graph.Code):
        self.cfg = cfg
        self.nodes: Dict[cfg_graph.CFGBlock, CDGNode] = {}
        self.node_id_counter = 0
        self.root_node: Optional[CDGNode] = None
        
    def add_node(self, cfg_node: cfg_graph.CFGBlock) -> CDGNode:
        """Add a CDG node for the given CFG node."""
        if cfg_node not in self.nodes:
            cdg_node = CDGNode(cfg_node, self.node_id_counter)
            self.node_id_counter += 1
            self.nodes[cfg_node] = cdg_node
            
            # Set root node if this is the entry terminal
            if cfg_node == self.cfg.entryTerminal:
                self.root_node = cdg_node
                
        return self.nodes[cfg_node]
    
    def get_node(self, cfg_node: cfg_graph.CFGBlock) -> Optional[CDGNode]:
        """Get the CDG node for a given CFG node."""
        return self.nodes.get(cfg_node)
    
    def add_control_dependence(self, controller: cfg_graph.CFGBlock, 
                              dependent: cfg_graph.CFGBlock, 
                              edge_label: str = ""):
        """Add a control dependence edge between two CFG nodes."""
        controller_node = self.add_node(controller)
        dependent_node = self.add_node(dependent)
        controller_node.add_dependent(dependent_node, edge_label)
    
    def get_control_dependents(self, cfg_node: cfg_graph.CFGBlock) -> Set[CDGNode]:
        """Get all nodes that are control dependent on the given CFG node."""
        cdg_node = self.get_node(cfg_node)
        if cdg_node:
            return cdg_node.dependents.copy()
        return set()
    
    def get_control_dependencies(self, cfg_node: cfg_graph.CFGBlock) -> Set[CDGNode]:
        """Get all nodes that the given CFG node is control dependent on."""
        cdg_node = self.get_node(cfg_node)
        if cdg_node:
            return cdg_node.dependencies.copy()
        return set()
    
    def is_control_dependent(self, dependent: cfg_graph.CFGBlock, 
                           controller: cfg_graph.CFGBlock) -> bool:
        """Check if one CFG node is control dependent on another."""
        dependent_node = self.get_node(dependent)
        controller_node = self.get_node(controller)
        
        if dependent_node and controller_node:
            return dependent_node.is_control_dependent_on(controller_node)
        return False
    
    def get_all_nodes(self) -> List[CDGNode]:
        """Get all CDG nodes."""
        return list(self.nodes.values())
    
    def get_all_edges(self) -> List[CDGEdge]:
        """Get all CDG edges."""
        edges = []
        for node in self.nodes.values():
            edges.extend(node.edges_out)
        return edges
    
    def get_control_conditions(self, cfg_node: cfg_graph.CFGBlock) -> Dict[CDGNode, str]:
        """Get all control conditions for a given CFG node."""
        cdg_node = self.get_node(cfg_node)
        if not cdg_node:
            return {}
        
        conditions = {}
        for edge in cdg_node.edges_out:
            conditions[edge.target] = edge.label
        return conditions
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the CDG."""
        total_nodes = len(self.nodes)
        total_edges = len(self.get_all_edges())
        
        # Count nodes by type
        node_types = {}
        for node in self.nodes.values():
            node_type = type(node.cfg_node).__name__
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        # Count edges by label
        edge_labels = {}
        for edge in self.get_all_edges():
            label = edge.label or "unlabeled"
            edge_labels[label] = edge_labels.get(label, 0) + 1
        
        return {
            'total_nodes': total_nodes,
            'total_edges': total_edges,
            'node_types': node_types,
            'edge_labels': edge_labels,
            'has_root': self.root_node is not None
        }
    
    def __repr__(self):
        stats = self.get_statistics()
        return f"ControlDependenceGraph(nodes={stats['total_nodes']}, edges={stats['total_edges']})"
