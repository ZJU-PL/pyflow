"""
Control Dependence Graph data structures.

This module defines the core data structures for representing Control Dependence Graphs,
including nodes, edges, and the main graph class.

**Data Structure Overview:**
- CDGEdge: Represents a control dependence relationship with a label (true/false/normal)
- CDGNode: Represents a CFG node in the CDG, tracking its dependents and dependencies
- ControlDependenceGraph: The main graph structure that maps CFG nodes to CDG nodes

**Control Dependence Direction:**
In a CDG, edges point from controller to dependent:
- If node A controls node B, there's an edge A -> B
- The edge label indicates the condition (e.g., "true", "false", "normal")
- A node's dependents are nodes it controls
- A node's dependencies are nodes that control it
"""

from typing import Set, Dict, List, Optional, Any
from pyflow.analysis.cfg import graph as cfg_graph


class CDGEdge:
    """
    Represents a control dependence edge in the CDG.
    
    A control dependence edge indicates that the target node's execution is
    controlled by the source node. The label indicates the condition under
    which the target executes.
    
    **Edge Labels:**
    - "true": Target executes when source's condition is true
    - "false": Target executes when source's condition is false
    - "normal": Target executes on normal control flow from source
    - "fail": Target executes on failure/exception path
    - "error": Target executes on error path
    - "control": Generic control dependence (default)
    
    Attributes:
        source: The controlling CDG node
        target: The dependent CDG node
        label: Edge label indicating the control condition
    """
    
    def __init__(self, source: 'CDGNode', target: 'CDGNode', label: str = ""):
        """
        Initialize a control dependence edge.
        
        Args:
            source: The controlling node (where the decision is made)
            target: The dependent node (whose execution is controlled)
            label: Edge label indicating the control condition
        """
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
    """
    Represents a node in the Control Dependence Graph.
    
    A CDG node wraps a CFG node and tracks its control dependence relationships.
    Each node maintains:
    - Dependents: Nodes whose execution this node controls
    - Dependencies: Nodes that control this node's execution
    - Edges: Incoming and outgoing control dependence edges
    
    **Control Dependence Relationships:**
    - If A controls B: B is in A.dependents, A is in B.dependencies
    - The root node (entry terminal) has no dependencies
    - Nodes in the same basic block may share dependencies
    
    Attributes:
        cfg_node: Reference to the original CFG node
        node_id: Unique identifier for this CDG node
        dependents: Set of nodes that are control dependent on this node
        dependencies: Set of nodes that this node is control dependent on
        edges_in: Set of incoming control dependence edges
        edges_out: Set of outgoing control dependence edges
    """
    
    def __init__(self, cfg_node: cfg_graph.CFGBlock, node_id: int):
        """
        Initialize a CDG node.
        
        Args:
            cfg_node: The CFG node this CDG node represents
            node_id: Unique identifier for this CDG node
        """
        self.cfg_node = cfg_node  # Reference to the original CFG node
        self.node_id = node_id    # Unique identifier for this CDG node
        self.dependents: Set[CDGNode] = set()  # Nodes that depend on this node
        self.dependencies: Set[CDGNode] = set()  # Nodes this node depends on
        self.edges_in: Set[CDGEdge] = set()     # Incoming edges
        self.edges_out: Set[CDGEdge] = set()    # Outgoing edges
        
    def add_dependent(self, dependent: 'CDGNode', edge_label: str = ""):
        """
        Add a control dependent node.
        
        Establishes a control dependence relationship where this node controls
        the execution of the dependent node. Updates both nodes' dependency
        sets and creates a bidirectional edge.
        
        Args:
            dependent: The node that becomes control dependent on this node
            edge_label: Label indicating the control condition (e.g., "true", "false")
        """
        if dependent not in self.dependents:
            edge = CDGEdge(self, dependent, edge_label)
            self.dependents.add(dependent)
            dependent.dependencies.add(self)
            self.edges_out.add(edge)
            dependent.edges_in.add(edge)
    
    def remove_dependent(self, dependent: 'CDGNode'):
        """
        Remove a control dependent node.
        
        Removes the control dependence relationship between this node and
        the dependent node. Updates both nodes' dependency sets and removes
        the associated edge.
        
        Args:
            dependent: The node to remove from this node's dependents
        """
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
        """
        Check if this node is control dependent on another node.
        
        Returns True if this node's execution is controlled by the other node.
        
        Args:
            other: The node to check if it controls this node
            
        Returns:
            True if this node is control dependent on other, False otherwise
        """
        return other in self.dependencies
    
    def controls(self, other: 'CDGNode') -> bool:
        """
        Check if this node controls another node.
        
        Returns True if this node controls the execution of the other node.
        
        Args:
            other: The node to check if it's controlled by this node
            
        Returns:
            True if this node controls other, False otherwise
        """
        return other in self.dependents
    
    def get_control_condition(self, dependent: 'CDGNode') -> Optional[str]:
        """
        Get the control condition label for a dependent node.
        
        Returns the edge label that indicates under what condition the
        dependent node executes when controlled by this node.
        
        Args:
            dependent: The dependent node
            
        Returns:
            The edge label (e.g., "true", "false", "normal") or None if
            no such relationship exists
        """
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
    """
    Main Control Dependence Graph class.
    
    This class represents a complete Control Dependence Graph constructed from
    a Control Flow Graph. It maintains a mapping from CFG nodes to CDG nodes
    and provides methods to query control dependence relationships.
    
    **Graph Structure:**
    - Each CFG node has a corresponding CDG node
    - The entry terminal is the root node (has no dependencies)
    - Control dependence edges connect controller nodes to dependent nodes
    
    **Key Operations:**
    - add_node: Create a CDG node for a CFG node
    - add_control_dependence: Establish a control dependence relationship
    - get_control_dependents: Find all nodes controlled by a given node
    - get_control_dependencies: Find all nodes that control a given node
    - is_control_dependent: Check if a control dependence exists
    
    Attributes:
        cfg: The original Control Flow Graph
        nodes: Mapping from CFG nodes to CDG nodes
        node_id_counter: Counter for generating unique node IDs
        root_node: The CDG node corresponding to the CFG entry terminal
    """
    
    def __init__(self, cfg: cfg_graph.Code):
        """
        Initialize a Control Dependence Graph.
        
        Args:
            cfg: The Control Flow Graph to build the CDG from
        """
        self.cfg = cfg
        self.nodes: Dict[cfg_graph.CFGBlock, CDGNode] = {}
        self.node_id_counter = 0
        self.root_node: Optional[CDGNode] = None
        
    def add_node(self, cfg_node: cfg_graph.CFGBlock) -> CDGNode:
        """
        Add a CDG node for the given CFG node.
        
        Creates a CDG node for the specified CFG node if one doesn't already
        exist. If the CFG node is the entry terminal, it's marked as the
        root node of the CDG.
        
        Args:
            cfg_node: The CFG node to create a CDG node for
            
        Returns:
            The CDG node (newly created or existing)
        """
        if cfg_node not in self.nodes:
            cdg_node = CDGNode(cfg_node, self.node_id_counter)
            self.node_id_counter += 1
            self.nodes[cfg_node] = cdg_node
            
            # Set root node if this is the entry terminal
            if cfg_node == self.cfg.entryTerminal:
                self.root_node = cdg_node
                
        return self.nodes[cfg_node]
    
    def get_node(self, cfg_node: cfg_graph.CFGBlock) -> Optional[CDGNode]:
        """
        Get the CDG node for a given CFG node.
        
        Args:
            cfg_node: The CFG node to look up
            
        Returns:
            The corresponding CDG node, or None if not found
        """
        return self.nodes.get(cfg_node)
    
    def add_control_dependence(self, controller: cfg_graph.CFGBlock, 
                              dependent: cfg_graph.CFGBlock, 
                              edge_label: str = ""):
        """
        Add a control dependence edge between two CFG nodes.
        
        Establishes that the dependent node's execution is controlled by the
        controller node. Creates CDG nodes for both if they don't exist.
        
        Args:
            controller: The CFG node that controls execution
            dependent: The CFG node whose execution is controlled
            edge_label: Label indicating the control condition
        """
        controller_node = self.add_node(controller)
        dependent_node = self.add_node(dependent)
        controller_node.add_dependent(dependent_node, edge_label)
    
    def get_control_dependents(self, cfg_node: cfg_graph.CFGBlock) -> Set[CDGNode]:
        """
        Get all nodes that are control dependent on the given CFG node.
        
        Returns the set of CDG nodes whose execution is controlled by the
        specified CFG node.
        
        Args:
            cfg_node: The CFG node to query
            
        Returns:
            Set of CDG nodes that are control dependent on cfg_node
        """
        cdg_node = self.get_node(cfg_node)
        if cdg_node:
            return cdg_node.dependents.copy()
        return set()
    
    def get_control_dependencies(self, cfg_node: cfg_graph.CFGBlock) -> Set[CDGNode]:
        """
        Get all nodes that the given CFG node is control dependent on.
        
        Returns the set of CDG nodes that control the execution of the
        specified CFG node.
        
        Args:
            cfg_node: The CFG node to query
            
        Returns:
            Set of CDG nodes that cfg_node is control dependent on
        """
        cdg_node = self.get_node(cfg_node)
        if cdg_node:
            return cdg_node.dependencies.copy()
        return set()
    
    def is_control_dependent(self, dependent: cfg_graph.CFGBlock, 
                           controller: cfg_graph.CFGBlock) -> bool:
        """
        Check if one CFG node is control dependent on another.
        
        Args:
            dependent: The CFG node whose control dependence is checked
            controller: The CFG node that may control dependent
            
        Returns:
            True if dependent is control dependent on controller, False otherwise
        """
        dependent_node = self.get_node(dependent)
        controller_node = self.get_node(controller)
        
        if dependent_node and controller_node:
            return dependent_node.is_control_dependent_on(controller_node)
        return False
    
    def get_all_nodes(self) -> List[CDGNode]:
        """
        Get all CDG nodes in the graph.
        
        Returns:
            List of all CDG nodes
        """
        return list(self.nodes.values())
    
    def get_all_edges(self) -> List[CDGEdge]:
        """
        Get all control dependence edges in the graph.
        
        Returns:
            List of all CDG edges
        """
        edges = []
        for node in self.nodes.values():
            edges.extend(node.edges_out)
        return edges
    
    def get_control_conditions(self, cfg_node: cfg_graph.CFGBlock) -> Dict[CDGNode, str]:
        """
        Get all control conditions for a given CFG node.
        
        Returns a dictionary mapping dependent nodes to their control condition
        labels for all nodes controlled by the specified CFG node.
        
        Args:
            cfg_node: The CFG node to query
            
        Returns:
            Dictionary mapping dependent CDG nodes to their edge labels
        """
        cdg_node = self.get_node(cfg_node)
        if not cdg_node:
            return {}
        
        conditions = {}
        for edge in cdg_node.edges_out:
            conditions[edge.target] = edge.label
        return conditions
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the CDG.
        
        Computes various statistics including node counts, edge counts,
        node type distribution, and edge label distribution.
        
        Returns:
            Dictionary containing:
            - total_nodes: Total number of nodes
            - total_edges: Total number of edges
            - node_types: Dictionary mapping node type names to counts
            - edge_labels: Dictionary mapping edge labels to counts
            - has_root: Whether the graph has a root node
        """
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
