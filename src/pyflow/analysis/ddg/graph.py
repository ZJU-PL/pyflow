"""
Data Dependence Graph (DDG) data structures.

This module defines the core data structures for representing Data Dependence
Graphs. The DDG is built from dataflowIR graphs and represents data dependencies
between operations.

**Node Types:**
- **Op nodes**: Represent operations from dataflowIR (e.g., GenericOp, Merge, Split)
- **Slot nodes**: Represent storage locations (e.g., LocalNode, FieldNode)

**Edge Types:**
- **def-use**: Operation defines a slot, another operation uses it
- **memory**: Memory dependencies (RAW: Read After Write, WAR: Write After Read, WAW: Write After Write)

**Graph Structure:**
The DDG maintains bidirectional edges (edges_in, edges_out) for efficient
traversal in both directions. Nodes are indexed by their dataflowIR counterparts
for efficient lookup.
"""

from typing import Dict, List, Set, Optional, Any


class DDGEdge(object):
    """
    Represents a data dependence edge in the DDG.
    
    A DDG edge connects two nodes and represents a data dependence relationship.
    The edge kind indicates the type of dependence.
    
    **Edge Kinds:**
    - "def-use": Definition-use dependence (operation defines slot, another uses it)
    - "memory": Memory dependence (RAW, WAR, or WAW hazard)
    - "phi": Phi node dependence (for SSA form)
    
    **Edge Direction:**
    Edges point from producer (source) to consumer (target), indicating that
    the target depends on data produced by the source.
    
    Attributes:
        source: Source node (producer/definer)
        target: Target node (consumer/user)
        kind: Edge kind ("def-use", "memory", "phi", etc.)
        label: Optional label for additional information (e.g., slot name, "RAW")
    """
    __slots__ = ("source", "target", "kind", "label")

    def __init__(self, source: "DDGNode", target: "DDGNode", kind: str, label: str = ""):
        """
        Initialize a data dependence edge.
        
        Args:
            source: Source node (producer)
            target: Target node (consumer)
            kind: Edge kind ("def-use", "memory", etc.)
            label: Optional label for additional information
        """
        self.source = source
        self.target = target
        self.kind = kind  # e.g., "def-use", "mem-read", "mem-write", "phi"
        self.label = label

    def __repr__(self):
        return "DDGEdge(%r -> %r, %s)" % (self.source, self.target, self.kind)


class DDGNode(object):
    """
    Represents a node in the Data Dependence Graph.
    
    A DDG node wraps a dataflowIR node (either an OpNode or SlotNode) and
    tracks its data dependencies through incoming and outgoing edges.
    
    **Node Categories:**
    - "op": Operation node (wraps dataflowIR OpNode)
    - "slot": Slot node (wraps dataflowIR SlotNode)
    - "phi": Phi node (for SSA form, not currently used)
    
    **Dependency Tracking:**
    - edges_in: Edges from nodes this node depends on (producers)
    - edges_out: Edges to nodes that depend on this node (consumers)
    
    **Bidirectional Edges:**
    Edges are stored in both source and target nodes for efficient traversal
    in both directions (forward: find consumers, backward: find producers).
    
    Attributes:
        node_id: Unique identifier for this DDG node
        ir_node: The underlying dataflowIR node (OpNode or SlotNode)
        category: Node category ("op", "slot", "phi")
        edges_in: Set of incoming edges (dependencies)
        edges_out: Set of outgoing edges (dependents)
    """
    __slots__ = ("node_id", "ir_node", "category", "edges_in", "edges_out")

    def __init__(self, node_id: int, ir_node: Any, category: str):
        """
        Initialize a DDG node.
        
        Args:
            node_id: Unique identifier
            ir_node: The underlying dataflowIR node
            category: Node category ("op", "slot", or "phi")
        """
        self.node_id = node_id
        self.ir_node = ir_node  # dataflowIR.OpNode, SlotNode, or SSA Phi/Local
        self.category = category  # "op", "slot", "phi"
        self.edges_in: Set[DDGEdge] = set()
        self.edges_out: Set[DDGEdge] = set()

    def add_edge_to(self, other: "DDGNode", kind: str, label: str = ""):
        """
        Add an edge from this node to another node.
        
        Creates a bidirectional edge, adding it to both nodes' edge sets.
        
        Args:
            other: Target node
            kind: Edge kind ("def-use", "memory", etc.)
            label: Optional edge label
            
        Returns:
            The created DDGEdge
        """
        edge = DDGEdge(self, other, kind, label)
        self.edges_out.add(edge)
        other.edges_in.add(edge)
        return edge

    def __repr__(self):
        return "DDGNode(%d,%s)" % (self.node_id, self.category)

    def __hash__(self):
        return self.node_id

    def __eq__(self, other):
        return isinstance(other, DDGNode) and self.node_id == other.node_id


class DataDependenceGraph(object):
    """
    Main Data Dependence Graph class.
    
    This class represents a complete Data Dependence Graph constructed from
    a dataflowIR graph. It maintains mappings from dataflowIR nodes to DDG nodes
    and provides methods to query and manipulate the graph.
    
    **Node Management:**
    The graph maintains separate mappings for operation nodes and slot nodes,
    allowing efficient lookup by dataflowIR node. Nodes are created on-demand
    and cached to ensure each dataflowIR node has a unique DDG node.
    
    **Edge Management:**
    Provides convenience methods for adding common edge types:
    - add_def_use: Add definition-use edges
    - add_mem_dep: Add memory dependence edges
    
    **Graph Statistics:**
    The stats() method provides summary information about the graph structure.
    
    Attributes:
        nodes: List of all DDG nodes
        _id: Counter for generating unique node IDs
        op_node_map: Mapping from dataflowIR OpNode to DDGNode
        slot_node_map: Mapping from dataflowIR SlotNode to DDGNode
    """
    __slots__ = ("nodes", "_id", "op_node_map", "slot_node_map")

    def __init__(self):
        """Initialize an empty Data Dependence Graph."""
        self.nodes: List[DDGNode] = []
        self._id = 0
        self.op_node_map: Dict[Any, DDGNode] = {}
        self.slot_node_map: Dict[Any, DDGNode] = {}

    def _new_id(self) -> int:
        """
        Generate a new unique node ID.
        
        Returns:
            Unique integer ID
        """
        nid = self._id
        self._id += 1
        return nid

    def get_or_create_op_node(self, ir_op: Any) -> DDGNode:
        """
        Get or create a DDG node for a dataflowIR operation.
        
        If a node already exists for this operation, returns it.
        Otherwise, creates a new node and caches it.
        
        Args:
            ir_op: DataflowIR OpNode
            
        Returns:
            DDGNode for the operation
        """
        node = self.op_node_map.get(ir_op)
        if node is None:
            node = DDGNode(self._new_id(), ir_op, "op")
            self.nodes.append(node)
            self.op_node_map[ir_op] = node
        return node

    def get_or_create_slot_node(self, ir_slot: Any) -> DDGNode:
        """
        Get or create a DDG node for a dataflowIR slot.
        
        If a node already exists for this slot, returns it.
        Otherwise, creates a new node and caches it.
        
        Args:
            ir_slot: DataflowIR SlotNode
            
        Returns:
            DDGNode for the slot
        """
        node = self.slot_node_map.get(ir_slot)
        if node is None:
            node = DDGNode(self._new_id(), ir_slot, "slot")
            self.nodes.append(node)
            self.slot_node_map[ir_slot] = node
        return node

    def add_def_use(self, def_node: DDGNode, use_node: DDGNode, label: str = ""):
        """
        Add a definition-use edge.
        
        Creates an edge from a defining operation to a using operation,
        indicating that the use depends on the definition.
        
        Args:
            def_node: Node that defines a value
            use_node: Node that uses the value
            label: Optional label (typically the slot name)
            
        Returns:
            The created DDGEdge
        """
        return def_node.add_edge_to(use_node, "def-use", label)

    def add_mem_dep(self, src: DDGNode, dst: DDGNode, label: str = ""):
        """
        Add a memory dependence edge.
        
        Creates an edge representing a memory dependence (RAW, WAR, or WAW).
        The label typically indicates the type ("RAW", "WAR", "WAW").
        
        Args:
            src: Source node (earlier operation)
            dst: Destination node (later operation)
            label: Dependence type ("RAW", "WAR", "WAW")
            
        Returns:
            The created DDGEdge
        """
        return src.add_edge_to(dst, "memory", label)

    def all_edges(self) -> List[DDGEdge]:
        """
        Get all edges in the graph.
        
        Returns:
            List of all DDGEdge objects
        """
        result: List[DDGEdge] = []
        for n in self.nodes:
            result.extend(n.edges_out)
        return result

    def stats(self) -> Dict[str, Any]:
        """
        Get statistics about the graph.
        
        Returns:
            Dictionary containing:
            - nodes: Total number of nodes
            - edges: Total number of edges
            - ops: Number of operation nodes
            - slots: Number of slot nodes
        """
        return {
            "nodes": len(self.nodes),
            "edges": len(self.all_edges()),
            "ops": sum(1 for n in self.nodes if n.category == "op"),
            "slots": sum(1 for n in self.nodes if n.category == "slot"),
        }


