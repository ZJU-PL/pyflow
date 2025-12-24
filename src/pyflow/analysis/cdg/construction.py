"""
Control Dependence Graph construction algorithms.

This module implements algorithms for constructing Control Dependence Graphs
from Control Flow Graphs using dominance frontiers and post-dominance analysis.

**Construction Algorithm Overview:**

The CDG construction follows these steps:

1. **Build Dominance Information**: Compute dominance relationships using
   the existing dominance analysis framework. This identifies which nodes
   dominate which other nodes in the CFG.

2. **Compute Dominance Frontiers**: For each node X, the dominance frontier
   is the set of nodes Y where:
   - X dominates a predecessor of Y
   - X does not strictly dominate Y
   This identifies where control dependencies begin.

3. **Compute Post-Dominators**: For each node, find all nodes that
   post-dominate it (appear on all paths from that node to exit).

4. **Build Control Dependences**: Create CDG edges based on dominance
   frontiers. If Y is in the dominance frontier of X, then Y is control
   dependent on X.

**Algorithm Details:**

The dominance frontier computation uses the standard algorithm:
- For each node X with immediate dominator idom(X)
- For each predecessor P of X
- Walk up the dominance tree from P to idom(X)
- Add X to the dominance frontier of each node on this path

Post-dominance is computed by checking if a node appears on all paths
from a given node to the exit terminal.

**Edge Labels:**

Control dependence edges are labeled based on the CFG edge that connects
the controller to the dependent node:
- "true": True branch of a conditional
- "false": False branch of a conditional
- "normal": Normal control flow
- "fail": Exception/failure path
- "error": Error path
"""

from typing import Set, Dict, List, Optional, Callable
from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.analysis.cfg import dom
from .graph import ControlDependenceGraph, CDGNode


class CDGConstructor:
    """
    Constructs Control Dependence Graphs from Control Flow Graphs.
    
    This class implements the complete CDG construction algorithm, including
    dominance analysis, dominance frontier computation, post-dominance analysis,
    and control dependence edge creation.
    
    **Construction Process:**
    
    1. Dominance analysis: Uses the existing dominance framework to compute
       immediate dominators for all nodes.
    
    2. Dominance frontier: Computes the set of nodes where dominance ends,
       which identifies control dependence relationships.
    
    3. Post-dominance: Computes which nodes post-dominate each node (appear
       on all paths to exit).
    
    4. Control dependences: Creates CDG edges based on dominance frontiers
       and labels them according to CFG edge types.
    
    Attributes:
        cfg: The Control Flow Graph to build the CDG from
        cdg: The resulting Control Dependence Graph
        dominance_frontiers: Mapping from nodes to their dominance frontiers
        post_dominators: Mapping from nodes to their post-dominators
    """
    
    def __init__(self, cfg: cfg_graph.Code):
        """
        Initialize a CDG constructor.
        
        Args:
            cfg: The Control Flow Graph to construct a CDG from
        """
        self.cfg = cfg
        self.cdg = ControlDependenceGraph(cfg)
        self.dominance_frontiers: Dict[cfg_graph.CFGBlock, Set[cfg_graph.CFGBlock]] = {}
        self.post_dominators: Dict[cfg_graph.CFGBlock, Set[cfg_graph.CFGBlock]] = {}
        
    def construct(self) -> ControlDependenceGraph:
        """
        Construct the Control Dependence Graph from the CFG.
        
        Performs the complete CDG construction process:
        1. Builds dominance information for all nodes
        2. Computes dominance frontiers
        3. Computes post-dominators
        4. Builds control dependence edges
        
        Returns:
            The constructed Control Dependence Graph
        """
        # Step 1: Build dominance information
        self._build_dominance_info()
        
        # Step 2: Compute dominance frontiers
        self._compute_dominance_frontiers()
        
        # Step 3: Compute post-dominators
        self._compute_post_dominators()
        
        # Step 4: Build control dependence edges
        self._build_control_dependences()
        
        return self.cdg
    
    def _build_dominance_info(self):
        """
        Build dominance information using the existing dominance analysis.
        
        Uses the dominance analysis framework to compute immediate dominators
        for all nodes in the CFG. The dominance information is stored in the
        node.data attribute as DJNode objects.
        
        **Dominance Definition:**
        Node A dominates node B if all paths from the entry to B pass through A.
        The immediate dominator (idom) is the closest dominator of a node.
        """
        def forward_callback(node):
            """Get successors of a CFG node."""
            return node.normalForward()
        
        def bind_callback(node, dj_node):
            """Bind dominance information to CFG nodes."""
            node.data = dj_node
        
        # Use the existing dominance analysis framework
        # This computes immediate dominators for all nodes
        dom.evaluate([self.cfg.entryTerminal], forward_callback, bind_callback)
    
    def _compute_dominance_frontiers(self):
        """
        Compute dominance frontiers for all nodes.
        
        The dominance frontier of node X is the set of nodes Y where:
        - X dominates a predecessor of Y
        - X does not strictly dominate Y
        
        **Algorithm:**
        For each node X with immediate dominator idom(X):
        1. For each predecessor P of X
        2. Walk up the dominance tree from P to idom(X)
        3. Add X to the dominance frontier of each node on this path
        
        This identifies where control dependencies begin - nodes in the
        dominance frontier of X are control dependent on X.
        """
        # Initialize dominance frontiers for all nodes
        for node in self._get_all_cfg_nodes():
            self.dominance_frontiers[node] = set()
        
        # Compute dominance frontiers using the standard algorithm
        for node in self._get_all_cfg_nodes():
            if hasattr(node, 'data') and node.data:
                # Get immediate dominator
                idom = node.data.idom
                if idom:
                    # For each predecessor of the current node
                    for pred in self._get_predecessors(node):
                        runner = pred
                        # Walk up the dominance tree until we reach the immediate dominator
                        # All nodes on this path have node in their dominance frontier
                        while runner != idom.node and runner is not None:
                            if hasattr(runner, 'data') and runner.data:
                                self.dominance_frontiers[runner].add(node)
                            runner = runner.data.idom.node if runner.data and runner.data.idom else None
    
    def _compute_post_dominators(self):
        """
        Compute post-dominators for all nodes.
        
        A node A post-dominates node B if all paths from B to the exit
        pass through A. Post-dominance is the reverse of dominance.
        
        **Post-Dominance Definition:**
        Node A post-dominates node B if:
        - All paths from B to the exit terminal pass through A
        - A appears on every execution path from B to exit
        
        This is used to determine control dependencies: if A does not
        post-dominate B, then B may be control dependent on some node
        that controls whether A is reached.
        
        **Note:** This implementation uses a simple path-checking algorithm.
        For large CFGs, a more efficient algorithm using reverse dominance
        analysis would be preferable.
        """
        # Initialize post-dominators for all nodes
        for node in self._get_all_cfg_nodes():
            self.post_dominators[node] = set()
        
        # Get all nodes reachable from entry
        all_nodes = self._get_all_cfg_nodes()
        
        # For each node, find all nodes that post-dominate it
        for node in all_nodes:
            if node == self.cfg.normalTerminal:
                continue  # Exit node post-dominates itself (trivially)
            
            # Find all nodes that are on all paths from this node to exit
            for potential_pdom in all_nodes:
                if potential_pdom == node:
                    continue
                
                if self._post_dominates(potential_pdom, node):
                    self.post_dominators[node].add(potential_pdom)
    
    def _post_dominates(self, pdom: cfg_graph.CFGBlock, node: cfg_graph.CFGBlock) -> bool:
        """
        Check if pdom post-dominates node.
        
        Returns True if pdom appears on all paths from node to the exit terminal.
        This is checked by verifying that all paths from node to exit pass through pdom.
        
        Args:
            pdom: The potential post-dominator node
            node: The node to check post-dominance for
            
        Returns:
            True if pdom post-dominates node, False otherwise
        """
        # A node post-dominates another if it appears on all paths from that node to exit
        visited = set()
        return self._post_dominates_recursive(pdom, node, visited)
    
    def _post_dominates_recursive(self, pdom: cfg_graph.CFGBlock, 
                                 node: cfg_graph.CFGBlock, 
                                 visited: Set[cfg_graph.CFGBlock]) -> bool:
        """
        Recursive helper for post-dominance checking.
        
        Checks if pdom appears on all paths from node to exit by recursively
        exploring all paths. If any path from node to exit doesn't pass through
        pdom, then pdom does not post-dominate node.
        
        Args:
            pdom: The potential post-dominator node
            node: The current node being checked
            visited: Set of nodes already visited in this path
            
        Returns:
            True if all paths from node to exit pass through pdom, False otherwise
        """
        # If we've reached pdom, it's on this path
        if node == pdom:
            return True
        
        # If we've reached exit without finding pdom, or we're in a cycle, pdom doesn't post-dominate
        if node in visited or node == self.cfg.normalTerminal:
            return False
        
        visited.add(node)
        
        # Check all successors: pdom must post-dominate all of them
        for succ in node.normalForward():
            if not self._post_dominates_recursive(pdom, succ, visited.copy()):
                return False
        
        return True
    
    def _build_control_dependences(self):
        """
        Build control dependence edges based on dominance frontiers.
        
        Creates CDG edges for all control dependence relationships identified
        by the dominance frontier analysis. For each node X and each node Y in
        X's dominance frontier, creates an edge X -> Y labeled according to
        the CFG edge type.
        
        **Control Dependence Creation:**
        - If Y is in the dominance frontier of X, then Y is control dependent on X
        - The edge label indicates the condition (true/false/normal/etc.)
        - All CFG nodes get corresponding CDG nodes
        """
        # First, ensure all CFG nodes have corresponding CDG nodes
        all_cfg_nodes = self._get_all_cfg_nodes()
        
        for cfg_node in all_cfg_nodes:
            self.cdg.add_node(cfg_node)
        
        # For each node in the dominance frontier, create control dependence edges
        # If Y is in the dominance frontier of X, then Y is control dependent on X
        for node, frontier in self.dominance_frontiers.items():
            for frontier_node in frontier:
                # Determine the edge label based on the control flow
                edge_label = self._get_control_edge_label(node, frontier_node)
                self.cdg.add_control_dependence(node, frontier_node, edge_label)
        
        # Debug: Print dominance frontiers (commented out for production)
        # print(f"Debug: Found {len(self.dominance_frontiers)} nodes with dominance frontiers")
        # for node, frontier in self.dominance_frontiers.items():
        #     if frontier:
        #         print(f"  Node {type(node).__name__} has frontier: {[type(f).__name__ for f in frontier]}")
        
        # print(f"Debug: CDG now has {len(self.cdg.nodes)} nodes")
    
    def _get_control_edge_label(self, controller: cfg_graph.CFGBlock, 
                               dependent: cfg_graph.CFGBlock) -> str:
        """
        Determine the label for a control dependence edge.
        
        The edge label indicates the condition under which the dependent node
        executes when controlled by the controller node. Labels are derived
        from the CFG edge names (e.g., "true", "false", "normal").
        
        Args:
            controller: The controlling CFG node
            dependent: The dependent CFG node
            
        Returns:
            Edge label string (e.g., "true", "false", "normal", "control")
        """
        # Find the edge from controller to dependent in the CFG
        # The edge name in the CFG indicates the control condition
        for exit_name, successor in controller.next.items():
            if successor == dependent:
                return exit_name
        
        # If no direct edge, use default label
        # This can happen when control dependence is indirect (through multiple edges)
        # In practice, you might need more sophisticated logic to trace the path
        return "control"
    
    def _get_all_cfg_nodes(self) -> List[cfg_graph.CFGBlock]:
        """
        Get all CFG nodes using BFS traversal from the entry terminal.
        
        Performs a breadth-first search starting from the entry terminal
        to collect all reachable nodes in the CFG.
        
        Returns:
            List of all CFG nodes reachable from the entry terminal
        """
        visited = set()
        queue = [self.cfg.entryTerminal]
        all_nodes = []
        
        while queue:
            node = queue.pop(0)
            if node not in visited:
                visited.add(node)
                all_nodes.append(node)
                
                # Add all successors to queue using the next attribute
                if hasattr(node, 'next'):
                    for next_node in node.next.values():
                        if next_node and next_node not in visited:
                            queue.append(next_node)
        
        return all_nodes
    
    def _get_predecessors(self, node: cfg_graph.CFGBlock) -> List[cfg_graph.CFGBlock]:
        """
        Get all predecessors of a CFG node.
        
        Finds all nodes that have the specified node as a successor by
        examining the next attribute of all CFG nodes.
        
        Args:
            node: The CFG node to find predecessors for
            
        Returns:
            List of predecessor CFG nodes
        """
        predecessors = []
        
        # Find all nodes that have this node as a successor
        for potential_pred in self._get_all_cfg_nodes():
            for exit_name, successor in potential_pred.next.items():
                if successor == node:
                    predecessors.append(potential_pred)
        
        return predecessors
    
    def get_dominance_frontier(self, node: cfg_graph.CFGBlock) -> Set[cfg_graph.CFGBlock]:
        """
        Get the dominance frontier of a node.
        
        Args:
            node: The CFG node to query
            
        Returns:
            Set of nodes in the dominance frontier of node
        """
        return self.dominance_frontiers.get(node, set())
    
    def get_post_dominators(self, node: cfg_graph.CFGBlock) -> Set[cfg_graph.CFGBlock]:
        """
        Get all post-dominators of a node.
        
        Args:
            node: The CFG node to query
            
        Returns:
            Set of nodes that post-dominate node
        """
        return self.post_dominators.get(node, set())
    
    def is_control_dependent(self, dependent: cfg_graph.CFGBlock, 
                           controller: cfg_graph.CFGBlock) -> bool:
        """
        Check if one node is control dependent on another.
        
        A node is control dependent on another if it's in that node's
        dominance frontier.
        
        Args:
            dependent: The node whose control dependence is checked
            controller: The node that may control dependent
            
        Returns:
            True if dependent is control dependent on controller, False otherwise
        """
        return dependent in self.dominance_frontiers.get(controller, set())


def construct_cdg(cfg: cfg_graph.Code) -> ControlDependenceGraph:
    """
    Convenience function to construct a CDG from a CFG.
    
    Creates a CDGConstructor, runs the construction algorithm, and returns
    the resulting Control Dependence Graph.
    
    Args:
        cfg: The Control Flow Graph to build a CDG from
        
    Returns:
        The constructed Control Dependence Graph
    """
    constructor = CDGConstructor(cfg)
    return constructor.construct()


def analyze_control_dependencies(cfg: cfg_graph.Code) -> Dict[str, any]:
    """
    Analyze control dependencies in a CFG and return statistics.
    
    Constructs a CDG and returns comprehensive statistics including:
    - CDG structure statistics (nodes, edges, types)
    - Dominance frontiers for all nodes
    - Post-dominators for all nodes
    
    Args:
        cfg: The Control Flow Graph to analyze
        
    Returns:
        Dictionary containing:
        - CDG statistics (from get_statistics())
        - dominance_frontiers: Mapping from nodes to their dominance frontiers
        - post_dominators: Mapping from nodes to their post-dominators
    """
    constructor = CDGConstructor(cfg)
    cdg = constructor.construct()
    
    stats = cdg.get_statistics()
    
    # Add additional analysis information
    stats['dominance_frontiers'] = {
        str(node): [str(frontier_node) for frontier_node in frontier]
        for node, frontier in constructor.dominance_frontiers.items()
    }
    
    stats['post_dominators'] = {
        str(node): [str(pdom) for pdom in pdoms]
        for node, pdoms in constructor.post_dominators.items()
    }
    
    return stats
