"""
Control Dependence Graph construction algorithms.

This module implements algorithms for constructing Control Dependence Graphs
from Control Flow Graphs using dominance frontiers and other techniques.
"""

from typing import Set, Dict, List, Optional, Callable
from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.analysis.cfg import dom
from .graph import ControlDependenceGraph, CDGNode


class CDGConstructor:
    """Constructs Control Dependence Graphs from Control Flow Graphs."""
    
    def __init__(self, cfg: cfg_graph.Code):
        self.cfg = cfg
        self.cdg = ControlDependenceGraph(cfg)
        self.dominance_frontiers: Dict[cfg_graph.CFGBlock, Set[cfg_graph.CFGBlock]] = {}
        self.post_dominators: Dict[cfg_graph.CFGBlock, Set[cfg_graph.CFGBlock]] = {}
        
    def construct(self) -> ControlDependenceGraph:
        """Construct the Control Dependence Graph from the CFG."""
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
        """Build dominance information using the existing dominance analysis."""
        def forward_callback(node):
            """Get successors of a CFG node."""
            return node.normalForward()
        
        def bind_callback(node, dj_node):
            """Bind dominance information to CFG nodes."""
            node.data = dj_node
        
        # Use the existing dominance analysis
        dom.evaluate([self.cfg.entryTerminal], forward_callback, bind_callback)
    
    def _compute_dominance_frontiers(self):
        """Compute dominance frontiers for all nodes."""
        # Initialize dominance frontiers
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
                        while runner != idom.node and runner is not None:
                            if hasattr(runner, 'data') and runner.data:
                                self.dominance_frontiers[runner].add(node)
                            runner = runner.data.idom.node if runner.data and runner.data.idom else None
    
    def _compute_post_dominators(self):
        """Compute post-dominators for all nodes."""
        # Initialize post-dominators
        for node in self._get_all_cfg_nodes():
            self.post_dominators[node] = set()
        
        # Get all nodes reachable from entry
        all_nodes = self._get_all_cfg_nodes()
        
        # For each node, find all nodes that post-dominate it
        for node in all_nodes:
            if node == self.cfg.normalTerminal:
                continue  # Exit node post-dominates itself
            
            # Find all nodes that are on all paths from this node to exit
            for potential_pdom in all_nodes:
                if potential_pdom == node:
                    continue
                
                if self._post_dominates(potential_pdom, node):
                    self.post_dominators[node].add(potential_pdom)
    
    def _post_dominates(self, pdom: cfg_graph.CFGBlock, node: cfg_graph.CFGBlock) -> bool:
        """Check if pdom post-dominates node."""
        # A node post-dominates another if it appears on all paths from that node to exit
        visited = set()
        return self._post_dominates_recursive(pdom, node, visited)
    
    def _post_dominates_recursive(self, pdom: cfg_graph.CFGBlock, 
                                 node: cfg_graph.CFGBlock, 
                                 visited: Set[cfg_graph.CFGBlock]) -> bool:
        """Recursive helper for post-dominance checking."""
        if node == pdom:
            return True
        
        if node in visited or node == self.cfg.normalTerminal:
            return False
        
        visited.add(node)
        
        # Check all successors
        for succ in node.normalForward():
            if not self._post_dominates_recursive(pdom, succ, visited.copy()):
                return False
        
        return True
    
    def _build_control_dependences(self):
        """Build control dependence edges based on dominance frontiers."""
        # First, ensure all CFG nodes have corresponding CDG nodes
        all_cfg_nodes = self._get_all_cfg_nodes()
        # print(f"Debug: Creating CDG nodes for {len(all_cfg_nodes)} CFG nodes")
        
        for cfg_node in all_cfg_nodes:
            self.cdg.add_node(cfg_node)
        
        # For each node in the dominance frontier, create control dependence edges
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
        """Determine the label for a control dependence edge."""
        # Find the edge from controller to dependent in the CFG
        for exit_name, successor in controller.next.items():
            if successor == dependent:
                return exit_name
        
        # If no direct edge, check if it's through a path
        # This is a simplified approach - in practice, you might need more sophisticated logic
        return "control"
    
    def _get_all_cfg_nodes(self) -> List[cfg_graph.CFGBlock]:
        """Get all CFG nodes using BFS traversal."""
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
        
        # print(f"Debug: Found {len(all_nodes)} CFG nodes: {[type(n).__name__ for n in all_nodes]}")
        return all_nodes
    
    def _get_predecessors(self, node: cfg_graph.CFGBlock) -> List[cfg_graph.CFGBlock]:
        """Get all predecessors of a CFG node."""
        predecessors = []
        
        # Find all nodes that have this node as a successor
        for potential_pred in self._get_all_cfg_nodes():
            for exit_name, successor in potential_pred.next.items():
                if successor == node:
                    predecessors.append(potential_pred)
        
        return predecessors
    
    def get_dominance_frontier(self, node: cfg_graph.CFGBlock) -> Set[cfg_graph.CFGBlock]:
        """Get the dominance frontier of a node."""
        return self.dominance_frontiers.get(node, set())
    
    def get_post_dominators(self, node: cfg_graph.CFGBlock) -> Set[cfg_graph.CFGBlock]:
        """Get all post-dominators of a node."""
        return self.post_dominators.get(node, set())
    
    def is_control_dependent(self, dependent: cfg_graph.CFGBlock, 
                           controller: cfg_graph.CFGBlock) -> bool:
        """Check if one node is control dependent on another."""
        return dependent in self.dominance_frontiers.get(controller, set())


def construct_cdg(cfg: cfg_graph.Code) -> ControlDependenceGraph:
    """Convenience function to construct a CDG from a CFG."""
    constructor = CDGConstructor(cfg)
    return constructor.construct()


def analyze_control_dependencies(cfg: cfg_graph.Code) -> Dict[str, any]:
    """Analyze control dependencies in a CFG and return statistics."""
    constructor = CDGConstructor(cfg)
    cdg = constructor.construct()
    
    stats = cdg.get_statistics()
    
    # Add additional analysis
    stats['dominance_frontiers'] = {
        str(node): [str(frontier_node) for frontier_node in frontier]
        for node, frontier in constructor.dominance_frontiers.items()
    }
    
    stats['post_dominators'] = {
        str(node): [str(pdom) for pdom in pdoms]
        for node, pdoms in constructor.post_dominators.items()
    }
    
    return stats
