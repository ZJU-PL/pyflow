"""Call graph analysis module for pointer analysis debugging.

This module provides tools to analyze the call graph after pointer analysis,
computing reachability, identifying unreachable functions, and generating
detailed per-function metrics.
"""

from typing import Dict, Set, List, Any, Optional, TYPE_CHECKING
from collections import defaultdict, deque
import json

if TYPE_CHECKING:
    from pyflow.analysis.pointer._pythonstan.graph.call_graph import AbstractCallGraph
    from .constraints import ConstraintManager, CallConstraint

__all__ = ["CallGraphAnalyzer"]


class CallGraphAnalyzer:
    """Analyzer for call graph metrics and reachability.
    
    Provides methods to compute reachability, identify unreachable functions,
    and generate detailed per-function metrics for debugging.
    """
    
    def __init__(self, call_graph: 'AbstractCallGraph', constraint_manager: 'ConstraintManager'):
        """Initialize analyzer.
        
        Args:
            call_graph: Call graph from pointer analysis
            constraint_manager: Constraint manager with CallConstraints
        """
        self.call_graph = call_graph
        self.constraint_manager = constraint_manager
    
    def compute_reachability(self, entry_points: Optional[List[str]] = None) -> Dict[str, bool]:
        """Compute which functions are reachable from entry points.
        
        Args:
            entry_points: List of entry point function names (if None, uses all nodes with no predecessors)
        
        Returns:
            Dictionary mapping function names to reachability status
        """
        reachable = set()
        
        # Get all nodes
        all_nodes = set(self.call_graph.get_nodes())
        
        # Find entry points if not provided
        if entry_points is None:
            # Find nodes with no incoming edges
            entry_nodes = set()
            for node in all_nodes:
                has_incoming = False
                for edge in self.call_graph.get_edges():
                    if edge.callee == node:
                        has_incoming = True
                        break
                if not has_incoming:
                    entry_nodes.add(node)
        else:
            # Find nodes matching entry point names
            entry_nodes = set()
            for node in all_nodes:
                node_name = str(node.stmt.get_qualname() if hasattr(node.stmt, 'get_qualname') else node.stmt)
                if any(ep in node_name for ep in entry_points):
                    entry_nodes.add(node)
        
        # BFS from entry points
        queue = deque(entry_nodes)
        reachable.update(entry_nodes)
        
        while queue:
            current = queue.popleft()
            
            # Find all callees
            for edge in self.call_graph.get_edges():
                if edge.callsite.scope == current:
                    callee = edge.callee
                    if callee not in reachable:
                        reachable.add(callee)
                        queue.append(callee)
        
        # Build result dictionary
        result = {}
        for node in all_nodes:
            node_name = str(node.stmt.get_qualname() if hasattr(node.stmt, 'get_qualname') else node.stmt)
            result[node_name] = node in reachable
        
        return result
    
    def find_unreachable_functions(self, entry_points: Optional[List[str]] = None) -> List[str]:
        """Find functions with no incoming call edges.
        
        Args:
            entry_points: List of entry point function names
        
        Returns:
            List of unreachable function names
        """
        reachability = self.compute_reachability(entry_points)
        return [name for name, is_reachable in reachability.items() if not is_reachable]
    
    def compute_function_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Compute per-function metrics.
        
        Returns:
            Dictionary mapping function names to their metrics:
            - in_degree: Number of incoming call edges
            - out_degree: Number of outgoing call edges
            - callers: List of caller function names
            - callees: List of callee function names
        """
        metrics = defaultdict(lambda: {
            'in_degree': 0,
            'out_degree': 0,
            'callers': set(),
            'callees': set()
        })
        
        # Process all edges
        for edge in self.call_graph.get_edges():
            # Get caller and callee names
            caller_node = edge.callsite.scope
            callee_node = edge.callee
            
            caller_name = str(caller_node.stmt.get_qualname() if hasattr(caller_node.stmt, 'get_qualname') else caller_node.stmt)
            callee_name = str(callee_node.stmt.get_qualname() if hasattr(callee_node.stmt, 'get_qualname') else callee_node.stmt)
            
            # Update metrics
            metrics[caller_name]['out_degree'] += 1
            metrics[caller_name]['callees'].add(callee_name)
            
            metrics[callee_name]['in_degree'] += 1
            metrics[callee_name]['callers'].add(caller_name)
        
        # Convert sets to lists for JSON serialization
        result = {}
        for func_name, func_metrics in metrics.items():
            result[func_name] = {
                'in_degree': func_metrics['in_degree'],
                'out_degree': func_metrics['out_degree'],
                'callers': list(func_metrics['callers']),
                'callees': list(func_metrics['callees'])
            }
        
        return result
    
    def analyze_call_failures(self) -> Dict[str, Any]:
        """Analyze CallConstraints that didn't result in call edges.
        
        Returns:
            Dictionary with analysis of failed call resolutions:
            - total_constraints: Total number of CallConstraints
            - successful_calls: Number of constraints that created edges
            - failed_calls: Number of constraints without edges
            - failure_locations: List of call sites without edges
        """
        all_call_constraints = self.constraint_manager.get_by_type(CallConstraint)
        total_constraints = len(all_call_constraints)
        
        # Get all call sites from call graph
        successful_call_sites = set()
        for edge in self.call_graph.get_edges():
            call_site = str(edge.callsite.content)
            successful_call_sites.add(call_site)
        
        # Find call constraints without corresponding edges
        failed_call_sites = []
        for constraint in all_call_constraints:
            if hasattr(constraint, 'call_site'):
                call_site = str(constraint.call_site)
                if call_site not in successful_call_sites:
                    failed_call_sites.append(call_site)
        
        return {
            'total_constraints': total_constraints,
            'successful_calls': len(successful_call_sites),
            'failed_calls': len(failed_call_sites),
            'success_rate': len(successful_call_sites) / total_constraints if total_constraints > 0 else 0.0,
            'failure_locations': failed_call_sites[:100]  # Limit output
        }
    
    def compute_call_paths(self, target_function: str, max_depth: int = 10) -> List[List[str]]:
        """Compute call paths to a target function.
        
        Args:
            target_function: Target function name
            max_depth: Maximum path depth
        
        Returns:
            List of call paths (each path is a list of function names)
        """
        paths = []
        
        # Find target node
        target_nodes = []
        for node in self.call_graph.get_nodes():
            node_name = str(node.stmt.get_qualname() if hasattr(node.stmt, 'get_qualname') else node.stmt)
            if target_function in node_name:
                target_nodes.append(node)
        
        if not target_nodes:
            return []
        
        # For each target node, find paths using DFS
        for target_node in target_nodes:
            visited = set()
            current_path = []
            self._dfs_paths(target_node, visited, current_path, paths, max_depth)
        
        return paths
    
    def _dfs_paths(
        self,
        node: Any,
        visited: Set[Any],
        current_path: List[str],
        all_paths: List[List[str]],
        max_depth: int
    ):
        """DFS helper for computing call paths."""
        if len(current_path) >= max_depth:
            return
        
        if node in visited:
            return
        
        visited.add(node)
        node_name = str(node.stmt.get_qualname() if hasattr(node.stmt, 'get_qualname') else node.stmt)
        current_path.append(node_name)
        
        # Find callers
        has_callers = False
        for edge in self.call_graph.get_edges():
            if edge.callee == node:
                has_callers = True
                caller_node = edge.callsite.scope
                self._dfs_paths(caller_node, visited, current_path[:], all_paths, max_depth)
        
        # If no callers, this is a complete path
        if not has_callers:
            all_paths.append(current_path[::-1])  # Reverse to show root to target
        
        visited.remove(node)
    
    def export_detailed_report(self, output_file: str):
        """Export detailed analysis report to JSON.
        
        Args:
            output_file: Path to output JSON file
        """
        report = {
            'call_graph_stats': {
                'total_nodes': len(self.call_graph.get_nodes()),
                'total_edges': self.call_graph.get_number_of_edges()
            },
            'function_metrics': self.compute_function_metrics(),
            'call_failure_analysis': self.analyze_call_failures(),
            'unreachable_functions': self.find_unreachable_functions()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics for debugging.
        
        Returns:
            Dictionary with summary statistics
        """
        function_metrics = self.compute_function_metrics()
        
        # Compute statistics
        in_degrees = [m['in_degree'] for m in function_metrics.values()]
        out_degrees = [m['out_degree'] for m in function_metrics.values()]
        
        return {
            'total_functions': len(function_metrics),
            'functions_with_no_callers': sum(1 for m in function_metrics.values() if m['in_degree'] == 0),
            'functions_with_no_callees': sum(1 for m in function_metrics.values() if m['out_degree'] == 0),
            'avg_in_degree': sum(in_degrees) / len(in_degrees) if in_degrees else 0.0,
            'avg_out_degree': sum(out_degrees) / len(out_degrees) if out_degrees else 0.0,
            'max_in_degree': max(in_degrees) if in_degrees else 0,
            'max_out_degree': max(out_degrees) if out_degrees else 0,
            'call_failure_analysis': self.analyze_call_failures()
        }

