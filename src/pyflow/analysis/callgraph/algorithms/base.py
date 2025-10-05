"""Base classes for call graph algorithms.

This module provides the foundational classes for implementing different
call graph extraction algorithms in PyFlow. It defines the abstract interface
that all call graph algorithms must implement and provides common utilities.
"""

from abc import ABC, abstractmethod
from typing import Set, Dict, Any, Optional, List
import collections


class CallGraphData:
    """Data structure to hold call graph information.
    
    This class encapsulates all the data needed to represent a call graph,
    including functions, their invocations, contexts, and detected cycles.
    
    Attributes:
        functions: Set of all functions in the call graph.
        invocations: Dictionary mapping functions to their direct callees.
        invocation_contexts: Dictionary mapping invocations to their contexts.
        function_contexts: Dictionary mapping functions to their contexts.
        cycles: List of detected cycles in the call graph.
    """

    def __init__(self):
        """Initialize an empty call graph data structure."""
        self.functions: Set[Any] = set()
        self.invocations: Dict[Any, Set[Any]] = {}
        self.invocation_contexts: Dict[Any, Set[Any]] = {}
        self.function_contexts: Dict[Any, Set[Any]] = {}
        self.cycles: List[List[Any]] = []


class CallGraphAlgorithm(ABC):
    """Abstract base class for call graph algorithms.
    
    This class defines the interface that all call graph extraction algorithms
    must implement. It provides a common structure for different approaches
    to call graph construction.
    
    Attributes:
        verbose: Whether to output verbose information during extraction.
    """

    def __init__(self, verbose: bool = False):
        """Initialize the call graph algorithm.
        
        Args:
            verbose: Whether to output verbose information during extraction.
        """
        self.verbose = verbose

    @abstractmethod
    def extract_from_program(self, program, compiler, args) -> CallGraphData:
        """Extract call graph from a pyflow program.
        
        Args:
            program: PyFlow program object to analyze.
            compiler: Compiler context for the analysis.
            args: Command-line arguments for configuration.
            
        Returns:
            CallGraphData: Extracted call graph information.
        """
        pass

    @abstractmethod
    def extract_from_source(self, source_code: str, args) -> CallGraphData:
        """Extract call graph directly from Python source code.
        
        Args:
            source_code: Python source code as a string.
            args: Command-line arguments for configuration.
            
        Returns:
            CallGraphData: Extracted call graph information.
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the algorithm name.
        
        Returns:
            str: Unique name identifying this algorithm.
        """
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a description of the algorithm.
        
        Returns:
            str: Human-readable description of the algorithm's approach.
        """
        pass


def limit_depth(call_graph: CallGraphData, max_depth: int) -> CallGraphData:
    """Limit the call graph to a maximum depth.
    
    Args:
        call_graph: Original call graph data.
        max_depth: Maximum depth to limit the call graph to.
        
    Returns:
        CallGraphData: Limited call graph (currently returns a copy of original).
        
    Note:
        This is a basic implementation that currently returns a copy.
        Future improvements should implement actual depth limiting.
    """
    if max_depth <= 0:
        return call_graph

    # Simple depth limiting - keep only functions within max_depth
    # This is a basic implementation and could be improved
    limited_graph = CallGraphData()
    limited_graph.functions = call_graph.functions.copy()
    limited_graph.invocations = call_graph.invocations.copy()
    limited_graph.invocation_contexts = call_graph.invocation_contexts.copy()
    limited_graph.function_contexts = call_graph.function_contexts.copy()

    return limited_graph


def detect_cycles(call_graph: CallGraphData) -> List[List[Any]]:
    """Detect cycles in the call graph using depth-first search.
    
    Args:
        call_graph: Call graph data to analyze for cycles.
        
    Returns:
        List[List[Any]]: List of detected cycles, where each cycle is a list
                        of functions forming a circular call chain.
    """
    cycles = []
    visited = set()
    rec_stack = set()

    def dfs(node, path):
        """Depth-first search to detect cycles.
        
        Args:
            node: Current function node being visited.
            path: Current path from root to node.
        """
        if node in rec_stack:
            # Found a cycle
            cycle_start = path.index(node)
            cycles.append(path[cycle_start:] + [node])
            return

        if node in visited:
            return

        visited.add(node)
        rec_stack.add(node)

        for callee in call_graph.invocations.get(node, set()):
            dfs(callee, path + [node])

        rec_stack.remove(node)

    for func in call_graph.functions:
        if func not in visited:
            dfs(func, [])

    return cycles
