"""
Call graph analysis types and data structures.

This module contains the data structures used specifically for call graph
analysis, including function representations and analysis result containers.
"""

from typing import Dict, Set, List, Any
from ...machinery.callgraph import CallGraph


class SimpleFunction:
    """Simple function object for call graph analysis."""

    def __init__(self, name: str):
        self.name = name

    def codeName(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"SimpleFunction({self.name})"


class CallGraphData:
    """Analysis wrapper around the core CallGraph class."""

    def __init__(self):
        self._callgraph = CallGraph()
        self.functions: Set[Any] = set()
        self.invocations: Dict[Any, Set[Any]] = {}
        self.invocation_contexts: Dict[Any, Set[Any]] = {}
        self.function_contexts: Dict[Any, Set[Any]] = {}
        self.cycles: List[List[Any]] = []

    def add_function(self, func: SimpleFunction, modname: str = ""):
        """Add a function to the call graph."""
        self._callgraph.add_node(func.name, modname)
        self.functions.add(func)
        self.invocations[func] = set()
        self.function_contexts[func] = {None}

    def add_call(self, caller: SimpleFunction, callee: SimpleFunction):
        """Add a call relationship between functions."""
        self._callgraph.add_edge(caller.name, callee.name)
        if caller in self.invocations:
            self.invocations[caller].add(callee)
        else:
            self.invocations[caller] = {callee}

    def get_callgraph(self) -> CallGraph:
        """Get the underlying CallGraph instance."""
        return self._callgraph
