"""
Shared data types for call graph analysis.

This module contains common classes and data structures used across
different call graph algorithms.
"""

from typing import Dict, Set, List, Any


class SimpleFunction:
    """Simple function object that matches the expected interface."""

    def __init__(self, name: str):
        self.name = name

    def codeName(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"SimpleFunction({self.name})"


class CallGraphData:
    """Simple call graph data structure compatible with formatters."""

    def __init__(self):
        self.functions: Set[Any] = set()
        self.invocations: Dict[Any, Set[Any]] = {}
        self.invocation_contexts: Dict[Any, Set[Any]] = {}
        self.function_contexts: Dict[Any, Set[Any]] = {}
        self.cycles: List[List[Any]] = []
