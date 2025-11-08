"""
Simplified CallGraph implementation.

The original PyFlow project exposes a far more feature-rich call graph
machinery module that depends on native extensions. For the purposes of the
open-source friendly subset used in the tests, we only need a minimal in-memory
representation with a couple of helper methods.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, MutableMapping, MutableSet, Optional, Set


class CallGraphError(Exception):
    """Base error for call graph handling issues."""


class CallGraph:
    """
    Minimal directed call graph.

    Nodes are identified by their fully-qualified function names. Edges capture
    caller -> callee relationships. Module metadata is stored separately to
    support richer output formats when available.
    """

    def __init__(self) -> None:
        self._graph: MutableMapping[str, MutableSet[str]] = defaultdict(set)
        self._modules: Dict[str, str] = {}

    # ------------------------------------------------------------------ utils
    def add_node(self, name: str, module: Optional[str] = None) -> None:
        """
        Ensure a node exists in the graph.

        Parameters
        ----------
        name:
            Fully-qualified identifier for the function.
        module:
            Optional module origin to associate with the node.
        """
        self._graph.setdefault(name, set())
        if module is not None:
            self._modules[name] = module

    def add_edge(self, caller: str, callee: str) -> None:
        """
        Record an invocation from `caller` to `callee`.

        Nodes are auto-created on demand to keep the API ergonomic for the
        higher-level analysers.
        """
        self.add_node(caller)
        self.add_node(callee)
        self._graph[caller].add(callee)

    # ---------------------------------------------------------------- queries
    def get(self) -> Dict[str, Set[str]]:
        """Return a plain dictionary view of the graph."""
        return {node: set(callees) for node, callees in self._graph.items()}

    def get_modules(self) -> Dict[str, str]:
        """Return the recorded module metadata."""
        return dict(self._modules)

    # ------------------------------------------------------------ compat ops
    def merge(self, other: "CallGraph") -> None:
        """Merge another call graph into this one."""
        for node, callees in other._graph.items():
            self.add_node(node, other._modules.get(node))
            self._graph[node].update(callees)

    def nodes(self) -> Iterable[str]:
        """Iterate over nodes in the graph."""
        return self._graph.keys()

    def edges(self) -> Iterable[tuple[str, str]]:
        """Iterate over edges as (caller, callee) tuples."""
        for caller, callees in self._graph.items():
            for callee in callees:
                yield caller, callee

