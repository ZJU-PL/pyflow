"""
Call-graph query helpers for PyFlow.

These queries surface agent-friendly insights such as reachable functions,
callers, and shortest call paths. Backward-compatible raw graph access is
still available, but new consumers should prefer the plain-data helpers.
"""

from collections import deque
from typing import Dict, List, Optional, Set, Union

from .context import QueryContext
from .engine import GraphQueryEngine


class CallGraphQueries:
    """
    Provides call-graph derived answers for higher-level tooling.
    """

    def __init__(self, context: QueryContext, graph_engine: GraphQueryEngine):
        self.context = context
        self.graph_engine = graph_engine

    def _callgraph_dict(self) -> Dict[str, Set[str]]:
        """Return a plain dictionary view over the cached call graph."""
        return self.graph_engine.get_callgraph().get()

    def _resolve_graph_nodes(self, function: Union[str, object]) -> Set[str]:
        """Resolve a query input to callgraph node identifiers."""
        graph = self._callgraph_dict()
        aliases = self.graph_engine.get_callgraph_aliases()
        resolved: Set[str] = set()

        if isinstance(function, str):
            if function in graph:
                resolved.add(function)
            resolved.update(aliases.get(function, set()))
            return resolved

        if hasattr(function, "codeName"):
            for alias in self.context.code_aliases(function):
                if alias in graph:
                    resolved.add(alias)
                resolved.update(aliases.get(alias, set()))
            return resolved

        raise TypeError("Expected a function name or a PyFlow code object.")

    def get_callgraph(self):
        """Return the raw call graph for compatibility callers."""
        return self.graph_engine.get_callgraph()

    def get_callgraph_data(self) -> Dict[str, List[str]]:
        """Return the call graph as plain serializable data."""
        graph = self._callgraph_dict()
        return {
            caller: sorted(callees)
            for caller, callees in sorted(graph.items(), key=lambda item: item[0])
        }

    def get_callers(self, function: Union[str, object]) -> List[str]:
        """List functions that call the given target."""
        targets = self._resolve_graph_nodes(function)
        if not targets:
            return []
        graph = self._callgraph_dict()
        callers = [
            caller
            for caller, callees in graph.items()
            if any(target in callees for target in targets)
        ]
        return sorted(set(callers))

    def get_callees(self, function: Union[str, object]) -> List[str]:
        """List functions called by the given function."""
        names = self._resolve_graph_nodes(function)
        if not names:
            return []
        graph = self._callgraph_dict()
        result: Set[str] = set()
        for name in names:
            result.update(graph.get(name, set()))
        return sorted(result)

    def get_downstream_functions(
        self, function: Union[str, object], max_depth: Optional[int] = None
    ) -> List[str]:
        """Return the transitive callees of `function` within an optional depth."""
        names = self._resolve_graph_nodes(function)
        if not names:
            return []
        graph = self._callgraph_dict()

        visited: Set[str] = set()
        queue = deque((name, 0) for name in names)
        result: Set[str] = set()

        while queue:
            current, depth = queue.popleft()
            if max_depth is not None and depth >= max_depth:
                continue

            for callee in graph.get(current, set()):
                if callee not in visited:
                    visited.add(callee)
                    result.add(callee)
                    queue.append((callee, depth + 1))

        return sorted(result)

    def get_upstream_functions(
        self, function: Union[str, object], max_depth: Optional[int] = None
    ) -> List[str]:
        """Return all transitive callers of `function` within an optional depth."""
        targets = self._resolve_graph_nodes(function)
        if not targets:
            return []
        reverse_graph: Dict[str, Set[str]] = {}
        graph = self._callgraph_dict()

        for caller, callees in graph.items():
            for callee in callees:
                reverse_graph.setdefault(callee, set()).add(caller)

        visited: Set[str] = set()
        queue = deque((target, 0) for target in targets)
        result: Set[str] = set()

        while queue:
            current, depth = queue.popleft()
            if max_depth is not None and depth >= max_depth:
                continue

            for caller in reverse_graph.get(current, set()):
                if caller not in visited:
                    visited.add(caller)
                    result.add(caller)
                    queue.append((caller, depth + 1))

        return sorted(result)

    def get_shortest_path(
        self, source: Union[str, object], target: Union[str, object]
    ) -> Optional[List[str]]:
        """Return the shortest call path between two functions, if it exists."""
        src_names = self._resolve_graph_nodes(source)
        tgt_names = self._resolve_graph_nodes(target)
        if not src_names or not tgt_names:
            return None
        if src_names & tgt_names:
            return [sorted(src_names & tgt_names)[0]]

        graph = self._callgraph_dict()
        queue = deque((src_name, [src_name]) for src_name in src_names)
        visited: Set[str] = set(src_names)

        while queue:
            current, path = queue.popleft()
            for callee in graph.get(current, set()):
                if callee in tgt_names:
                    return path + [callee]

                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))

        return None
