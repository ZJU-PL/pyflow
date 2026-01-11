"""
Call-graph driven helpers for coding agents.

These queries surface agent-friendly insights such as reachable functions,
callers, and shortest call paths without exposing the raw graph objects
directly. They are intended to support workflows like patch generation
and change-impact understanding where agents care about high-level
function interactions.
"""

from typing import Dict, List, Optional, Set, Union

from .context import QueryContext
from .graph_engine import GraphQueryEngine


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

    def get_callgraph(self):
        """Return the raw call graph for consumers that need graph traversal APIs."""
        return self.graph_engine.get_callgraph()

    def get_callers(self, function: Union[str, object]) -> List[str]:
        """List functions that call the given target."""
        name = self.context.resolve_function_name(function)
        graph = self._callgraph_dict()
        callers = [caller for caller, callees in graph.items() if name in callees]
        return sorted(set(callers))

    def get_callees(self, function: Union[str, object]) -> List[str]:
        """List functions called by the given function."""
        name = self.context.resolve_function_name(function)
        graph = self._callgraph_dict()
        return sorted(graph.get(name, set()))

    def get_downstream_functions(
        self, function: Union[str, object], max_depth: Optional[int] = None
    ) -> List[str]:
        """Return the transitive callees of `function` within an optional depth."""
        name = self.context.resolve_function_name(function)
        graph = self._callgraph_dict()

        visited: Set[str] = set()
        queue: List[tuple[str, int]] = [(name, 0)]
        result: Set[str] = set()

        while queue:
            current, depth = queue.pop(0)
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
        target = self.context.resolve_function_name(function)
        reverse_graph: Dict[str, Set[str]] = {}
        graph = self._callgraph_dict()

        for caller, callees in graph.items():
            for callee in callees:
                reverse_graph.setdefault(callee, set()).add(caller)

        visited: Set[str] = set()
        queue: List[tuple[str, int]] = [(target, 0)]
        result: Set[str] = set()

        while queue:
            current, depth = queue.pop(0)
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
        src_name = self.context.resolve_function_name(source)
        tgt_name = self.context.resolve_function_name(target)

        if src_name == tgt_name:
            return [src_name]

        graph = self._callgraph_dict()
        queue: List[tuple[str, List[str]]] = [(src_name, [src_name])]
        visited: Set[str] = {src_name}

        while queue:
            current, path = queue.pop(0)
            for callee in graph.get(current, set()):
                if callee == tgt_name:
                    return path + [callee]

                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))

        return None
