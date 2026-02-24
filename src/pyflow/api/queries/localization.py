"""
Queries for bug and feature localization.

This module supports agents in localizing bugs or identifying where features
are implemented by analyzing call graphs, control flow, data dependencies, and
program slicing.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Union

from .call_graph import CallGraphQueries
from .context import QueryContext
from .engine import GraphQueryEngine


@dataclass
class LocalizationCandidate:
    """A candidate location for a bug or feature."""

    function_name: str
    confidence: float
    reason: str
    related_functions: List[str]
    data_dependencies: List[str]


@dataclass
class ProgramSlice:
    """A program slice relevant to a variable or statement."""

    target_function: str
    target_variable: Optional[str]
    backward_slice: List[str]
    forward_slice: List[str]


class LocalizationQueries:
    """
    High-level queries for bug and feature localization.
    """

    def __init__(
        self,
        context: QueryContext,
        graph_engine: GraphQueryEngine,
        call_graph_queries: CallGraphQueries,
        control_flow_queries,
        data_flow_queries,
    ):
        self.context = context
        self.graph_engine = graph_engine
        self.call_graph = call_graph_queries
        self.control_flow = control_flow_queries
        self.data_flow = data_flow_queries

    def find_related_functions(
        self, keywords: List[str], max_results: int = 10
    ) -> List[str]:
        results = []
        all_functions = self._get_all_functions()

        for func_name in all_functions:
            score = self._keyword_match_score(func_name, keywords)
            if score > 0:
                results.append((func_name, score))

        results.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in results[:max_results]]

    def get_localization_candidates(
        self,
        symptom_function: Union[str, object],
        suspicious_variable: Optional[str] = None,
    ) -> List[LocalizationCandidate]:
        func_name = self.context.resolve_function_name(symptom_function)
        candidates = []

        upstream = self.call_graph.get_upstream_functions(symptom_function, max_depth=3)

        for upstream_func in upstream:
            confidence = self._compute_suspiciousness(upstream_func, func_name)
            related = self.call_graph.get_callees(upstream_func)

            candidate = LocalizationCandidate(
                function_name=upstream_func,
                confidence=confidence,
                reason=f"Called by {func_name} (distance: {self._compute_distance(upstream_func, func_name)})",
                related_functions=related,
                data_dependencies=self._get_data_deps(upstream_func),
            )
            candidates.append(candidate)

        candidate = LocalizationCandidate(
            function_name=func_name,
            confidence=0.8,
            reason="Symptom location",
            related_functions=self.call_graph.get_callees(symptom_function),
            data_dependencies=self._get_data_deps(func_name),
        )
        candidates.append(candidate)

        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def compute_backward_slice(
        self, function: Union[str, object], variable: Optional[str] = None
    ) -> ProgramSlice:
        func_name = self.context.resolve_function_name(function)
        backward = self.call_graph.get_upstream_functions(function)

        return ProgramSlice(
            target_function=func_name,
            target_variable=variable,
            backward_slice=backward,
            forward_slice=[],
        )

    def compute_forward_slice(
        self, function: Union[str, object], variable: Optional[str] = None
    ) -> ProgramSlice:
        func_name = self.context.resolve_function_name(function)
        forward = self.call_graph.get_downstream_functions(function)

        return ProgramSlice(
            target_function=func_name,
            target_variable=variable,
            backward_slice=[],
            forward_slice=forward,
        )

    def trace_data_flow(
        self, function: Union[str, object], variable: str
    ) -> Dict[str, Any]:
        func_name = self.context.resolve_function_name(function)

        trace = {
            "variable": variable,
            "origin_function": func_name,
            "definitions": [],
            "uses": [],
            "interprocedural_flow": [],
        }

        try:
            ssa = self.control_flow.get_ssa(function)
            trace["definitions"] = self._extract_definitions_from_ssa(ssa, variable)
            trace["uses"] = self._extract_uses_from_ssa(ssa, variable)
        except Exception:
            pass

        callees = self.call_graph.get_callees(function)
        trace["interprocedural_flow"] = callees

        return trace

    def find_feature_entry_points(self, feature_functions: List[str]) -> List[str]:
        entry_points = set()

        for func in feature_functions:
            upstream = self.call_graph.get_upstream_functions(func)

            for candidate in upstream:
                callers = self.call_graph.get_callers(candidate)
                if not callers:
                    entry_points.add(candidate)

        return sorted(entry_points)

    def get_change_impact(
        self, changed_function: Union[str, object]
    ) -> Dict[str, List[str]]:
        func_name = self.context.resolve_function_name(changed_function)

        direct_callers = self.call_graph.get_callers(changed_function)
        all_upstream = self.call_graph.get_upstream_functions(changed_function)

        return {
            "changed_function": func_name,
            "directly_affected": direct_callers,
            "transitively_affected": all_upstream,
            "test_targets": list(set(direct_callers + all_upstream)),
        }

    def _get_all_functions(self) -> List[str]:
        callgraph = self.call_graph.get_callgraph()
        return list(callgraph.get().keys())

    def _keyword_match_score(self, function_name: str, keywords: List[str]) -> float:
        name_lower = function_name.lower()
        matches = sum(1 for keyword in keywords if keyword.lower() in name_lower)
        return matches / len(keywords) if keywords else 0.0

    def _compute_suspiciousness(self, suspect_func: str, symptom_func: str) -> float:
        path = self.call_graph.get_shortest_path(suspect_func, symptom_func)
        if path is None:
            return 0.1

        distance = len(path) - 1
        if distance == 0:
            return 0.8
        elif distance == 1:
            return 0.6
        elif distance == 2:
            return 0.4
        else:
            return 0.2

    def _compute_distance(self, source: str, target: str) -> int:
        path = self.call_graph.get_shortest_path(source, target)
        return len(path) - 1 if path else -1

    def _get_data_deps(self, function: str) -> List[str]:
        return []

    def _extract_definitions_from_ssa(self, ssa, variable: str) -> List[str]:
        return []

    def _extract_uses_from_ssa(self, ssa, variable: str) -> List[str]:
        return []
