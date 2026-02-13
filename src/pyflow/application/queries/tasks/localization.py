"""
Queries for bug and feature localization.

This module supports agents in localizing bugs or identifying where features
are implemented by analyzing call graphs, control flow, data dependencies, and
program slicing.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Union

from ..core.context import QueryContext
from ..core.graph_engine import GraphQueryEngine


@dataclass
class LocalizationCandidate:
    """A candidate location for a bug or feature."""

    function_name: str
    confidence: float  # 0.0 to 1.0
    reason: str
    related_functions: List[str]
    data_dependencies: List[str]


@dataclass
class ProgramSlice:
    """A program slice relevant to a variable or statement."""

    target_function: str
    target_variable: Optional[str]
    backward_slice: List[str]  # Functions that influence the target
    forward_slice: List[str]  # Functions influenced by the target


class LocalizationQueries:
    """
    High-level queries for bug and feature localization.

    Supports:
    - Identifying functions related to a symptom or feature
    - Computing program slices for debugging
    - Tracing data flow to locate data origins
    - Finding impacted functions for changes
    """

    def __init__(
        self,
        context: QueryContext,
        graph_engine: GraphQueryEngine,
        call_graph_queries,
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
        """
        Find functions related to given keywords (for feature localization).

        Searches function names and can be extended to search docstrings
        and comments.
        """
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
        """
        Get candidate functions that may contain a bug affecting the symptom.

        Uses backward slicing and call graph analysis to identify suspects.
        """
        func_name = self.context.resolve_function_name(symptom_function)
        candidates = []

        # Get upstream functions (potential bug sources)
        upstream = self.call_graph.get_upstream_functions(symptom_function, max_depth=3)

        # Score each upstream function
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

        # Include the symptom function itself
        candidate = LocalizationCandidate(
            function_name=func_name,
            confidence=0.8,
            reason="Symptom location",
            related_functions=self.call_graph.get_callees(symptom_function),
            data_dependencies=self._get_data_deps(func_name),
        )
        candidates.append(candidate)

        # Sort by confidence
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def compute_backward_slice(
        self, function: Union[str, object], variable: Optional[str] = None
    ) -> ProgramSlice:
        """
        Compute backward slice: functions that influence the target function/variable.

        This helps identify where data flows from to reach the target.
        """
        func_name = self.context.resolve_function_name(function)

        # Use call graph for inter-procedural slicing
        backward = self.call_graph.get_upstream_functions(function)

        # TODO: Refine with data flow analysis for intra-procedural slicing
        # For now, use call graph as approximation

        return ProgramSlice(
            target_function=func_name,
            target_variable=variable,
            backward_slice=backward,
            forward_slice=[],  # Will be computed in compute_forward_slice
        )

    def compute_forward_slice(
        self, function: Union[str, object], variable: Optional[str] = None
    ) -> ProgramSlice:
        """
        Compute forward slice: functions influenced by the target function/variable.

        This helps identify the impact of changes or understand bug propagation.
        """
        func_name = self.context.resolve_function_name(function)

        # Use call graph for inter-procedural slicing
        forward = self.call_graph.get_downstream_functions(function)

        return ProgramSlice(
            target_function=func_name,
            target_variable=variable,
            backward_slice=[],  # Will be computed in compute_backward_slice
            forward_slice=forward,
        )

    def trace_data_flow(
        self, function: Union[str, object], variable: str
    ) -> Dict[str, Any]:
        """
        Trace data flow for a specific variable through the program.

        Returns information about where the variable is defined, used, and
        how it flows between functions.
        """
        func_name = self.context.resolve_function_name(function)

        trace = {
            "variable": variable,
            "origin_function": func_name,
            "definitions": [],
            "uses": [],
            "interprocedural_flow": [],
        }

        # Intra-procedural analysis via SSA
        try:
            ssa = self.control_flow.get_ssa(function)
            # Extract variable information from SSA
            trace["definitions"] = self._extract_definitions_from_ssa(ssa, variable)
            trace["uses"] = self._extract_uses_from_ssa(ssa, variable)
        except Exception:
            pass

        # Inter-procedural: check if variable flows to callees
        callees = self.call_graph.get_callees(function)
        trace["interprocedural_flow"] = callees

        return trace

    def find_feature_entry_points(self, feature_functions: List[str]) -> List[str]:
        """
        Find entry points (top-level callers) for a set of feature functions.

        Useful for understanding how a feature is invoked.
        """
        entry_points = set()

        for func in feature_functions:
            # Get all callers transitively
            upstream = self.call_graph.get_upstream_functions(func)

            # Entry points are functions with no callers themselves
            for candidate in upstream:
                callers = self.call_graph.get_callers(candidate)
                if not callers:
                    entry_points.add(candidate)

        return sorted(entry_points)

    def get_change_impact(
        self, changed_function: Union[str, object]
    ) -> Dict[str, List[str]]:
        """
        Analyze the impact of changes to a function.

        Returns:
        - directly_affected: Functions that directly call this function
        - transitively_affected: All functions transitively affected
        - test_targets: Functions that should be tested
        """
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
        """Get all functions in the program."""
        callgraph = self.call_graph.get_callgraph()
        return list(callgraph.get().keys())

    def _keyword_match_score(self, function_name: str, keywords: List[str]) -> float:
        """Score how well a function name matches keywords."""
        name_lower = function_name.lower()
        matches = sum(1 for keyword in keywords if keyword.lower() in name_lower)
        return matches / len(keywords) if keywords else 0.0

    def _compute_suspiciousness(self, suspect_func: str, symptom_func: str) -> float:
        """
        Compute suspiciousness score for a function.

        This is a simple heuristic based on call graph distance.
        Can be extended with coverage, execution frequency, etc.
        """
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
        """Compute call graph distance between functions."""
        path = self.call_graph.get_shortest_path(source, target)
        return len(path) - 1 if path else -1

    def _get_data_deps(self, function: str) -> List[str]:
        """Get data dependencies for a function (placeholder)."""
        # TODO: Implement using data flow analysis
        return []

    def _extract_definitions_from_ssa(self, ssa, variable: str) -> List[str]:
        """Extract variable definitions from SSA."""
        # Placeholder: would need to traverse SSA phi nodes and assignments
        return []

    def _extract_uses_from_ssa(self, ssa, variable: str) -> List[str]:
        """Extract variable uses from SSA."""
        # Placeholder: would need to traverse SSA use chains
        return []
