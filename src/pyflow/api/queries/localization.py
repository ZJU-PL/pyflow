"""
Queries for bug and feature localization.

This module supports agents in localizing bugs or identifying where features
are implemented by analyzing call graphs, control flow, data dependencies, and
program slicing.
"""

import logging
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Union

from pyflow.application.errors import TemporaryLimitation

from .call_graph import CallGraphQueries
from .context import QueryContext
from .engine import GraphQueryEngine

LOG = logging.getLogger(__name__)


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
            data_deps = self._get_data_deps(upstream_func)
            var_match = self._matches_variable(data_deps, suspicious_variable)
            confidence = self._adjust_confidence_for_variable(confidence, suspicious_variable, var_match)
            reason = (
                f"Calls {func_name} (distance: {self._compute_distance(upstream_func, func_name)})"
            )
            if suspicious_variable:
                reason += (
                    f"; touches '{suspicious_variable}'"
                    if var_match
                    else f"; no evidence for '{suspicious_variable}'"
                )

            candidate = LocalizationCandidate(
                function_name=upstream_func,
                confidence=confidence,
                reason=reason,
                related_functions=related,
                data_dependencies=data_deps,
            )
            candidates.append(candidate)

        symptom_data_deps = self._get_data_deps(func_name)
        symptom_match = self._matches_variable(symptom_data_deps, suspicious_variable)
        symptom_confidence = self._adjust_confidence_for_variable(
            0.8, suspicious_variable, symptom_match
        )
        symptom_reason = "Symptom location"
        if suspicious_variable:
            symptom_reason += (
                f"; touches '{suspicious_variable}'"
                if symptom_match
                else f"; no evidence for '{suspicious_variable}'"
            )

        candidate = LocalizationCandidate(
            function_name=func_name,
            confidence=symptom_confidence,
            reason=symptom_reason,
            related_functions=self.call_graph.get_callees(symptom_function),
            data_dependencies=symptom_data_deps,
        )
        candidates.append(candidate)

        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def compute_backward_slice(
        self, function: Union[str, object], variable: Optional[str] = None
    ) -> ProgramSlice:
        func_name = self.context.resolve_function_name(function)
        if variable:
            candidates = self.get_localization_candidates(function, variable)
            backward = [
                candidate.function_name
                for candidate in candidates
                if candidate.function_name != func_name
                and f"touches '{variable}'" in candidate.reason
            ]
        else:
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
        if variable:
            forward = []
            for callee in self.call_graph.get_downstream_functions(function):
                try:
                    deps = self._get_data_deps(callee)
                except (TemporaryLimitation, ValueError, TypeError, AttributeError):
                    continue
                if self._matches_variable(deps, variable):
                    forward.append(callee)
        else:
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
        except (ValueError, TypeError, AttributeError):
            LOG.debug("Unable to derive SSA trace for %r", function, exc_info=True)

        fallback_defs: List[str] = []
        fallback_uses: List[str] = []

        try:
            defs_by_var = self.data_flow.get_reaching_defs(function)
            fallback_defs = [
                self._format_reaching_def(item) for item in defs_by_var.get(variable, [])
            ]
        except (TemporaryLimitation, ValueError, TypeError, AttributeError):
            LOG.debug(
                "Unable to derive fallback reaching defs for %r", function, exc_info=True
            )

        try:
            fallback_uses = self.data_flow.get_variable_uses(function, variable)
        except (TemporaryLimitation, ValueError, TypeError, AttributeError):
            LOG.debug(
                "Unable to derive fallback variable uses for %r", function, exc_info=True
            )

        trace["definitions"] = self._merge_strings(trace["definitions"], fallback_defs)
        trace["uses"] = self._merge_strings(trace["uses"], fallback_uses)

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
    ) -> Dict[str, Union[str, List[str]]]:
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
        deps: Set[str] = set()

        try:
            reaching_defs = self.data_flow.get_reaching_defs(function)
            deps.update(reaching_defs.keys())
        except (TemporaryLimitation, ValueError, TypeError, AttributeError):
            LOG.debug(
                "Unable to collect reaching-def dependencies for %r",
                function,
                exc_info=True,
            )

        try:
            aliases = self.data_flow.get_aliases(function)
            for alias in aliases.values():
                deps.add(alias.variable)
                deps.update(alias.aliases)
        except (TemporaryLimitation, ValueError, TypeError, AttributeError):
            LOG.debug(
                "Unable to collect alias dependencies for %r", function, exc_info=True
            )

        try:
            points_to = self.data_flow.get_points_to(function)
            deps.update(points_to.keys())
        except (TemporaryLimitation, ValueError, TypeError, AttributeError):
            LOG.debug(
                "Unable to collect points-to dependencies for %r", function, exc_info=True
            )

        return sorted(d for d in deps if isinstance(d, str) and d)

    def _matches_variable(self, data_deps: List[str], variable: Optional[str]) -> bool:
        if not variable:
            return False
        var = variable.lower()
        return any(var == dep.lower() or dep.lower().endswith(f".{var}") for dep in data_deps)

    def _adjust_confidence_for_variable(
        self, confidence: float, variable: Optional[str], variable_match: bool
    ) -> float:
        if not variable:
            return confidence
        if variable_match:
            return min(1.0, confidence + 0.2)
        return max(0.0, confidence - 0.1)

    def _iter_cfg_blocks(self, ssa) -> List[Any]:
        entry = getattr(ssa, "entryTerminal", None)
        if entry is None:
            return []

        blocks: List[Any] = []
        visited = set()
        queue = deque([entry])

        while queue:
            block = queue.popleft()
            if block in visited:
                continue
            visited.add(block)
            blocks.append(block)

            nxt = getattr(block, "next", None)
            if isinstance(nxt, dict):
                for target in nxt.values():
                    if target not in visited:
                        queue.append(target)
            elif nxt is not None and nxt not in visited:
                queue.append(nxt)

        return blocks

    def _format_reaching_def(self, reaching_def) -> str:
        location = getattr(reaching_def, "def_location", None)
        value = getattr(reaching_def, "def_value", None)
        if location is not None and value:
            return f"line {location}: {value}"
        if location is not None:
            return f"line {location}"
        if value:
            return str(value)
        return str(reaching_def)

    def _get_block_statements(self, block) -> List[Any]:
        if hasattr(block, "statements"):
            return block.statements
        if hasattr(block, "ops"):
            return block.ops
        if hasattr(block, "body"):
            return block.body
        return []

    def _extract_definitions_from_ssa(self, ssa, variable: str) -> List[str]:
        definitions: List[str] = []
        for block in self._iter_cfg_blocks(ssa):
            for stmt in self._get_block_statements(block):
                targets = getattr(stmt, "targets", [])
                for target in targets:
                    if getattr(target, "id", None) == variable:
                        line = getattr(stmt, "lineno", None)
                        prefix = f"line {line}: " if line is not None else ""
                        definitions.append(f"{prefix}{type(stmt).__name__}")
        return definitions

    def _extract_uses_from_ssa(self, ssa, variable: str) -> List[str]:
        uses: List[str] = []
        for block in self._iter_cfg_blocks(ssa):
            for stmt in self._get_block_statements(block):
                value = getattr(stmt, "value", None)
                if getattr(value, "id", None) == variable:
                    line = getattr(stmt, "lineno", None)
                    prefix = f"line {line}: " if line is not None else ""
                    uses.append(f"{prefix}{type(stmt).__name__}")
        return uses

    def _merge_strings(self, primary: List[str], fallback: List[str]) -> List[str]:
        merged: List[str] = []
        seen: Set[str] = set()
        for item in primary + fallback:
            if item in seen:
                continue
            seen.add(item)
            merged.append(item)
        return merged
