"""
Task-oriented code localization queries built on analysis facts.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Union

from pyflow.application.errors import TemporaryLimitation

from .._models import (
    ChangeImpactReport,
    LocalizationCandidate,
    LocalizationEvidence,
    ProgramSlice,
    VariableFlowTrace,
)
from ..call_graph import CallGraphQueries
from ..context import QueryContext
from ..engine import GraphQueryEngine

LOG = logging.getLogger(__name__)


class LocalizationQueries:
    """High-level queries for bug and feature localization."""

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

    def find_related_functions(self, keywords: List[str], max_results: int = 10) -> List[str]:
        results = []
        for func_name in self._get_all_functions():
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
            evidence = self._collect_localization_evidence(
                upstream_func,
                func_name,
                suspicious_variable,
            )
            candidates.append(
                self._build_candidate(
                    upstream_func,
                    func_name,
                    evidence,
                    suspicious_variable=suspicious_variable,
                    is_symptom=False,
                )
            )

        symptom_evidence = self._collect_localization_evidence(
            func_name,
            func_name,
            suspicious_variable,
        )
        candidates.append(
            self._build_candidate(
                func_name,
                func_name,
                symptom_evidence,
                suspicious_variable=suspicious_variable,
                is_symptom=True,
            )
        )

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
                and self._candidate_matches_variable(candidate, variable)
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

    def trace_data_flow(self, function: Union[str, object], variable: str) -> Dict[str, Any]:
        func_name = self.context.resolve_function_name(function)
        trace = VariableFlowTrace(variable=variable, origin_function=func_name)

        defs_by_var = self.data_flow.get_reaching_defs(function)
        trace.definitions = [
            self._format_reaching_def(item)
            for item in defs_by_var.get(variable, [])
        ]
        trace.uses = self.data_flow.get_variable_uses(function, variable)
        trace.upstream_functions = self.call_graph.get_upstream_functions(function, max_depth=2)
        trace.downstream_functions = self.call_graph.get_downstream_functions(function, max_depth=2)
        trace.dependency_summary = self._dependency_summary(function)

        candidate_locations = []
        for candidate in self.get_localization_candidates(function, variable):
            if candidate.function_name != func_name and self._candidate_matches_variable(candidate, variable):
                candidate_locations.append(candidate.function_name)
        trace.candidate_locations = candidate_locations
        return trace.to_dict()

    def find_feature_entry_points(self, feature_functions: List[str]) -> List[str]:
        entry_points = set()
        for func in feature_functions:
            for candidate in self.call_graph.get_upstream_functions(func):
                if not self.call_graph.get_callers(candidate):
                    entry_points.add(candidate)
        return sorted(entry_points)

    def get_change_impact(self, changed_function: Union[str, object]) -> Dict[str, Union[str, List[str]]]:
        func_name = self.context.resolve_function_name(changed_function)
        direct_callers = self.call_graph.get_callers(changed_function)
        all_upstream = self.call_graph.get_upstream_functions(changed_function)
        direct_callees = self.call_graph.get_callees(changed_function)
        all_downstream = self.call_graph.get_downstream_functions(changed_function)
        test_targets = sorted(set(direct_callers + all_upstream))
        impact_score = min(
            1.0,
            0.15
            + min(0.35, len(direct_callers) * 0.1)
            + min(0.25, len(all_upstream) * 0.04)
            + min(0.15, len(direct_callees) * 0.05)
            + min(0.10, len(all_downstream) * 0.02),
        )
        return ChangeImpactReport(
            changed_function=func_name,
            direct_callers=direct_callers,
            transitive_callers=all_upstream,
            direct_callees=direct_callees,
            transitive_callees=all_downstream,
            test_targets=test_targets,
            impact_score=impact_score,
        ).to_dict()

    def _get_all_functions(self) -> List[str]:
        return list(self.call_graph.get_callgraph().get().keys())

    def _keyword_match_score(self, function_name: str, keywords: List[str]) -> float:
        name_lower = function_name.lower()
        matches = sum(1 for keyword in keywords if keyword.lower() in name_lower)
        return matches / len(keywords) if keywords else 0.0

    def _dependency_summary(self, function: str) -> Dict[str, List[str]]:
        buckets = self._collect_dependency_buckets(function)
        return {key: sorted(values) for key, values in buckets.items()}

    def _get_data_deps(self, function: str) -> List[str]:
        buckets = self._collect_dependency_buckets(function)
        return sorted(set().union(*buckets.values()))

    def _collect_dependency_buckets(self, function: str) -> Dict[str, Set[str]]:
        buckets: Dict[str, Set[str]] = {
            "reaching_defs": set(),
            "aliases": set(),
            "points_to": set(),
        }

        try:
            buckets["reaching_defs"].update(self.data_flow.get_reaching_defs(function).keys())
        except (TemporaryLimitation, ValueError, TypeError, AttributeError):
            LOG.debug("Unable to collect reaching-def dependencies for %r", function, exc_info=True)

        try:
            aliases = self.data_flow.get_aliases(function)
            for alias in aliases.values():
                buckets["aliases"].add(alias.variable)
                buckets["aliases"].update(alias.aliases)
        except (TemporaryLimitation, ValueError, TypeError, AttributeError):
            LOG.debug("Unable to collect alias dependencies for %r", function, exc_info=True)

        try:
            buckets["points_to"].update(self.data_flow.get_points_to(function).keys())
        except (TemporaryLimitation, ValueError, TypeError, AttributeError):
            LOG.debug("Unable to collect points-to dependencies for %r", function, exc_info=True)

        return buckets

    def _matches_variable(self, data_deps: Union[List[str], Dict[str, Set[str]]], variable: Optional[str]) -> bool:
        if not variable:
            return False
        if isinstance(data_deps, dict):
            flattened: List[str] = sorted(set().union(*data_deps.values()))
        else:
            flattened = data_deps
        var = variable.lower()
        return any(
            var == dep.lower() or dep.lower().endswith(f".{var}")
            for dep in flattened
        )

    def _collect_localization_evidence(
        self,
        candidate_function: str,
        symptom_function: str,
        suspicious_variable: Optional[str],
    ) -> LocalizationEvidence:
        path = self.call_graph.get_shortest_path(candidate_function, symptom_function) or []
        deps = self._collect_dependency_buckets(candidate_function)
        return LocalizationEvidence(
            distance=(len(path) - 1) if path else None,
            shortest_path=path,
            variable_match=self._matches_variable(deps, suspicious_variable),
            reaching_defs=sorted(deps["reaching_defs"]),
            aliases=sorted(deps["aliases"]),
            points_to=sorted(deps["points_to"]),
            upstream_callers=self.call_graph.get_callers(candidate_function),
            downstream_callees=self.call_graph.get_callees(candidate_function),
        )

    def _build_candidate(
        self,
        candidate_function: str,
        symptom_function: str,
        evidence: LocalizationEvidence,
        *,
        suspicious_variable: Optional[str],
        is_symptom: bool,
    ) -> LocalizationCandidate:
        confidence = self._score_candidate(
            evidence,
            suspicious_variable=suspicious_variable,
            is_symptom=is_symptom,
        )
        reason = self._describe_candidate_reason(
            symptom_function,
            evidence,
            suspicious_variable=suspicious_variable,
            is_symptom=is_symptom,
        )
        return LocalizationCandidate(
            function_name=candidate_function,
            confidence=confidence,
            reason=reason,
            related_functions=evidence.downstream_callees,
            data_dependencies=sorted(
                set(evidence.reaching_defs) | set(evidence.aliases) | set(evidence.points_to)
            ),
            evidence=evidence,
        )

    def _score_candidate(
        self,
        evidence: LocalizationEvidence,
        *,
        suspicious_variable: Optional[str],
        is_symptom: bool,
    ) -> float:
        score = 0.15
        if is_symptom:
            score += 0.45
        elif evidence.distance is None:
            score += 0.05
        elif evidence.distance == 0:
            score += 0.55
        elif evidence.distance == 1:
            score += 0.40
        elif evidence.distance == 2:
            score += 0.28
        elif evidence.distance == 3:
            score += 0.18
        else:
            score += 0.10

        score += min(0.15, evidence.dependency_hits * 0.02)
        if suspicious_variable:
            score += 0.15 if evidence.variable_match else -0.05

        if evidence.upstream_callers:
            score += min(0.05, len(evidence.upstream_callers) * 0.01)
        return max(0.0, min(1.0, score))

    def _describe_candidate_reason(
        self,
        symptom_function: str,
        evidence: LocalizationEvidence,
        *,
        suspicious_variable: Optional[str],
        is_symptom: bool,
    ) -> str:
        parts: List[str] = []
        if is_symptom:
            parts.append("Symptom location")
        elif evidence.distance is not None:
            parts.append(f"Reaches {symptom_function} at distance {evidence.distance}")
        else:
            parts.append(f"No call path to {symptom_function} found")

        parts.append(f"{evidence.dependency_hits} dependency hits")
        if suspicious_variable:
            parts.append(
                f"matches variable '{suspicious_variable}'"
                if evidence.variable_match
                else f"no match for '{suspicious_variable}'"
            )
        return "; ".join(parts)

    def _candidate_matches_variable(
        self, candidate: LocalizationCandidate, variable: Optional[str]
    ) -> bool:
        if not variable:
            return False
        if candidate.evidence is not None:
            return candidate.evidence.variable_match
        return f"touches '{variable}'" in candidate.reason

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
