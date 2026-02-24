"""
Queries for unit test generation.

This module provides high-level queries that support test generation agents by
exposing function signatures, input/output behavior, control flow paths, and
data dependencies needed to generate comprehensive test cases.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

from .context import QueryContext
from .data_flow import DataFlowQueries, IpaFunctionSummary
from .engine import GraphQueryEngine


@dataclass
class FunctionTestProfile:
    """Profile of a function for test generation."""

    name: str
    signature: Optional[str]
    parameters: List[str]
    return_type: Optional[str]
    calls: List[str]
    called_by: List[str]
    has_branches: bool
    has_loops: bool
    complexity: int
    external_dependencies: List[str]


@dataclass
class TestScenario:
    """A test scenario derived from control flow analysis."""

    scenario_id: str
    path_description: str
    conditions: List[str]
    expected_calls: List[str]


class TestGenerationQueries:
    """
    High-level queries for test generation tasks.
    """

    def __init__(
        self,
        context: QueryContext,
        graph_engine: GraphQueryEngine,
        call_graph_queries,
        control_flow_queries,
        data_flow_queries: DataFlowQueries,
    ):
        self.context = context
        self.graph_engine = graph_engine
        self.call_graph = call_graph_queries
        self.control_flow = control_flow_queries
        self.data_flow = data_flow_queries

    def get_function_test_profile(
        self, function: Union[str, object]
    ) -> FunctionTestProfile:
        name = self.context.resolve_function_name(function)
        code = self.context.resolve_function(function)

        callees = self.call_graph.get_callees(function)
        callers = self.call_graph.get_callers(function)

        cfg = self.control_flow.get_cfg(function)
        has_branches, has_loops, complexity = self._analyze_cfg_structure(cfg)

        signature_info = self._extract_signature_info(code)

        return FunctionTestProfile(
            name=name,
            signature=signature_info.get("signature"),
            parameters=signature_info.get("parameters", []),
            return_type=signature_info.get("return_type"),
            calls=callees,
            called_by=callers,
            has_branches=has_branches,
            has_loops=has_loops,
            complexity=complexity,
            external_dependencies=self._identify_external_deps(callees),
        )

    def get_test_scenarios(self, function: Union[str, object]) -> List[TestScenario]:
        cfg = self.control_flow.get_cfg(function)
        paths = self._extract_cfg_paths(cfg)

        scenarios = []
        for i, path in enumerate(paths):
            scenario = TestScenario(
                scenario_id=f"path_{i}",
                path_description=self._describe_path(path),
                conditions=self._extract_path_conditions(path),
                expected_calls=self._extract_path_calls(path),
            )
            scenarios.append(scenario)

        return scenarios

    def get_input_output_examples(
        self, function: Union[str, object]
    ) -> List[Dict[str, Any]]:
        try:
            summaries = self.data_flow.get_ipa_function_summaries(function)
            examples = []
            for summary in summaries:
                if hasattr(summary.summary, "examples"):
                    examples.extend(summary.summary.examples)
            return examples
        except Exception:
            return []

    def get_boundary_conditions(
        self, function: Union[str, object]
    ) -> List[Dict[str, Any]]:
        cfg = self.control_flow.get_cfg(function)
        return self._extract_boundary_conditions(cfg)

    def get_mock_requirements(self, function: Union[str, object]) -> List[str]:
        profile = self.get_function_test_profile(function)
        return profile.external_dependencies

    def _analyze_cfg_structure(self, cfg) -> tuple[bool, bool, int]:
        has_branches = False
        has_loops = False
        complexity = 1

        visited = set()
        queue = [cfg.entryTerminal]

        while queue:
            block = queue.pop(0)
            if block in visited:
                has_loops = True
                continue
            visited.add(block)

            if hasattr(block, "next") and isinstance(block.next, dict):
                num_exits = len(block.next)
                if num_exits > 1:
                    has_branches = True
                    complexity += num_exits - 1

                for target in block.next.values():
                    if target not in visited:
                        queue.append(target)

        return has_branches, has_loops, complexity

    def _extract_signature_info(self, code) -> Dict[str, Any]:
        info = {"signature": None, "parameters": [], "return_type": None}

        if hasattr(code, "annotation"):
            ann = code.annotation
            if hasattr(ann, "args"):
                info["parameters"] = [
                    arg.arg if hasattr(arg, "arg") else str(arg) for arg in ann.args
                ]
            if hasattr(ann, "returns"):
                info["return_type"] = str(ann.returns)

        if not info["parameters"] and hasattr(code, "argnames"):
            info["parameters"] = code.argnames

        return info

    def _identify_external_deps(self, callees: List[str]) -> List[str]:
        external = []
        for callee in callees:
            if "." in callee or callee.startswith("_"):
                external.append(callee)
        return external

    def _extract_cfg_paths(self, cfg) -> List[List]:
        paths = []
        self._dfs_paths(cfg.entryTerminal, [], set(), paths, max_paths=10)
        return paths

    def _dfs_paths(self, block, current_path, visited, all_paths, max_paths):
        if len(all_paths) >= max_paths:
            return

        current_path = current_path + [block]

        if hasattr(block, "next") and isinstance(block.next, dict):
            if not block.next:
                all_paths.append(current_path)
                return

            for target in block.next.values():
                if target not in visited:
                    new_visited = visited.copy()
                    new_visited.add(target)
                    self._dfs_paths(
                        target, current_path, new_visited, all_paths, max_paths
                    )
        else:
            all_paths.append(current_path)

    def _describe_path(self, path: List) -> str:
        steps = []
        for block in path:
            block_type = block.__class__.__name__
            steps.append(block_type)
        return " -> ".join(steps)

    def _extract_path_conditions(self, path: List) -> List[str]:
        conditions = []
        for block in path:
            if hasattr(block, "condition"):
                conditions.append(str(block.condition))
        return conditions

    def _extract_path_calls(self, path: List) -> List[str]:
        calls = []
        for block in path:
            if hasattr(block, "operations"):
                for op in block.operations:
                    if hasattr(op, "function"):
                        calls.append(str(op.function))
        return calls

    def _extract_boundary_conditions(self, cfg) -> List[Dict[str, Any]]:
        conditions = []
        visited = set()
        queue = [cfg.entryTerminal]

        while queue:
            block = queue.pop(0)
            if block in visited:
                continue
            visited.add(block)

            if hasattr(block, "condition"):
                condition_info = {
                    "type": self._classify_condition(block.condition),
                    "condition": str(block.condition),
                }
                conditions.append(condition_info)

            if hasattr(block, "next") and isinstance(block.next, dict):
                for target in block.next.values():
                    if target not in visited:
                        queue.append(target)

        return conditions

    def _classify_condition(self, condition) -> str:
        condition_str = str(condition).lower()
        if "none" in condition_str or "null" in condition_str:
            return "null_check"
        elif "==" in condition_str or "!=" in condition_str:
            return "equality"
        elif ">" in condition_str or "<" in condition_str:
            return "comparison"
        elif "len" in condition_str or "empty" in condition_str:
            return "collection_size"
        elif "isinstance" in condition_str or "type" in condition_str:
            return "type_check"
        else:
            return "other"
