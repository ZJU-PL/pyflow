"""Task-oriented test generation queries built on analysis facts."""

import ast
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Union

from pyflow.application.errors import TemporaryLimitation
from pyflow.language.asttools import mccabe_complexity

from .._models import FunctionTestProfile, TestScenario
from ..context import QueryContext
from ..data_flow import DataFlowQueries
from ..engine import GraphQueryEngine


class TestGenerationQueries:
    """High-level queries for test generation tasks."""

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

    def get_function_test_profile(self, function: Union[str, object]) -> FunctionTestProfile:
        name = self.context.resolve_function_name(function)
        code = self.context.resolve_function(function)
        callees = self.call_graph.get_callees(function)
        callers = self.call_graph.get_callers(function)
        cfg = self.control_flow.get_cfg(function)
        has_branches, has_loops, complexity = self._analyze_cfg_structure(cfg)
        complexity = self._source_complexity(code) or complexity
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
        return [
            TestScenario(
                scenario_id=f"path_{i}",
                path_description=self._describe_path(path),
                conditions=self._extract_path_conditions(path),
                expected_calls=self._extract_path_calls(path),
            )
            for i, path in enumerate(paths)
        ]

    def get_input_output_examples(self, function: Union[str, object]) -> List[Dict[str, Any]]:
        try:
            examples = []
            for summary in self.data_flow.get_ipa_function_summaries(function):
                examples.extend(summary.examples)
            return examples
        except (TemporaryLimitation, ValueError, TypeError, AttributeError):
            return []

    def get_boundary_conditions(self, function: Union[str, object]) -> List[Dict[str, Any]]:
        return self._extract_boundary_conditions(self.control_flow.get_cfg(function))

    def get_mock_requirements(self, function: Union[str, object]) -> List[str]:
        return self.get_function_test_profile(function).external_dependencies

    def _analyze_cfg_structure(self, cfg) -> tuple[bool, bool, int]:
        has_branches = False
        has_loops = False
        complexity = 1

        visited = set()
        queue = deque([cfg.entryTerminal])

        while queue:
            block = queue.popleft()
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

    def _source_complexity(self, code) -> int | None:
        location = self._source_location(code)
        if location is None:
            return None

        filename, lineno = location
        try:
            source = Path(filename).read_text(encoding="utf-8")
            tree = ast.parse(source, filename=filename)
        except (OSError, SyntaxError, ValueError):
            return None

        function_node = self._find_source_function_node(tree, code, lineno)
        if function_node is None:
            return None
        return mccabe_complexity(function_node)

    def _source_location(self, code) -> tuple[str, int | None] | None:
        filename, lineno = self.context._origin_location(code)
        if filename:
            return str(filename), self._coerce_lineno(lineno)
        return None

    @staticmethod
    def _coerce_lineno(lineno) -> int | None:
        try:
            value = int(lineno)
        except (TypeError, ValueError):
            return None
        return value if value > 0 else None

    def _find_source_function_node(self, tree: ast.AST, code, lineno: int | None):
        name = (
            self.context.code_name(code)
            if hasattr(self.context, "code_name")
            else None
        )
        if name is None:
            name = getattr(code, "name", None)
        short_name = str(name).rsplit(".", 1)[-1] if name else None

        candidates = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        if lineno is not None:
            line_matches = [
                node
                for node in candidates
                if getattr(node, "lineno", None) == lineno
                and (short_name is None or node.name == short_name)
            ]
            if line_matches:
                return line_matches[0]

        if short_name is not None:
            name_matches = [node for node in candidates if node.name == short_name]
            if len(name_matches) == 1:
                return name_matches[0]

        return None

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
        return [callee for callee in callees if "." in callee or callee.startswith("_")]

    def _extract_cfg_paths(self, cfg) -> List[List]:
        paths = []
        self._dfs_paths(
            cfg.entryTerminal,
            [],
            set(),
            paths,
            max_paths=10,
            depth=0,
            max_depth=64,
        )
        return paths

    def _dfs_paths(self, block, current_path, visited, all_paths, max_paths, depth, max_depth):
        if len(all_paths) >= max_paths:
            return
        if depth >= max_depth:
            all_paths.append(current_path + [block])
            return

        current_path = current_path + [block]
        current_visited = visited | {block}

        nxt = getattr(block, "next", None)
        if isinstance(nxt, dict):
            if not nxt:
                all_paths.append(current_path)
                return

            progressed = False
            for target in nxt.values():
                if target is None:
                    continue
                if target not in current_visited:
                    progressed = True
                    self._dfs_paths(
                        target,
                        current_path,
                        current_visited,
                        all_paths,
                        max_paths,
                        depth + 1,
                        max_depth,
                    )
            if not progressed:
                all_paths.append(current_path)
        elif nxt is not None:
            if nxt in current_visited:
                all_paths.append(current_path)
            else:
                self._dfs_paths(
                    nxt,
                    current_path,
                    current_visited,
                    all_paths,
                    max_paths,
                    depth + 1,
                    max_depth,
                )
        else:
            all_paths.append(current_path)

    def _describe_path(self, path: List) -> str:
        return " -> ".join(block.__class__.__name__ for block in path)

    def _extract_path_conditions(self, path: List) -> List[str]:
        return [str(block.condition) for block in path if hasattr(block, "condition")]

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
        queue = deque([cfg.entryTerminal])

        while queue:
            block = queue.popleft()
            if block in visited:
                continue
            visited.add(block)

            if hasattr(block, "condition"):
                conditions.append(
                    {
                        "type": self._classify_condition(block.condition),
                        "condition": str(block.condition),
                    }
                )

            if hasattr(block, "next") and isinstance(block.next, dict):
                for target in block.next.values():
                    if target not in visited:
                        queue.append(target)

        return conditions

    def _classify_condition(self, condition) -> str:
        condition_str = str(condition).lower()
        if "none" in condition_str or "null" in condition_str:
            return "null_check"
        if "==" in condition_str or "!=" in condition_str:
            return "equality"
        if ">" in condition_str or "<" in condition_str:
            return "comparison"
        if "len" in condition_str or "empty" in condition_str:
            return "collection_size"
        if "isinstance" in condition_str or "type" in condition_str:
            return "type_check"
        return "other"
