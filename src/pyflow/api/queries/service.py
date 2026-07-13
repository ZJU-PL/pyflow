"""
Semantic query service for PyFlow.

This service provides a unified facade for querying analysis results,
wrapping the various query classes for convenient access.
"""

from typing import Any, Dict, List, Optional, Union

from pyflow.analysis.typeinfo import TypeFact, TypeInfoService
from pyflow.analysis.typeinfo.typesystem import ProperType

from .call_graph import CallGraphQueries
from .capabilities import (
    DEFAULT_MODE,
    CapabilityInfo,
    MCPServerMode,
    get_server_mode_description,
    resolve_capabilities,
)
from .context import QueryContext
from .control_flow import ControlFlowQueries
from .data_flow import DataFlowQueries, IpaFunctionSummary
from .engine import GraphQueryEngine
from .localization import LocalizationCandidate, LocalizationQueries, ProgramSlice
from .test_generation import FunctionTestProfile, TestGenerationQueries, TestScenario
from ._models import AliasInfo, PointsToInfo


class SemanticQueryService:
    """
    Queryable semantic facts for a Program.

    This service wraps existing analysis results (IPA/CPA/lifetime) and
    provides convenience methods for fetching graphs and semantic facts.
    """

    def __init__(
        self,
        compiler,
        program,
        server_mode: Optional[MCPServerMode] = None,
        type_info_service: Optional[TypeInfoService] = None,
    ):
        self.context = QueryContext(compiler, program)
        self.graph_engine = GraphQueryEngine(self.context)
        self.control_flow_queries = ControlFlowQueries(self.context, self.graph_engine)
        self.call_graph_queries = CallGraphQueries(self.context, self.graph_engine)
        self.data_flow_queries = DataFlowQueries(self.context, self.graph_engine)
        self.localization_queries = LocalizationQueries(
            self.context,
            self.graph_engine,
            self.call_graph_queries,
            self.control_flow_queries,
            self.data_flow_queries,
        )
        self.test_generation_queries = TestGenerationQueries(
            self.context,
            self.graph_engine,
            self.call_graph_queries,
            self.control_flow_queries,
            self.data_flow_queries,
        )

        self.compiler = compiler
        self.program = program
        self.server_mode = server_mode or DEFAULT_MODE
        self.type_info_service = type_info_service

    def capabilities(self) -> Dict[str, CapabilityInfo]:
        """Return supported query capabilities and notes for tooling."""
        capabilities = resolve_capabilities(self.server_mode)
        capabilities["_server_mode"] = {
            "available": True,
            "note": get_server_mode_description(self.server_mode),
        }
        capabilities["type_info"] = {
            "available": self.type_info_service is not None,
            "note": "Project-aware type information service.",
        }
        return capabilities

    def set_server_mode(self, mode: MCPServerMode):
        """Switch the MCP server mode and reset caches."""
        if self.server_mode is not mode:
            self.server_mode = mode
            self._reset_graph_cache()
        return self

    def _reset_graph_cache(self):
        self.graph_engine.reset_cache()

    # Type information queries
    def get_symbol_type(self, module_name: str, name: str) -> Optional[ProperType]:
        """Return the resolved type for a module-level symbol, if available."""
        if self.type_info_service is None:
            return None
        return self.type_info_service.type_of(module_name, name)

    def get_type_fact(self, module_name: str, name: str) -> Optional[TypeFact]:
        """Return the full collected type fact for a module-level symbol."""
        if self.type_info_service is None:
            return None
        return self.type_info_service.fact_of(module_name, name)

    # Control flow queries
    def get_cfg(self, function: Union[str, object]):
        return self.control_flow_queries.get_cfg(function)

    def get_cfg_structure(self, function: Union[str, object]) -> Dict[str, Any]:
        return self.control_flow_queries.get_cfg_structure(function)

    def get_ssa(self, function: Union[str, object]):
        return self.control_flow_queries.get_ssa(function)

    def get_cdg(self, function: Union[str, object]):
        return self.control_flow_queries.get_cdg(function)

    # Call graph queries
    def get_callgraph(self):
        """Return the raw call graph object for compatibility callers."""
        return self.call_graph_queries.get_callgraph()

    def get_callgraph_data(self) -> Dict[str, List[str]]:
        """Return the call graph as plain serializable data."""
        return self.call_graph_queries.get_callgraph_data()

    def get_callers(self, function: Union[str, object]) -> List[str]:
        return self.call_graph_queries.get_callers(function)

    def get_callees(self, function: Union[str, object]) -> List[str]:
        return self.call_graph_queries.get_callees(function)

    def get_downstream_functions(
        self, function: Union[str, object], max_depth: Optional[int] = None
    ) -> List[str]:
        return self.call_graph_queries.get_downstream_functions(function, max_depth)

    def get_upstream_functions(
        self, function: Union[str, object], max_depth: Optional[int] = None
    ) -> List[str]:
        return self.call_graph_queries.get_upstream_functions(function, max_depth)

    def get_shortest_path(
        self, source: Union[str, object], target: Union[str, object]
    ) -> Optional[List[str]]:
        return self.call_graph_queries.get_shortest_path(source, target)

    # Data flow queries
    def get_reaching_defs(self, function: Union[str, object]):
        return self.data_flow_queries.get_reaching_defs(function)

    def get_aliases(self, function: Union[str, object]):
        return self.data_flow_queries.get_aliases(function)

    def get_points_to(self, function: Union[str, object]):
        return self.data_flow_queries.get_points_to(function)

    def get_lifetime(self):
        return self.data_flow_queries.get_lifetime()

    def get_store_graph(self):
        return self.data_flow_queries.get_store_graph()

    def get_interprocedural_taint(
        self,
        function: Union[str, object],
        *,
        source_names: set[str],
        sink_names: set[str],
        sanitizer_names: Optional[set[str]] = None,
    ):
        return self.data_flow_queries.get_interprocedural_taint(
            function,
            source_names=source_names,
            sink_names=sink_names,
            sanitizer_names=sanitizer_names,
        )

    def get_ipa_analysis(self):
        return self.data_flow_queries.get_ipa_analysis()

    def get_ipa_function_summaries(
        self, function: Optional[Union[str, object]] = None
    ) -> List[IpaFunctionSummary]:
        return self.data_flow_queries.get_ipa_function_summaries(function)

    # Localization queries
    def find_related_functions(
        self, keywords: List[str], max_results: int = 10
    ) -> List[str]:
        return self.localization_queries.find_related_functions(keywords, max_results)

    def get_localization_candidates(
        self,
        symptom_function: Union[str, object],
        suspicious_variable: Optional[str] = None,
    ) -> List[LocalizationCandidate]:
        return self.localization_queries.get_localization_candidates(
            symptom_function, suspicious_variable
        )

    def compute_backward_slice(
        self, function: Union[str, object], variable: Optional[str] = None
    ) -> ProgramSlice:
        return self.localization_queries.compute_backward_slice(function, variable)

    def compute_forward_slice(
        self, function: Union[str, object], variable: Optional[str] = None
    ) -> ProgramSlice:
        return self.localization_queries.compute_forward_slice(function, variable)

    def trace_data_flow(
        self, function: Union[str, object], variable: str
    ) -> Dict[str, Any]:
        return self.localization_queries.trace_data_flow(function, variable)

    def find_feature_entry_points(self, feature_functions: List[str]) -> List[str]:
        return self.localization_queries.find_feature_entry_points(feature_functions)

    def get_change_impact(
        self, changed_function: Union[str, object]
    ) -> Dict[str, Union[str, List[str]]]:
        return self.localization_queries.get_change_impact(changed_function)

    # Test generation queries
    def get_function_test_profile(
        self, function: Union[str, object]
    ) -> FunctionTestProfile:
        return self.test_generation_queries.get_function_test_profile(function)

    def get_test_scenarios(self, function: Union[str, object]) -> List[TestScenario]:
        return self.test_generation_queries.get_test_scenarios(function)

    def get_input_output_examples(
        self, function: Union[str, object]
    ) -> List[Dict[str, Any]]:
        return self.test_generation_queries.get_input_output_examples(function)

    def get_boundary_conditions(
        self, function: Union[str, object]
    ) -> List[Dict[str, Any]]:
        return self.test_generation_queries.get_boundary_conditions(function)

    def get_mock_requirements(self, function: Union[str, object]) -> List[str]:
        return self.test_generation_queries.get_mock_requirements(function)

    # Heap / points-to queries
    def get_heap_graph(self):
        """Return the :class:`PointsToGraph` if the heap pass has run."""
        return getattr(self.program, "heap_analysis", None)

    def _require_heap_graph(self):
        graph = self.get_heap_graph()
        if graph is None:
            raise RuntimeError(
                "Heap analysis not available; ensure the 'heap' pass has been run."
            )
        return graph

    def get_escaped_locations(self) -> List[str]:
        """Return human-readable labels of all escaped heap locations."""
        graph = self._require_heap_graph()
        return sorted(entry.label for entry in graph.iter_entries() if entry.is_escaped)

    def get_singleton_locations(self) -> List[str]:
        """Return labels of all singleton (strong-update-eligible) locations."""
        graph = self._require_heap_graph()
        return sorted(
            entry.label for entry in graph.iter_entries() if entry.is_singleton
        )

    def heap_never_escapes(self, variable: str) -> bool:
        """Check whether a named variable's heap location has never escaped."""
        graph = self._require_heap_graph()
        for entry in graph.iter_entries():
            if entry.label == variable:
                return not entry.is_escaped
        return True

    def heap_aliased(self, var_a: str, var_b: str) -> bool:
        """Check whether two named variables are must-aliases."""
        graph = self._require_heap_graph()
        loc_a = None
        loc_b = None
        for entry in graph.iter_entries():
            if entry.label == var_a:
                loc_a = entry.location
            if entry.label == var_b:
                loc_b = entry.location
        if loc_a is None or loc_b is None:
            return False
        return graph.aliased(loc_a, loc_b)

    def heap_single_reference(self, variable: str) -> bool:
        """Check whether a variable's heap location has ≤ 1 reference."""
        graph = self._require_heap_graph()
        for entry in graph.iter_entries():
            if entry.label == variable:
                return entry.ref_count <= 1
        return True

    def get_aliases_for_variable(self, variable: str) -> AliasInfo:
        """Return structured alias information for a named variable."""
        graph = self.get_heap_graph()
        info = AliasInfo(variable=variable)
        if graph is None:
            return info
        for entry in graph.iter_entries():
            if entry.label == variable:
                info.aliases = {
                    loc.root.label for loc in entry.aliases if loc.root.label
                }
                info.is_aliased = len(info.aliases) > 1
                info.ref_count = entry.ref_count
                info.is_escaped = entry.is_escaped
                info.is_singleton = entry.is_singleton
                info.strong_update_possible = entry.is_strong
                break
        return info

    def get_points_to_for_variable(self, variable: str) -> PointsToInfo:
        """Return structured points-to information for a named variable."""
        graph = self.get_heap_graph()
        info = PointsToInfo(variable=variable)
        if graph is None:
            return info
        for entry in graph.iter_entries():
            if entry.label == variable:
                info.points_to = {
                    loc.root.label for loc in entry.aliases if loc.root.label
                }
                info.ref_count = entry.ref_count
                info.is_escaped = entry.is_escaped
                info.is_singleton = entry.is_singleton
                info.strong_update_possible = entry.is_strong
                info.may_be_null = entry.is_escaped
                break
        return info
