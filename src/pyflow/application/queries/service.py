"""
Semantic query service for PyFlow.

This service reorganizes node-centric facts into agent-ready groupings such as
"call graph driven" insights for patch/test reasoning and "semantic fact"
answers for unit test generation or alias/lifetime-aware tasks.
"""

from typing import Dict, Optional, Union, List, Any

from .core import (
    DEFAULT_MODE,
    MCPServerMode,
    QueryContext,
    GraphQueryEngine,
    get_server_mode_description,
    resolve_capabilities,
)
from .graphs import CallGraphQueries, ControlFlowQueries, DataFlowQueries, IpaFunctionSummary


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
    ):
        self.context = QueryContext(compiler, program)
        self.graph_engine = GraphQueryEngine(self.context)
        self.control_flow_queries = ControlFlowQueries(self.context, self.graph_engine)
        self.call_graph_queries = CallGraphQueries(self.context, self.graph_engine)
        self.data_flow_queries = DataFlowQueries(self.context)

        self.compiler = compiler
        self.program = program
        self.server_mode = server_mode or DEFAULT_MODE

    def capabilities(self) -> Dict[str, Dict[str, Optional[str]]]:
        """Return supported query capabilities and notes for tooling."""
        capabilities = resolve_capabilities(self.server_mode)
        capabilities["_server_mode"] = {
            "available": True,
            "note": get_server_mode_description(self.server_mode),
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

    # Delegate to GraphQueryEngine
    def get_cfg(self, function: Union[str, object]):
        return self.control_flow_queries.get_cfg(function)

    def get_cfg_structure(self, function: Union[str, object]) -> Dict[str, Any]:
        """Return a JSON-friendly structure of the CFG."""
        return self.control_flow_queries.get_cfg_structure(function)

    def get_ssa(self, function: Union[str, object]):
        return self.control_flow_queries.get_ssa(function)

    def get_cdg(self, function: Union[str, object]):
        return self.control_flow_queries.get_cdg(function)

    def get_callgraph(self):
        return self.call_graph_queries.get_callgraph()

    # Call-graph driven helpers for patch/test reasoning
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

    # Semantic facts for unit test generation and alias reasoning
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

    def get_ipa_analysis(self):
        return self.data_flow_queries.get_ipa_analysis()

    def get_ipa_function_summaries(
        self, function: Optional[Union[str, object]] = None
    ) -> List[IpaFunctionSummary]:
        return self.data_flow_queries.get_ipa_function_summaries(function)
