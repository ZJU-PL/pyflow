"""
Semantic query service for PyFlow.
"""

from typing import Dict, Optional, Union, List, Any

from .context import QueryContext
from .facts_engine import AnalysisFactEngine, FunctionSummary
from .graph_engine import GraphQueryEngine
from .server_mode import (
    DEFAULT_MODE,
    MCPServerMode,
    get_server_mode_description,
    resolve_capabilities,
)


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
        self.fact_engine = AnalysisFactEngine(self.context, self.graph_engine)

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
        return self.graph_engine.get_cfg(function)

    def get_cfg_structure(self, function: Union[str, object]) -> Dict[str, Any]:
        """Return a JSON-friendly structure of the CFG."""
        return self.graph_engine.get_cfg_structure(function)

    def get_ssa(self, function: Union[str, object]):
        return self.graph_engine.get_ssa(function)

    def get_cdg(self, function: Union[str, object]):
        return self.graph_engine.get_cdg(function)

    def get_callgraph(self):
        return self.graph_engine.get_callgraph()

    # Delegate to AnalysisFactEngine
    def get_callers(self, function: Union[str, object]) -> List[str]:
        return self.fact_engine.get_callers(function)

    def get_callees(self, function: Union[str, object]) -> List[str]:
        return self.fact_engine.get_callees(function)

    def get_reaching_defs(self, function: Union[str, object]):
        return self.fact_engine.get_reaching_defs(function)

    def get_aliases(self, function: Union[str, object]):
        return self.fact_engine.get_aliases(function)

    def get_points_to(self, function: Union[str, object]):
        return self.fact_engine.get_points_to(function)

    def get_lifetime(self):
        return self.fact_engine.get_lifetime()

    def get_store_graph(self):
        return self.fact_engine.get_store_graph()

    def get_ipa_analysis(self):
        return self.fact_engine.get_ipa_analysis()

    def get_function_summaries(
        self, function: Optional[Union[str, object]] = None
    ) -> List[FunctionSummary]:
        return self.fact_engine.get_function_summaries(function)
