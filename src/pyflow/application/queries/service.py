"""
Semantic query service for PyFlow.
"""

from typing import Dict, Optional

from pyflow.application.errors import TemporaryLimitation

from .analysis_facts import AnalysisFactQueries
from .graph_queries import GraphQueries
from .summary_queries import SummaryQueries
from .server_mode import (
    DEFAULT_MODE,
    MCPServerMode,
    get_server_mode_description,
    resolve_capabilities,
)


class SemanticQueryService(
    GraphQueries,
    AnalysisFactQueries,
    SummaryQueries,
):
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
        GraphQueries.__init__(self)
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
        self._cfg_cache.clear()
        self._ssa_cache.clear()
        self._cdg_cache.clear()
        self._callgraph_cache = None

    def _require_ipa(self):
        if getattr(self.program, "ipa_analysis", None) is None:
            raise TemporaryLimitation("IPA analysis not available; run IPA first.")
        return self.program.ipa_analysis

    def _resolve_function(self, function):
        if isinstance(function, str):
            code = self._find_function_by_name(function)
            if code is None:
                raise ValueError(f"Function '{function}' not found in live code.")
            return code
        if hasattr(function, "codeName"):
            return function
        raise TypeError("Expected a function name or a PyFlow code object.")

    def _resolve_function_name(self, function):
        if function is None:
            raise ValueError("Function name is required.")
        if isinstance(function, str):
            return function
        if hasattr(function, "codeName"):
            return function.codeName()
        if hasattr(function, "__name__"):
            return function.__name__
        raise TypeError("Expected a function name or a PyFlow code object.")

    def _context_name(self, context) -> Optional[str]:
        code = getattr(context.signature, "code", None)
        return self._code_name(code)

    def _code_name(self, code) -> Optional[str]:
        if code is None:
            return None
        if hasattr(code, "codeName"):
            return code.codeName()
        if hasattr(code, "__name__"):
            return code.__name__
        return str(code)

    def _find_function_by_name(self, function_name: str):
        for code in getattr(self.program, "liveCode", []):
            if hasattr(code, "codeName") and code.codeName() == function_name:
                return code

        interface = getattr(self.program, "interface", None)
        if interface and hasattr(interface, "entryPoint"):
            for ep in interface.entryPoint:
                if hasattr(ep.code, "codeName") and ep.code.codeName() == function_name:
                    return ep.code
        return None
