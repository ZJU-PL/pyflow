"""
Semantic query service for PyFlow.
"""

from typing import Dict, Optional

from pyflow.application.errors import TemporaryLimitation

from .facts import FactQueries
from .graphs import GraphQueries
from .summaries import SummaryQueries


class SemanticQueryService(GraphQueries, FactQueries, SummaryQueries):
    """
    Queryable semantic facts for a Program.

    This service wraps existing analysis results (IPA/CPA/lifetime) and
    provides convenience methods for fetching graphs and semantic facts.
    """

    def __init__(self, compiler, program):
        GraphQueries.__init__(self)
        self.compiler = compiler
        self.program = program

    def capabilities(self) -> Dict[str, Dict[str, Optional[str]]]:
        """Return supported query capabilities and notes for tooling."""
        return {
            "cfg": {"available": True, "note": None},
            "ssa": {"available": True, "note": None},
            "cdg": {"available": True, "note": None},
            "callgraph": {"available": True, "note": "Requires IPA analysis."},
            "callers": {"available": True, "note": "Requires IPA analysis."},
            "callees": {"available": True, "note": "Requires IPA analysis."},
            "function_summaries": {"available": True, "note": "Requires IPA analysis."},
            "store_graph": {"available": True, "note": "Requires IPA/CPA analysis."},
            "lifetime": {"available": True, "note": "Requires lifetime analysis."},
            "reaching_defs": {
                "available": False,
                "note": "Derive from SSA form.",
            },
            "aliases": {
                "available": False,
                "note": "Use store graph + CPA dataflow.",
            },
            "points_to": {
                "available": False,
                "note": "Use store graph + CPA dataflow.",
            },
        }

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
