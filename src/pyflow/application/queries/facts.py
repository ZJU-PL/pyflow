"""
Semantic fact queries for PyFlow.
"""

from typing import List, Union

from pyflow.application.errors import TemporaryLimitation


class FactQueries:
    """Fact query mixin for call relationships and analysis results."""

    def get_callers(self, function: Union[str, object]) -> List[str]:
        """Return callers for the given function name."""
        name = self._resolve_function_name(function)
        graph = self.get_callgraph().get()
        callers = [caller for caller, callees in graph.items() if name in callees]
        return sorted(set(callers))

    def get_callees(self, function: Union[str, object]) -> List[str]:
        """Return callees for the given function name."""
        name = self._resolve_function_name(function)
        graph = self.get_callgraph().get()
        return sorted(graph.get(name, set()))

    def get_reaching_defs(self, function: Union[str, object]):
        """Return reaching definitions for a function."""
        raise TemporaryLimitation(
            "Reaching-definitions are not computed directly; "
            "use get_ssa() and derive them from SSA form."
        )

    def get_aliases(self, function: Union[str, object]):
        """Return alias information for a function."""
        raise TemporaryLimitation(
            "Alias queries are not exposed yet; "
            "use store graph + CPA dataflow for now."
        )

    def get_points_to(self, function: Union[str, object]):
        """Return points-to information for a function."""
        raise TemporaryLimitation(
            "Points-to queries are not exposed yet; "
            "use store graph + CPA dataflow for now."
        )

    def get_lifetime(self):
        """Return lifetime analysis results."""
        if getattr(self.program, "lifetime_analysis", None) is None:
            raise TemporaryLimitation(
                "Lifetime analysis not available; run the lifetime pass first."
            )
        return self.program.lifetime_analysis

    def get_store_graph(self):
        """Return the store graph if available."""
        if getattr(self.program, "storeGraph", None) is None:
            raise TemporaryLimitation("Store graph not available; run IPA/CPA first.")
        return self.program.storeGraph

    def get_ipa_analysis(self):
        """Return IPA analysis results if available."""
        return self._require_ipa()
