"""
Analysis fact engine for PyFlow.
"""

from dataclasses import dataclass
from typing import List, Optional, Union

from pyflow.application.errors import TemporaryLimitation
from .context import QueryContext
from .graph_engine import GraphQueryEngine


@dataclass(frozen=True)
class FunctionSummary:
    """Container for IPA summaries per analyzed context."""

    name: str
    signature: object
    summary: object


class AnalysisFactEngine:
    """
    Engine for retrieving analysis facts (callers, callees, lifetime, store graph, summaries).
    """

    def __init__(self, context: QueryContext, graph_engine: GraphQueryEngine):
        self.context = context
        self.graph_engine = graph_engine

    def get_callers(self, function: Union[str, object]) -> List[str]:
        """Return callers for the given function name."""
        name = self.context.resolve_function_name(function)
        graph = self.graph_engine.get_callgraph().get()
        callers = [caller for caller, callees in graph.items() if name in callees]
        return sorted(set(callers))

    def get_callees(self, function: Union[str, object]) -> List[str]:
        """Return callees for the given function name."""
        name = self.context.resolve_function_name(function)
        graph = self.graph_engine.get_callgraph().get()
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
        if getattr(self.context.program, "lifetime_analysis", None) is None:
            raise TemporaryLimitation(
                "Lifetime analysis not available; run the lifetime pass first."
            )
        return self.context.program.lifetime_analysis

    def get_store_graph(self):
        """Return the store graph if available."""
        if getattr(self.context.program, "storeGraph", None) is None:
            raise TemporaryLimitation("Store graph not available; run IPA/CPA first.")
        return self.context.program.storeGraph

    def get_ipa_analysis(self):
        """Return IPA analysis results if available."""
        return self.context.require_ipa()

    def get_function_summaries(
        self, function: Optional[Union[str, object]] = None
    ) -> List[FunctionSummary]:
        """Return IPA summaries for all contexts (or a single function)."""
        ipa = self.context.require_ipa()
        target = self.context.resolve_function_name(function) if function else None
        summaries: List[FunctionSummary] = []
        for context in ipa.contexts.values():
            name = self.context.context_name(context)
            if not name:
                continue
            if target and name != target:
                continue
            summaries.append(
                FunctionSummary(name=name, signature=context.signature, summary=context.summary)
            )
        return summaries
