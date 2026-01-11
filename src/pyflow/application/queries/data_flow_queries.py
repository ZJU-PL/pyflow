"""
Data-flow helpers for coding agents.

These queries expose IPA/lifetime/store graph insights without forcing
consumers to interact with the raw analysis objects directly.
"""

from dataclasses import dataclass
from typing import List, Optional, Union

from pyflow.application.errors import TemporaryLimitation

from .context import QueryContext


@dataclass(frozen=True)
class IpaFunctionSummary:
    """Container for IPA summaries per analyzed context."""

    name: str
    signature: object
    summary: object


class DataFlowQueries:
    """Encapsulates IPA-driven facts in a task-aware facade."""

    def __init__(self, context: QueryContext):
        self.context = context

    def get_reaching_defs(self, function: Union[str, object]):
        """Reaching definitions are not exposed directly yet."""
        raise TemporaryLimitation(
            "Reaching-definitions are not computed directly; "
            "use get_ssa() and derive them from SSA form."
        )

    def get_aliases(self, function: Union[str, object]):
        """Alias facts are not publicly exposed yet."""
        raise TemporaryLimitation(
            "Alias queries are not exposed yet; "
            "use store graph + CPA dataflow for now."
        )

    def get_points_to(self, function: Union[str, object]):
        """Points-to facts are not publicly exposed yet."""
        raise TemporaryLimitation(
            "Points-to queries are not exposed yet; "
            "use store graph + CPA dataflow for now."
        )

    def get_lifetime(self):
        """Return lifetime analysis results if available."""
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
        """Return IPA analysis results when available."""
        return self.context.require_ipa()

    def get_ipa_function_summaries(
        self, function: Optional[Union[str, object]] = None
    ) -> List[IpaFunctionSummary]:
        """Return IPA summaries for all contexts (or a single function)."""
        ipa = self.context.require_ipa()
        target = self.context.resolve_function_name(function) if function else None
        summaries: List[IpaFunctionSummary] = []
        for context in ipa.contexts.values():
            name = self.context.context_name(context)
            if not name:
                continue
            if target and name != target:
                continue
            summaries.append(
                IpaFunctionSummary(
                    name=name, signature=context.signature, summary=context.summary
                )
            )
        return summaries
