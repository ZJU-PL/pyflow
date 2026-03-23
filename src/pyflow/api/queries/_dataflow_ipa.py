"""
Helpers for IPA-backed query views.
"""

from typing import List, Optional, Union

from ._models import IpaFunctionSummary


class IpaAnalyzer:
    """Extract summaries from IPA contexts."""

    def get_function_summaries(self, context, ipa, function: Optional[Union[str, object]] = None) -> List[IpaFunctionSummary]:
        target = context.resolve_function_name(function) if function else None
        summaries: List[IpaFunctionSummary] = []
        for ipa_context in ipa.contexts.values():
            name = context.context_name(ipa_context)
            if not name:
                continue
            if target and name != target:
                continue
            summaries.append(
                IpaFunctionSummary(
                    name=name,
                    signature=ipa_context.signature,
                    summary=ipa_context.summary,
                )
            )
        return summaries
