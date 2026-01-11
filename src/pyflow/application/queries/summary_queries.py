"""
Summary queries for PyFlow.
"""

from dataclasses import dataclass
from typing import List, Optional, Union


@dataclass(frozen=True)
class FunctionSummary:
    """Container for IPA summaries per analyzed context."""

    name: str
    signature: object
    summary: object


class SummaryQueries:
    """Summary query mixin for IPA summaries."""

    def get_function_summaries(
        self, function: Optional[Union[str, object]] = None
    ) -> List[FunctionSummary]:
        """Return IPA summaries for all contexts (or a single function)."""
        ipa = self._require_ipa()
        target = self._resolve_function_name(function) if function else None
        summaries: List[FunctionSummary] = []
        for context in ipa.contexts.values():
            name = self._context_name(context)
            if not name:
                continue
            if target and name != target:
                continue
            summaries.append(
                FunctionSummary(name=name, signature=context.signature, summary=context.summary)
            )
        return summaries
