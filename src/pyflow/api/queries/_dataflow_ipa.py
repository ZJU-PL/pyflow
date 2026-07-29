"""
Helpers for IPA-backed query views.
"""

from typing import List, Optional, Union

from ._models import IpaFunctionSummary


class IpaAnalyzer:
    """Resolve immutable IPA summary facts."""

    def get_function_summaries(self, context, function: Optional[Union[str, object]] = None) -> List[IpaFunctionSummary]:
        from pyflow.ir.core import AnalysisFacts

        codes = (
            (context.resolve_function(function),)
            if function is not None
            else tuple(context.program.liveCode)
        )
        summaries: List[IpaFunctionSummary] = []
        facts = AnalysisFacts(context.program.ir)
        for code in sorted(codes, key=lambda item: str(context.program.ir.procedure(item).code_id)):
            for summary in sorted(facts.ipa_summaries(code), key=lambda item: item.context):
                summaries.append(
                    IpaFunctionSummary(
                        name=context.code_name(code),
                        context_id=summary.context,
                        parameter_names=summary.parameter_names,
                        return_dependencies=summary.return_dependencies,
                        returns_value=summary.returns_value,
                        examples=summary.examples,
                    )
                )
        return summaries
