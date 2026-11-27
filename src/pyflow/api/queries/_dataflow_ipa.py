"""
Helpers for IPA-backed query views.
"""

from typing import List, Optional, Union

from ._models import IpaFunctionSummary


class IpaAnalyzer:
    """Resolve immutable IPA summary facts."""

    def get_function_summaries(
        self, context, function: Optional[Union[str, object]] = None
    ) -> List[IpaFunctionSummary]:
        from pyflow.ir.core import AnalysisFacts, Capabilities, MissingAnalysisFact

        catalog = context.program.ir
        if catalog is None or not catalog.facts.has(Capabilities.IPA_SUMMARIES):
            raise MissingAnalysisFact(
                f"{Capabilities.IPA_SUMMARIES}: missing {Capabilities.IPA_SUMMARIES}"
            )

        codes = (
            (context.resolve_function(function),)
            if function is not None
            else tuple(context.program.liveCode)
        )
        summaries: List[IpaFunctionSummary] = []
        facts = AnalysisFacts(catalog)
        for code in sorted(codes, key=lambda item: str(catalog.procedure(item).code_id)):
            try:
                code_summaries = facts.ipa_summaries(code)
            except MissingAnalysisFact:
                if function is not None:
                    raise
                continue
            for summary in sorted(code_summaries, key=lambda item: item.context):
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
