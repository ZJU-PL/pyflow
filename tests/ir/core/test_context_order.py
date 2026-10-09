"""Semantic context identities include inherited argument type fields."""

from pyflow.analysis.cpasignature import CPASignature
from pyflow.analysis.cpa.base import AnalysisContext
from pyflow.ir.core import (
    IRCatalog,
    AnalysisFacts,
    Capabilities,
    FactResult,
    CallTarget,
    ContextualKey,
    ContextSignature,
)
from pyflow.ir.core.order import canonical_context_signature
from pyflow.ir.storegraph.extendedtypes import ExistingObjectType
from pyflow.language.python import program


def test_existing_argument_values_and_types_keep_distinct_context_identities():
    code = object()
    catalog = IRCatalog()
    catalog.register_code(code, module="sample", qualname="call")

    def signature(value):
        argument = ExistingObjectType(program.Object(value), None)
        context = AnalysisContext(CPASignature(code, None, (argument,)), None, None)
        return canonical_context_signature(context, catalog, code)

    values = (None, 1, 2, int, str)
    identities = [signature(value) for value in values]
    assert len(set(identities)) == len(values)
    assert identities == [signature(value) for value in values]
    assert all("0x" not in identity.value for identity in identities)


def test_call_targets_follow_the_same_cpa_producer_as_contexts():
    code, target, operation = object(), object(), object()
    catalog = IRCatalog()
    caller = catalog.register_code(code, module="sample", qualname="caller")
    callee = catalog.register_code(target, module="sample", qualname="callee")
    node = catalog.register_node(caller.code_id, operation)
    source_context = object()
    cpa_context = object()
    ipa_context = object()
    source_id = catalog.register_context(code, source_context, ContextSignature("source"))
    cpa_id = catalog.register_context(target, cpa_context, ContextSignature("cpa"))
    ipa_id = catalog.register_context(target, ipa_context, ContextSignature("ipa"))
    key = ContextualKey(node, source_id)
    catalog.facts.publish(
        Capabilities.CALL_TARGETS,
        "ipa",
        {key: FactResult.exact((CallTarget(callee.code_id, ipa_id),), "ipa")},
    )
    facts = AnalysisFacts(catalog)
    assert tuple(facts.call_targets(code, operation, source_context))[0][1] is ipa_context
    catalog.facts.publish(
        Capabilities.CALL_TARGETS,
        "cpa",
        {key: FactResult.exact((CallTarget(callee.code_id, cpa_id),), "cpa")},
    )
    assert tuple(facts.call_targets(code, operation, source_context))[0][1] is cpa_context
    catalog.facts.publish(Capabilities.CALL_TARGETS, "cpa", {key: FactResult.exact((), "cpa")})
    assert facts.call_targets(code, operation, source_context) == frozenset()
