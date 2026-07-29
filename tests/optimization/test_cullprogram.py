"""Tests for FactStore-based program context culling."""

from pyflow.ir.core import (
    CallTarget,
    Capabilities,
    ContextualKey,
    FactResult,
    ensure_code_indexed,
)
from pyflow.language.python import ast
from pyflow.optimization.cullprogram import retain_live_contexts


def _code_with_call():
    local = ast.Local("callee")
    call = ast.Call(local, [], [], None, None)
    code = ast.Code(
        "caller",
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=(),
            posonlynames=(),
            params=(),
            paramnames=(),
            defaults=(),
            vparam=None,
            kparam=None,
            returnparams=(),
            type_params=None,
        ),
        ast.Suite([ast.Discard(call)]),
    )
    return code, local, call


def test_retain_live_contexts_filters_contextual_facts_and_targets():
    code, local, call = _code_with_call()
    catalog = ensure_code_indexed(code)
    first, dead = object(), object()
    first_id = catalog.register_context(code, first, 0)
    dead_id = catalog.register_context(code, dead, 1)
    code_id = catalog.procedure(code).code_id
    symbol_id = catalog.symbol_id(local, code)
    call_id = catalog.node_id(call, code)

    catalog.facts.publish_many(
        "test",
        {
            Capabilities.CONTEXTS: {
                code_id: FactResult.exact((first_id, dead_id), "test")
            },
            Capabilities.REFERENCES: {
                ContextualKey(symbol_id, first_id): FactResult.exact(("live",), "test"),
                ContextualKey(symbol_id, dead_id): FactResult.exact(("dead",), "test"),
            },
            Capabilities.CALL_TARGETS: {
                ContextualKey(call_id, first_id): FactResult.exact(
                    (CallTarget(code_id, dead_id),), "test"
                ),
                ContextualKey(call_id, dead_id): FactResult.exact((), "test"),
            },
        },
    )

    assert retain_live_contexts(catalog, {code: {first}})
    assert catalog.facts.query(Capabilities.CONTEXTS, code_id).values == {first_id}
    assert catalog.facts.query(
        Capabilities.REFERENCES, ContextualKey(symbol_id, first_id)
    ).values == {"live"}
    assert not catalog.facts.query(
        Capabilities.CALL_TARGETS, ContextualKey(call_id, first_id)
    ).values
    assert not catalog.facts.query(
        Capabilities.REFERENCES, ContextualKey(symbol_id, dead_id)
    ).values


def test_retain_live_contexts_reports_no_change_for_complete_live_set():
    code, _local, _call = _code_with_call()
    catalog = ensure_code_indexed(code)
    context = object()
    context_id = catalog.register_context(code, context, 0)
    code_id = catalog.procedure(code).code_id
    catalog.facts.publish(
        Capabilities.CONTEXTS,
        "test",
        {code_id: FactResult.exact((context_id,), "test")},
    )

    assert not retain_live_contexts(catalog, {code: {context}})
