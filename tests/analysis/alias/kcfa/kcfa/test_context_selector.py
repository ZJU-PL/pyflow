from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.context import (
    CallStringContext,
    HybridContext,
    ObjectContext,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.context_selector import (
    ContextPolicy,
    ContextSelector,
    parse_policy,
)


def test_parse_policy_accepts_current_values():
    assert parse_policy("0-cfa") is ContextPolicy.INSENSITIVE
    assert parse_policy("1-cfa") is ContextPolicy.CALL_1
    assert parse_policy("2-obj") is ContextPolicy.OBJ_2


def test_call_policy_appends_callsite(call_site_factory):
    selector = ContextSelector(ContextPolicy.CALL_1)
    call_site = call_site_factory()

    ctx = selector.select_call_context(call_site, selector.empty_context())

    assert isinstance(ctx, CallStringContext)
    assert ctx.call_sites == (call_site,)


def test_object_policy_uses_callee_object(call_site_factory, object_factory):
    selector = ContextSelector(ContextPolicy.OBJ_1)
    callee = object_factory()

    ctx = selector.select_call_context(call_site_factory(), selector.empty_context(), callee_obj=callee)

    assert isinstance(ctx, ObjectContext)
    assert ctx.alloc_sites == (callee,)


def test_hybrid_policy_tracks_call_and_object(call_site_factory, object_factory):
    selector = ContextSelector(ContextPolicy.HYBRID_CALL1_OBJ1)
    call_site = call_site_factory()
    callee = object_factory()

    ctx = selector.select_call_context(call_site, selector.empty_context(), callee_obj=callee)

    assert isinstance(ctx, HybridContext)
    assert ctx.call_sites == (call_site,)
    assert ctx.alloc_sites == (callee,)
