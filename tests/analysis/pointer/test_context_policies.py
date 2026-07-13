"""Tests for the current k-CFA context selector policies."""

import ast

from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.context import (
    CallSite,
    CallStringContext,
    HybridContext,
    ObjectContext,
    ParamContext,
    ReceiverContext,
    TypeContext,
)
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.context_selector import (
    ContextPolicy,
    ContextSelector,
    parse_policy,
)
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.object import (
    AbstractObject,
    AllocKind,
    AllocSite,
)
from pyflow.analysis.pointer._pythonstan.ir.ir_statements import IRAstStmt


def _stmt(source: str):
    return IRAstStmt(ast.parse(source).body[0])


def _call_site(name: str) -> CallSite:
    return CallSite(_stmt(f"{name} = f()"), "test_module")


def _object(kind: AllocKind = AllocKind.OBJECT) -> AbstractObject:
    ctx = CallStringContext((), 1)
    return AbstractObject(ctx, AllocSite(_stmt("x = object()"), kind))


def test_parse_policy_uses_current_enum_values():
    assert parse_policy("0-cfa") is ContextPolicy.INSENSITIVE
    assert parse_policy("2-cfa") is ContextPolicy.CALL_2
    assert parse_policy("1-obj") is ContextPolicy.OBJ_1
    assert parse_policy("1c1o") is ContextPolicy.HYBRID_CALL1_OBJ1


def test_call_string_policy_truncates_to_k():
    selector = ContextSelector(ContextPolicy.CALL_2)
    ctx = selector.empty_context()

    ctx = selector.select_call_context(_call_site("a"), ctx)
    ctx = selector.select_call_context(_call_site("b"), ctx)
    ctx = selector.select_call_context(_call_site("c"), ctx)

    assert isinstance(ctx, CallStringContext)
    assert len(ctx.call_sites) == 2
    assert "b = f()" in str(ctx.call_sites[0])
    assert "c = f()" in str(ctx.call_sites[1])


def test_insensitive_policy_keeps_empty_context():
    selector = ContextSelector(ContextPolicy.INSENSITIVE)
    ctx = selector.empty_context()

    assert selector.select_call_context(_call_site("a"), ctx) is ctx
    assert isinstance(ctx, CallStringContext)
    assert ctx.k == 0


def test_object_policy_prefers_callee_object():
    selector = ContextSelector(ContextPolicy.OBJ_1)
    callee = _object()

    ctx = selector.select_call_context(_call_site("a"), selector.empty_context(), callee_obj=callee)

    assert isinstance(ctx, ObjectContext)
    assert ctx.alloc_sites == (callee,)


def test_type_policy_uses_callee_when_available():
    selector = ContextSelector(ContextPolicy.TYPE_1)
    callee = _object(AllocKind.CLASS)

    ctx = selector.select_call_context(_call_site("a"), selector.empty_context(), callee_obj=callee)

    assert isinstance(ctx, TypeContext)
    assert ctx.types == (callee,)


def test_receiver_policy_uses_callee_alloc_site():
    selector = ContextSelector(ContextPolicy.RECEIVER_1)
    callee = _object()

    ctx = selector.select_call_context(_call_site("a"), selector.empty_context(), callee_obj=callee)

    assert isinstance(ctx, ReceiverContext)
    assert ctx.receivers == (callee.alloc_site,)


def test_param_policy_records_parameter_tuple():
    selector = ContextSelector(ContextPolicy.PARAM_1)
    arg = _object()

    ctx = selector.select_call_context(_call_site("a"), selector.empty_context(), params=(arg,))

    assert isinstance(ctx, ParamContext)
    assert ctx.params == ((arg,),)


def test_hybrid_policy_records_call_and_object():
    selector = ContextSelector(ContextPolicy.HYBRID_CALL1_OBJ1)
    call_site = _call_site("a")
    callee = _object()

    ctx = selector.select_call_context(call_site, selector.empty_context(), callee_obj=callee)

    assert isinstance(ctx, HybridContext)
    assert ctx.call_sites == (call_site,)
    assert ctx.alloc_sites == (callee,)
