import ast

import pytest

from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.context import (
    CallSite,
    CallStringContext,
    HybridContext,
    ObjectContext,
    ReceiverContext,
    TypeContext,
)
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRAstStmt


def test_call_site_is_bound_to_ir_statement(call_site_factory):
    site = call_site_factory("scope")

    assert isinstance(site, CallSite)
    assert "scope" in site.site_id
    assert site.short_id().endswith(":1")


def test_call_site_without_location_has_stable_content_identity():
    first_node = ast.parse("result = f()").body[0]
    second_node = ast.parse("result = f()").body[0]
    for node in (first_node, second_node):
        node.lineno = None
        node.col_offset = None

    first = CallSite(IRAstStmt(first_node), "scope", 2)
    second = CallSite(IRAstStmt(second_node), "scope", 2)

    assert first.short_id() == second.short_id()


def test_call_string_context_appends_and_truncates(call_site_factory):
    ctx = CallStringContext((), 2)
    first = call_site_factory("a")
    second = call_site_factory("b")
    third = call_site_factory("c")

    ctx = ctx.append(first).append(second).append(third)

    assert ctx.call_sites == (second, third)
    assert not ctx.is_empty()


def test_zero_cfa_context_does_not_grow(call_site_factory):
    ctx = CallStringContext((), 0)

    assert ctx.append(call_site_factory()) is ctx
    assert ctx.is_empty()


def test_context_labels_are_content_based_and_deterministic(call_site_factory):
    site = call_site_factory("scope")
    first = CallStringContext((), 1).append(site)
    second = CallStringContext((), 1).append(site)

    assert str(first) == str(second)
    assert site.site_id in str(first)


def test_object_type_and_receiver_contexts_truncate(object_factory):
    first = object_factory()
    second = object_factory()

    assert ObjectContext((), 1).append(first).append(second).alloc_sites == (second,)
    assert TypeContext((), 1).append(first).append(second).types == (second,)
    assert ReceiverContext((), 1).append(first.alloc_site).append(second.alloc_site).receivers == (
        second.alloc_site,
    )


def test_object_context_rejects_context_objects(simple_context):
    with pytest.raises(TypeError, match="CallSite or AbstractObject"):
        ObjectContext((), 1).append(simple_context)


def test_hybrid_context_tracks_calls_and_objects(call_site_factory, object_factory):
    call_site = call_site_factory()
    obj = object_factory()

    ctx = HybridContext((), (), 1, 1).append(call_site, obj)

    assert ctx.call_sites == (call_site,)
    assert ctx.alloc_sites == (obj,)
    assert not ctx.is_empty()


def test_hybrid_context_updates_nonzero_dimensions_independently(
    call_site_factory, object_factory
):
    call_site = call_site_factory()
    obj = object_factory()

    object_only = HybridContext((), (), 0, 1).append(call_site, obj)
    call_only = HybridContext((), (), 1, 0).append(call_site, obj)

    assert object_only.call_sites == ()
    assert object_only.alloc_sites == (obj,)
    assert call_only.call_sites == (call_site,)
    assert call_only.alloc_sites == ()


def test_scope_is_ir_bound(module_scope, module_ir, simple_context):
    assert module_scope.stmt is module_ir
    assert module_scope.context == simple_context
    assert module_scope.name == "test_module"
    assert module_scope.kind == "module"
    assert module_scope.parent is module_scope
