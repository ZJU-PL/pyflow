from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.context import (
    CallSite,
    CallStringContext,
    HybridContext,
    ObjectContext,
    ReceiverContext,
    TypeContext,
)


def test_call_site_is_bound_to_ir_statement(call_site_factory):
    site = call_site_factory("scope")

    assert isinstance(site, CallSite)
    assert "scope" in site.site_id
    assert site.short_id().endswith(":1")


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


def test_object_type_and_receiver_contexts_truncate(object_factory):
    first = object_factory()
    second = object_factory()

    assert ObjectContext((), 1).append(first).append(second).alloc_sites == (second,)
    assert TypeContext((), 1).append(first).append(second).types == (second,)
    assert ReceiverContext((), 1).append(first.alloc_site).append(second.alloc_site).receivers == (
        second.alloc_site,
    )


def test_hybrid_context_tracks_calls_and_objects(call_site_factory, object_factory):
    call_site = call_site_factory()
    obj = object_factory()

    ctx = HybridContext((), (), 1, 1).append(call_site, obj)

    assert ctx.call_sites == (call_site,)
    assert ctx.alloc_sites == (obj,)
    assert not ctx.is_empty()


def test_scope_is_ir_bound(module_scope, module_ir, simple_context):
    assert module_scope.stmt is module_ir
    assert module_scope.context == simple_context
    assert module_scope.name == "test_module"
    assert module_scope.kind == "module"
    assert module_scope.parent is module_scope
