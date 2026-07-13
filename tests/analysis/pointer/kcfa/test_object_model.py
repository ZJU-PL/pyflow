from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.object import (
    AbstractObject,
    AllocKind,
    AllocSite,
)


def test_alloc_site_requires_ir_statement(ir_stmt_factory):
    stmt = ir_stmt_factory("x = object()")
    site = AllocSite(stmt, AllocKind.OBJECT)

    assert site.stmt is stmt
    assert site.kind is AllocKind.OBJECT
    assert str(site).endswith(f"@{AllocKind.OBJECT}")


def test_alloc_site_from_ir_node(ir_stmt_factory):
    stmt = ir_stmt_factory("items = []")

    assert AllocSite.from_ir_node(stmt, AllocKind.LIST) == AllocSite(stmt, AllocKind.LIST)


def test_alloc_site_name_is_derived_from_named_ir_nodes(module_ir):
    site = AllocSite(module_ir, AllocKind.MODULE)

    assert site.name == "test_module"


def test_abstract_object_identity_uses_context_and_alloc_site(simple_context, alloc_site_factory):
    site = alloc_site_factory(AllocKind.OBJECT)
    obj = AbstractObject(simple_context, site)

    assert obj.context == simple_context
    assert obj.alloc_site == site
    assert obj.kind is AllocKind.OBJECT
    assert obj.get_type() == site


def test_callable_kinds(simple_context, ir_stmt_factory):
    function = AbstractObject(simple_context, AllocSite(ir_stmt_factory("def f():\n    pass"), AllocKind.BUILTIN))
    plain = AbstractObject(simple_context, AllocSite(ir_stmt_factory("x = object()"), AllocKind.OBJECT))

    assert function.is_callable
    assert not plain.is_callable
