from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.constraints import (
    AllocConstraint,
    CallConstraint,
    ConstraintManager,
    CopyConstraint,
    LoadConstraint,
    ReturnConstraint,
    StoreConstraint,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.heap_model import attr
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import AllocKind
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.variable import Variable


def test_copy_load_store_and_return_variable_sets():
    source = Variable("source")
    target = Variable("target")
    base = Variable("base")
    index = Variable("index")

    assert CopyConstraint(source, target).variables() == {source, target}
    assert LoadConstraint(base, attr("x"), target).variables() == {base}
    assert LoadConstraint(base, None, target, index=index).variables() == {base, index}
    assert StoreConstraint(base, attr("x"), source).variables() == {base}
    assert ReturnConstraint(source, target).variables() == {source, target}


def test_alloc_constraint_uses_ir_alloc_site(alloc_site_factory):
    target = Variable("target")
    constraint = AllocConstraint(target, alloc_site_factory(AllocKind.LIST))

    assert constraint.variables() == {target}
    assert constraint.alloc_site.kind is AllocKind.LIST


def test_call_constraint_uses_current_keyword_and_callsite_shape(call_site_factory):
    callee = Variable("callee")
    arg = Variable("arg")
    kw = Variable("kw")
    target = Variable("target")
    call_site = call_site_factory()

    constraint = CallConstraint(
        callee=callee,
        args=(arg,),
        kwargs=frozenset({("name", kw)}),
        target=target,
        call_site=call_site,
    )

    assert constraint.variables() == {callee, arg, kw, target}
    assert constraint.stmt is call_site.statement


def test_call_constraint_preserves_star_and_repeated_mapping_expansions(
    call_site_factory,
):
    callee = Variable("callee")
    items = Variable("items")
    left = Variable("left")
    right = Variable("right")

    constraint = CallConstraint(
        callee=callee,
        args=(items,),
        kwargs=((None, left), (None, right)),
        target=None,
        call_site=call_site_factory(),
        starred=(True,),
    )

    assert tuple(constraint.iter_args()) == ((items, True),)
    assert constraint.kwargs == ((None, left), (None, right))


def test_constraint_manager_indexes_by_explicit_trigger_variable(module_scope):
    manager = ConstraintManager()
    source = Variable("source")
    target = Variable("target")
    constraint = CopyConstraint(source, target)

    assert manager.add(module_scope, source, constraint)
    assert not manager.add(module_scope, source, constraint)
    assert manager.get_by_variable(source) == [constraint]
    assert manager.get_by_type(CopyConstraint) == [constraint]
    assert manager.all() == {(module_scope, constraint)}

    assert manager.remove(module_scope, source, constraint)
    assert manager.get_by_variable(source) == []
    assert manager.get_by_type(CopyConstraint) == []
