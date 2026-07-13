from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.context import Ctx
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.heap_model import attr, elem
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import AllocKind
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.points_to_set import PointsToSet
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.variable import Variable, VariableKind


def test_points_to_set_singleton_union_and_iteration(object_factory):
    first = object_factory(AllocKind.OBJECT)
    second = object_factory(AllocKind.LIST)

    pts = PointsToSet.singleton(first).union(PointsToSet.singleton(second))

    assert set(pts) == {first, second}
    assert len(pts) == 2
    assert first in pts


def test_points_to_set_from_objects_handles_empty_and_nonempty(object_factory):
    assert PointsToSet.from_objects([]).is_empty()

    obj = object_factory()
    assert set(PointsToSet.from_objects([obj])) == {obj}


def test_state_sets_points_to_on_contextual_variables(empty_state, module_scope, simple_context, object_factory):
    cvar = empty_state.get_variable(module_scope, simple_context, Variable("x"))
    obj = object_factory()

    assert empty_state.set_points_to(cvar, PointsToSet.singleton(obj))
    assert not empty_state.set_points_to(cvar, PointsToSet.singleton(obj))
    assert set(empty_state.get_points_to(cvar)) == {obj}


def test_state_resolves_global_variable_to_module_scope(empty_state, module_scope, simple_context):
    local = empty_state.get_variable(module_scope, simple_context, Variable("x"))
    global_var = empty_state.get_variable(module_scope, simple_context, Variable("x", VariableKind.GLOBAL))

    assert isinstance(local, Ctx)
    assert global_var.scope is module_scope
    assert global_var.context == module_scope.context


def test_state_field_access_is_contextualized(empty_state, module_scope, simple_context, object_factory):
    obj = object_factory(AllocKind.OBJECT)
    field = attr("value")

    cfield = empty_state.get_field(module_scope, simple_context, obj, field)

    assert cfield.context == obj.context
    assert cfield.content.obj == obj
    assert cfield.content.field == field
    assert empty_state.has_field(module_scope, simple_context, obj, field) == cfield.content


def test_state_container_elem_field(empty_state, module_scope, simple_context, object_factory):
    obj = object_factory(AllocKind.LIST)

    cfield = empty_state.get_field(module_scope, simple_context, obj, elem())

    assert cfield.content.field == elem()


def test_state_statistics_shape(empty_state):
    stats = empty_state.get_statistics()

    assert set(stats) == {
        "num_variables",
        "num_objects",
        "num_heap_locations",
        "num_call_edges",
    }
