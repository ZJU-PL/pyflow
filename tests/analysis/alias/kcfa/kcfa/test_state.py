from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.context import Ctx
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.heap_model import attr, elem
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import AllocKind
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.points_to_set import (
    AnalysisArena,
    PointsToSet,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.pointer_flow_graph import (
    NormalNode,
    PointerFlowEdge,
    PointerFlowKind,
    SelectorNode,
)
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


def test_points_to_sets_keep_analysis_arenas_isolated(object_factory):
    first = object_factory(AllocKind.OBJECT)
    second = object_factory(AllocKind.LIST)
    first_arena = AnalysisArena()
    second_arena = AnalysisArena()

    first_pts = PointsToSet.singleton(first, first_arena)
    second_pts = PointsToSet.singleton(second, second_arena)

    # Both objects occupy bit zero, but each set resolves it in its own arena.
    assert first_pts.objs_mask == second_pts.objs_mask == 1
    assert set(first_pts) == {first}
    assert set(second_pts) == {second}
    assert set(first_pts.union(second_pts)) == {first, second}


def test_state_rebases_external_points_to_sets_into_its_arena(
    empty_state, module_scope, simple_context, object_factory
):
    cvar = empty_state.get_variable(module_scope, simple_context, Variable("x"))
    obj = object_factory()

    empty_state.set_points_to(cvar, PointsToSet.singleton(obj))

    assert empty_state.get_points_to(cvar).arena is empty_state.arena


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


def test_state_statistics_count_reachable_objects(
    empty_state, module_scope, simple_context, object_factory
):
    cvar = empty_state.get_variable(module_scope, simple_context, Variable("x"))
    empty_state.set_points_to(cvar, PointsToSet.singleton(object_factory()))

    assert empty_state.get_statistics()["num_objects"] == 1


def test_heap_get_all_variables_returns_contextual_bindings(
    empty_state, module_scope, simple_context
):
    first = empty_state.get_variable(module_scope, simple_context, Variable("first"))
    second = empty_state.get_variable(module_scope, simple_context, Variable("second"))

    variables = set(empty_state._heap.get_all_variables(module_scope, simple_context))

    assert {first, second} <= variables


def test_selector_is_monotone_and_independent_of_candidate_arrival_order(
    empty_state, module_scope, simple_context, object_factory
):
    high = NormalNode(
        empty_state.get_variable(module_scope, simple_context, Variable("high"))
    )
    low = NormalNode(
        empty_state.get_variable(module_scope, simple_context, Variable("low"))
    )
    selector = SelectorNode()
    high_edge = PointerFlowEdge(high, selector, PointerFlowKind.NORMAL)
    low_edge = PointerFlowEdge(low, selector, PointerFlowKind.NORMAL)
    selector.add_edge(high_edge, 0)
    selector.add_edge(low_edge, 1)
    high_pts = PointsToSet.singleton(object_factory(AllocKind.OBJECT))
    low_pts = PointsToSet.singleton(object_factory(AllocKind.LIST))

    low_then_high = selector.flow_through(low_edge, low_pts).union(
        selector.flow_through(high_edge, high_pts)
    )
    high_then_low = selector.flow_through(high_edge, high_pts).union(
        selector.flow_through(low_edge, low_pts)
    )

    assert low_then_high == high_then_low == low_pts.union(high_pts)
