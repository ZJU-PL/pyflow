"""Tests for control-flow constructs: switch, for, TypeSwitch, try, break/continue."""

from __future__ import annotations

from pyflow.analysis.alias.flow_sensitive import (
    HeapAnalysis,
    HeapObjectKind,
    HeapPolicy,
    UpdatePolicy,
)
from pyflow.language.python import ast as py_ast


def _existing(value):
    return py_ast.Existing(py_ast.program.Object(value))


def _code(name: str, body: py_ast.Suite, *, params=(), returns=()):
    return py_ast.Code(
        name,
        py_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=list(params),
            paramnames=[param.name for param in params],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=list(returns),
            type_params=None,
        ),
        body,
    )


def test_joins_switch_branch_field_values():
    obj = py_ast.Local("obj")
    cond = py_ast.Local("cond")
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), cond),
                    py_ast.Suite([py_ast.SetAttr(left, obj, _existing("payload"))]),
                    py_ast.Suite([py_ast.SetAttr(right, obj, _existing("payload"))]),
                ),
                py_ast.Assign(py_ast.GetAttr(obj, _existing("payload")), [loaded]),
            ]
        ),
        params=(obj, cond, left, right),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    left_location = heap.locations_for_local(code, left)[0]
    right_location = heap.locations_for_local(code, right)[0]

    assert left_location in loaded_locations
    assert right_location in loaded_locations
    assert graph.may_alias(loaded_locations[0], left_location)


def test_joins_switch_branch_local_bindings():
    """Local points-to bindings are part of the flow state, not global mutation."""
    cond = py_ast.Local("cond")
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    selected = py_ast.Local("selected")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), cond),
                    py_ast.Suite([py_ast.Assign(left, [selected])]),
                    py_ast.Suite([py_ast.Assign(right, [selected])]),
                ),
                py_ast.Assign(selected, [loaded]),
            ]
        ),
        params=(cond, left, right),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    selected_locations = heap.locations_for_local(code, selected)
    loaded_locations = heap.locations_for_local(code, loaded)
    left_location = heap.locations_for_local(code, left)[0]
    right_location = heap.locations_for_local(code, right)[0]

    assert left_location in selected_locations
    assert right_location in selected_locations
    assert left_location in loaded_locations
    assert right_location in loaded_locations
    assert any(graph.may_alias(loc, left_location) for loc in loaded_locations)
    assert any(graph.may_alias(loc, right_location) for loc in loaded_locations)


def test_switch_join_preserves_incoming_binding_on_unchanged_branch():
    cond = py_ast.Local("cond")
    original = py_ast.Local("original")
    replacement = py_ast.Local("replacement")
    selected = py_ast.Local("selected")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(original, [selected]),
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), cond),
                    py_ast.Suite([py_ast.Assign(replacement, [selected])]),
                    py_ast.Suite([]),
                ),
                py_ast.Assign(selected, [loaded]),
            ]
        ),
        params=(cond, original, replacement),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    assert heap.locations_for_local(code, original)[0] in loaded_locations
    assert heap.locations_for_local(code, replacement)[0] in loaded_locations


def test_identity_guard_narrows_aliases_in_each_branch():
    cond = py_ast.Local("cond")
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    selected = py_ast.Local("selected")
    true_loaded = py_ast.Local("true_loaded")
    false_loaded = py_ast.Local("false_loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [left]),
                py_ast.Assign(py_ast.BuildList([]), [right]),
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), cond),
                    py_ast.Suite([py_ast.Assign(left, [selected])]),
                    py_ast.Suite([py_ast.Assign(right, [selected])]),
                ),
                py_ast.Switch(
                    py_ast.Condition(
                        py_ast.Suite([]),
                        py_ast.Is(selected, left),
                    ),
                    py_ast.Suite([py_ast.Assign(selected, [true_loaded])]),
                    py_ast.Suite([py_ast.Assign(selected, [false_loaded])]),
                ),
            ]
        ),
        params=(cond,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, true_loaded) == heap.locations_for_local(
        code,
        left,
    )
    assert heap.locations_for_local(code, false_loaded) == heap.locations_for_local(
        code,
        right,
    )


def test_joined_roots_remain_individually_singleton():
    cond = py_ast.Local("cond")
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    selected = py_ast.Local("selected")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [left]),
                py_ast.Assign(py_ast.BuildList([]), [right]),
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), cond),
                    py_ast.Suite([py_ast.Assign(left, [selected])]),
                    py_ast.Suite([py_ast.Assign(right, [selected])]),
                ),
            ]
        ),
        params=(cond,),
    )

    analysis = HeapAnalysis(policy=HeapPolicy.precise())
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    for location in heap.locations_for_local(code, selected):
        field = heap.dynamic_attribute_location(location, "payload")
        assert heap.update_policy_for_location(field) is UpdatePolicy.STRONG


def test_loop_fixed_point_keeps_wildcard_contamination():
    mapping = py_ast.Local("mapping")
    cond = py_ast.Local("cond")
    dynamic_key = py_ast.Local("dynamic_key")
    dynamic_value = py_ast.Local("dynamic_value")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildMap([]), [mapping]),
                py_ast.While(
                    py_ast.Condition(py_ast.Suite([]), cond),
                    py_ast.Suite(
                        [py_ast.SetSubscript(dynamic_value, mapping, dynamic_key)]
                    ),
                    py_ast.Suite([]),
                ),
                py_ast.Assign(py_ast.GetSubscript(mapping, _existing("a")), [loaded]),
            ]
        ),
        params=(cond, dynamic_key, dynamic_value),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    dynamic_location = heap.locations_for_local(code, dynamic_value)[0]
    loaded_locations = heap.locations_for_local(code, loaded)

    assert dynamic_location in loaded_locations
    assert graph.may_alias(loaded_locations[0], dynamic_location)


def test_idempotent_loop_write_reaches_a_fixed_point_without_degradation():
    """Repeated abstract writes must not create fresh lattice elements."""
    obj = py_ast.Local("obj")
    cond = py_ast.Local("cond")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    loop = py_ast.While(
        py_ast.Condition(py_ast.Suite([]), cond),
        py_ast.Suite([py_ast.SetAttr(value, obj, _existing("payload"))]),
        py_ast.Suite([]),
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                loop,
                py_ast.Assign(py_ast.GetAttr(obj, _existing("payload")), [loaded]),
            ]
        ),
        params=(cond, value),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert "loop-iteration-bound" not in {
        reason for reasons in analysis.precision_degradations.values() for reason in reasons
    }
    assert heap.locations_for_local(code, value)[0] in heap.locations_for_local(
        code, loaded
    )


def test_loop_bound_degrades_and_havocs_modified_heap_locations():
    """A genuine bound hit is visible and does not retain a precise store."""
    from pyflow.analysis.alias.flow_sensitive.abstraction import HeapAbstraction
    from pyflow.analysis.alias.flow_sensitive.transfer import HeapTransferEngine

    obj = py_ast.Local("obj")
    cond = py_ast.Local("cond")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    loop = py_ast.While(
        py_ast.Condition(py_ast.Suite([]), cond),
        py_ast.Suite([py_ast.SetAttr(value, obj, _existing("payload"))]),
        py_ast.Suite([]),
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                loop,
                py_ast.Assign(py_ast.GetAttr(obj, _existing("payload")), [loaded]),
            ]
        ),
        params=(cond, value),
    )

    heap = HeapAbstraction(lambda _procedure, _local: ())
    engine = HeapTransferEngine(heap, max_loop_iterations=1)
    outcome = engine.analyze_node(code, code.ast)

    assert (loop, "loop-iteration-bound") in engine.precision_degradations
    assert outcome.normal is not None
    loaded_locations = heap.locations_for_local(code, loaded)
    assert any(
        location.root.kind is HeapObjectKind.UNKNOWN for location in loaded_locations
    )


def test_while_re_evaluates_condition_with_loop_carried_heap_effects():
    obj = py_ast.Local("obj")
    cond_formal = py_ast.Local("cond_formal")
    initial = py_ast.Local("initial")
    replacement = py_ast.Local("replacement")
    loaded = py_ast.Local("loaded")
    condition_code = _code(
        "condition",
        py_ast.Suite(
            [
                py_ast.SetAttr(
                    py_ast.GetAttr(cond_formal, _existing("inp")),
                    cond_formal,
                    _existing("out"),
                )
            ]
        ),
        params=(cond_formal,),
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.SetAttr(initial, obj, _existing("inp")),
                py_ast.While(
                    py_ast.Condition(
                        py_ast.Suite([]),
                        py_ast.DirectCall(condition_code, None, [obj], [], None, None),
                    ),
                    py_ast.Suite(
                        [py_ast.SetAttr(replacement, obj, _existing("inp"))]
                    ),
                    py_ast.Suite([]),
                ),
                py_ast.Assign(py_ast.GetAttr(obj, _existing("out")), [loaded]),
            ]
        ),
        params=(initial, replacement),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    assert heap.locations_for_local(code, initial)[0] in loaded_locations
    assert heap.locations_for_local(code, replacement)[0] in loaded_locations


def test_assert_message_evaluates_on_the_false_refined_state():
    from pyflow.analysis.alias.flow_sensitive.abstraction import HeapAbstraction
    from pyflow.analysis.alias.flow_sensitive.transfer import HeapTransferEngine

    cond = py_ast.Local("cond")
    value = py_ast.Local("value")
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    selected = py_ast.Local("selected")
    formal = py_ast.Local("formal")
    stored = py_ast.Local("stored")
    mutation = _code(
        "mutate",
        py_ast.Suite([py_ast.SetAttr(stored, formal, _existing("marked"))]),
        params=(formal, stored),
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(py_ast.BuildList([]), [x]),
                py_ast.Assign(py_ast.BuildList([]), [y]),
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), cond),
                    py_ast.Suite([py_ast.Assign(x, [selected])]),
                    py_ast.Suite([py_ast.Assign(y, [selected])]),
                ),
                py_ast.Assert(
                    py_ast.Is(selected, x),
                    py_ast.DirectCall(
                        mutation,
                        None,
                        [selected, value],
                        [],
                        None,
                        None,
                    ),
                ),
            ]
        ),
        params=(cond,),
    )

    heap = HeapAbstraction(lambda _procedure, _local: ())
    engine = HeapTransferEngine(heap)
    outcome = engine.analyze_node(code, code.ast)

    assert "raise" in outcome.abrupt
    x_location = heap.locations_for_local(code, x)[0]
    y_location = heap.locations_for_local(code, y)[0]
    value_location = heap.locations_for_local(code, value)[0]
    raised = outcome.abrupt["raise"].heap_state
    x_mark = heap.dynamic_attribute_location(x_location, "marked")
    y_mark = heap.dynamic_attribute_location(y_location, "marked")
    assert value_location not in raised.values.get(x_mark, ())
    assert value_location in raised.values.get(y_mark, ())


def test_for_loop_index_binds_to_iterator_elements():
    """After ``for x in lst: pass``, ``x`` should be bound to the
    element values stored in ``lst``."""
    lst = py_ast.Local("lst")
    value = py_ast.Local("value")
    index = py_ast.Local("index")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([value]), [lst]),
                py_ast.For(
                    iterator=lst,
                    index=index,
                    loopPreamble=py_ast.Suite([]),
                    bodyPreamble=py_ast.Suite([]),
                    body=py_ast.Suite([]),
                    else_=py_ast.Suite([]),
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(lst, _existing(0)),
                    [py_ast.Local("loaded")],
                ),
            ]
        ),
        params=(value,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    index_locations = heap.locations_for_local(code, index)
    value_location = heap.locations_for_local(code, value)[0]

    assert value_location in index_locations, (
        "For loop index should bind to iterator element values"
    )


def test_for_loop_index_aliases_container_elements():
    """After ``for x in [a, b]: pass``, ``x`` should be bound to
    all element values."""
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    lst = py_ast.Local("lst")
    index = py_ast.Local("index")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([a, b]), [lst]),
                py_ast.For(
                    iterator=lst,
                    index=index,
                    loopPreamble=py_ast.Suite([]),
                    bodyPreamble=py_ast.Suite([]),
                    body=py_ast.Suite([]),
                    else_=py_ast.Suite([]),
                ),
            ]
        ),
        params=(a, b),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    index_locations = heap.locations_for_local(code, index)
    a_location = heap.locations_for_local(code, a)[0]
    b_location = heap.locations_for_local(code, b)[0]

    assert a_location in index_locations
    assert b_location in index_locations


def test_type_switch_analyzes_case_body():
    """``match x: case _: body`` must analyze the case body for heap effects."""
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    case_body = py_ast.Suite(
        [py_ast.SetAttr(value, obj, _existing("field"))]
    )
    type_case = py_ast.TypeSwitchCase(
        types=[], expr=None, body=case_body
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.TypeSwitch(
                    conditional=obj,
                    cases=[type_case],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(obj, _existing("field")),
                    [loaded],
                ),
            ]
        ),
        params=(value,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    value_location = heap.locations_for_local(code, value)[0]

    assert value_location in loaded_locations, (
        "Value written in TypeSwitch case body should be readable afterward"
    )


def test_type_switch_joins_multiple_case_branches():
    """``match x: case A: ... case B: ...`` must join state from all branches."""
    obj = py_ast.Local("obj")
    val_a = py_ast.Local("val_a")
    val_b = py_ast.Local("val_b")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.TypeSwitch(
                    conditional=obj,
                    cases=[
                        py_ast.TypeSwitchCase(
                            types=[], expr=None,
                            body=py_ast.Suite(
                                [py_ast.SetAttr(val_a, obj, _existing("f"))]
                            ),
                        ),
                        py_ast.TypeSwitchCase(
                            types=[], expr=None,
                            body=py_ast.Suite(
                                [py_ast.SetAttr(val_b, obj, _existing("f"))]
                            ),
                        ),
                    ],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(obj, _existing("f")),
                    [loaded],
                ),
            ]
        ),
        params=(val_a, val_b),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    a_loc = heap.locations_for_local(code, val_a)[0]
    b_loc = heap.locations_for_local(code, val_b)[0]

    assert a_loc in loaded_locations
    assert b_loc in loaded_locations


def test_type_switch_binds_case_expr_to_conditional():
    """``match x: case int(y): ...`` should bind ``y`` to locations from ``x``."""
    obj = py_ast.Local("obj")
    case_var = py_ast.Local("case_var")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.TypeSwitch(
                    conditional=obj,
                    cases=[
                        py_ast.TypeSwitchCase(
                            types=[], expr=case_var,
                            body=py_ast.Suite([]),
                        ),
                    ],
                ),
                py_ast.Assign(obj, [loaded]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    case_var_locs = heap.locations_for_local(code, case_var)
    obj_loc = heap.locations_for_local(code, obj)[0]

    assert obj_loc in case_var_locs, (
        "Case variable should alias the matched expression"
    )


def test_try_handler_sees_body_mutations():
    """An exception handler should see heap mutations made in the try body
    before the exception was raised (e.g., container.append())."""
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    handler = py_ast.ExceptionHandler(
        preamble=py_ast.Suite([]),
        type=_existing("Exception"),
        value=None,
        body=py_ast.Suite(
            [
                py_ast.Assign(
                    py_ast.GetAttr(obj, _existing("field")),
                    [loaded],
                ),
            ]
        ),
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.TryExceptFinally(
                    body=py_ast.Suite(
                        [py_ast.SetAttr(value, obj, _existing("field"))]
                    ),
                    handlers=[handler],
                    defaultHandler=None,
                    else_=None,
                    finally_=None,
                ),
            ]
        ),
        params=(value,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    value_location = heap.locations_for_local(code, value)[0]

    assert value_location in loaded_locations, (
        "Handler should see field mutation from try body"
    )


def test_raise_stops_try_body_before_handler_state_is_captured():
    obj = py_ast.Local("obj")
    before_raise = py_ast.Local("before_raise")
    after_raise = py_ast.Local("after_raise")
    loaded = py_ast.Local("loaded")
    handler = py_ast.ExceptionHandler(
        preamble=py_ast.Suite([]),
        type=_existing("Exception"),
        value=None,
        body=py_ast.Suite(
            [py_ast.Assign(py_ast.GetAttr(obj, _existing("field")), [loaded])]
        ),
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.TryExceptFinally(
                    body=py_ast.Suite(
                        [
                            py_ast.SetAttr(before_raise, obj, _existing("field")),
                            py_ast.Raise(_existing("boom"), None, None),
                            py_ast.SetAttr(after_raise, obj, _existing("field")),
                        ]
                    ),
                    handlers=[handler],
                    defaultHandler=None,
                    else_=None,
                    finally_=None,
                ),
            ]
        ),
        params=(before_raise, after_raise),
    )

    analysis = HeapAnalysis(policy=HeapPolicy.precise())
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    assert heap.locations_for_local(code, before_raise)[0] in loaded_locations
    assert heap.locations_for_local(code, after_raise)[0] not in loaded_locations


def test_exception_handler_joins_all_try_prefixes():
    obj = py_ast.Local("obj")
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    loaded = py_ast.Local("loaded")
    handler = py_ast.ExceptionHandler(
        preamble=py_ast.Suite([]),
        type=_existing("Exception"),
        value=None,
        body=py_ast.Suite(
            [py_ast.Assign(py_ast.GetAttr(obj, _existing("field")), [loaded])]
        ),
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.TryExceptFinally(
                    body=py_ast.Suite(
                        [
                            py_ast.SetAttr(first, obj, _existing("field")),
                            py_ast.SetAttr(second, obj, _existing("field")),
                        ]
                    ),
                    handlers=[handler],
                    defaultHandler=None,
                    else_=None,
                    finally_=None,
                ),
            ]
        ),
        params=(first, second),
    )

    analysis = HeapAnalysis(policy=HeapPolicy.precise())
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    assert heap.locations_for_local(code, first)[0] in loaded_locations
    assert heap.locations_for_local(code, second)[0] in loaded_locations


def test_return_stops_suite_execution():
    returned = py_ast.Local("returned")
    unreachable = py_ast.Local("unreachable")
    ret = py_ast.Local("ret")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [returned]),
                py_ast.Return([returned]),
                py_ast.Assign(py_ast.BuildList([]), [unreachable]),
            ]
        ),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, returned)
    assert heap.locations_for_local(code, ret)
    assert not heap.locations_for_local(code, unreachable)


def test_break_stops_suite_execution():
    """``break`` must skip subsequent blocks in the same Suite."""
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [a]),
                py_ast.Break(),
                py_ast.Assign(py_ast.BuildList([]), [b]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    a_locs = heap.locations_for_local(code, a)
    assert len(a_locs) >= 1, "Assignment before break should be visible"

    b_locs = heap.locations_for_local(code, b)
    assert len(b_locs) == 0, (
        "Assignment after break should not be applied"
    )


def test_continue_stops_suite_execution():
    """``continue`` must skip subsequent blocks in the same Suite."""
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [a]),
                py_ast.Continue(),
                py_ast.Assign(py_ast.BuildList([]), [b]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    a_locs = heap.locations_for_local(code, a)
    assert len(a_locs) >= 1, "Assignment before continue should be visible"

    b_locs = heap.locations_for_local(code, b)
    assert len(b_locs) == 0, (
        "Assignment after continue should not be applied"
    )
