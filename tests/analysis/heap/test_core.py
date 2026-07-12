"""Tests for core alias, escape, direct call, field access, and imports."""

from __future__ import annotations

from pyflow.analysis.heap import (
    HeapAnalysis,
    HeapIntrinsicModels,
    HeapObjectKind,
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


def test_applies_standalone_transfers_for_alias_escape_and_return():
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    value = py_ast.Local("value")
    ret = py_ast.Local("ret0")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [x]),
                py_ast.Assign(x, [y]),
                py_ast.Discard(
                    py_ast.MethodCall(
                        y, _existing("append"), [value], [], None, None
                    )
                ),
                py_ast.Return([x]),
            ]
        ),
        params=(value,),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    x_location = heap.locations_for_local(code, x)[0]
    y_location = heap.locations_for_local(code, y)[0]
    value_location = heap.locations_for_local(code, value)[0]
    ret_location = heap.locations_for_local(code, ret)[0]

    assert graph.aliased(x_location, y_location)
    assert graph.is_escaped(x_location)
    assert graph.is_escaped(value_location)
    assert graph.aliased(ret_location, x_location)


def test_instantiates_direct_call_formals_and_returns():
    arg = py_ast.Local("arg")
    formal = py_ast.Local("formal")
    callee_ret = py_ast.Local("callee_ret")
    result = py_ast.Local("result")
    callee = _code(
        "identity",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(callee_ret,),
    )
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [arg]),
                py_ast.Assign(
                    py_ast.DirectCall(callee, None, [arg], [], None, None),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    arg_location = heap.locations_for_local(caller, arg)[0]
    result_location = heap.locations_for_local(caller, result)[0]
    formal_location = heap.locations_for_local(callee, formal)[0]
    return_location = heap.locations_for_local(callee, callee_ret)[0]

    assert graph.aliased(arg_location, formal_location)
    assert graph.aliased(result_location, arg_location)
    assert graph.aliased(return_location, arg_location)


def test_rebound_callee_formal_is_not_treated_as_param_return_or_escape():
    actual = py_ast.Local("actual")
    formal = py_ast.Local("formal")
    callee_ret = py_ast.Local("callee_ret")
    result = py_ast.Local("result")
    caller_ret = py_ast.Local("caller_ret")
    callee = _code(
        "rebind_formal",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [formal]),
                py_ast.Return([formal]),
            ]
        ),
        params=(formal,),
        returns=(callee_ret,),
    )
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildMap([]), [actual]),
                py_ast.Assign(
                    py_ast.DirectCall(callee, None, [actual], [], None, None),
                    [result],
                ),
                py_ast.Return([result]),
            ]
        ),
        returns=(caller_ret,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    actual_location = heap.locations_for_local(caller, actual)[0]
    result_location = heap.locations_for_local(caller, result)[0]
    formal_location = heap.locations_for_local(callee, formal)[0]
    return_location = heap.locations_for_local(callee, callee_ret)[0]

    assert not graph.is_escaped(actual_location)
    assert graph.is_escaped(result_location)
    assert not graph.aliased(result_location, actual_location)
    assert graph.aliased(result_location, formal_location)
    assert graph.aliased(return_location, formal_location)


def test_summary_cache_key_distinguishes_actual_selectors():
    obj = py_ast.Local("obj")
    formal = py_ast.Local("formal")
    callee_ret = py_ast.Local("callee_ret")
    result_a = py_ast.Local("result_a")
    result_b = py_ast.Local("result_b")
    callee = _code(
        "identity",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(callee_ret,),
    )
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        callee,
                        None,
                        [py_ast.GetAttr(obj, _existing("a"))],
                        [],
                        None,
                        None,
                    ),
                    [result_a],
                ),
                py_ast.Assign(
                    py_ast.DirectCall(
                        callee,
                        None,
                        [py_ast.GetAttr(obj, _existing("b"))],
                        [],
                        None,
                        None,
                    ),
                    [result_b],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    result_a_location = heap.locations_for_local(caller, result_a)[0]
    result_b_location = heap.locations_for_local(caller, result_b)[0]

    assert not graph.may_alias(result_a_location, result_b_location)


def test_replays_cached_direct_call_summary_side_effects():
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    formal_obj = py_ast.Local("formal_obj")
    formal_value = py_ast.Local("formal_value")
    loaded = py_ast.Local("loaded")
    callee = _code(
        "store_payload",
        py_ast.Suite(
            [py_ast.SetAttr(formal_value, formal_obj, _existing("payload"))]
        ),
        params=(formal_obj, formal_value),
    )
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Discard(
                    py_ast.DirectCall(callee, None, [obj, value], [], None, None)
                ),
                py_ast.DeleteAttr(obj, _existing("payload")),
                py_ast.Discard(
                    py_ast.DirectCall(callee, None, [obj, value], [], None, None)
                ),
                py_ast.Assign(py_ast.GetAttr(obj, _existing("payload")), [loaded]),
            ]
        ),
        params=(value,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    loaded_location = heap.locations_for_local(caller, loaded)[0]
    value_location = heap.locations_for_local(caller, value)[0]

    assert graph.aliased(loaded_location, value_location)


def test_replays_cached_direct_call_summary_deletes():
    obj = py_ast.Local("obj")
    first_value = py_ast.Local("first_value")
    second_value = py_ast.Local("second_value")
    formal_obj = py_ast.Local("formal_obj")
    loaded = py_ast.Local("loaded")
    callee = _code(
        "delete_payload",
        py_ast.Suite([py_ast.DeleteAttr(formal_obj, _existing("payload"))]),
        params=(formal_obj,),
    )
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.SetAttr(first_value, obj, _existing("payload")),
                py_ast.Discard(
                    py_ast.DirectCall(callee, None, [obj], [], None, None)
                ),
                py_ast.SetAttr(second_value, obj, _existing("payload")),
                py_ast.Discard(
                    py_ast.DirectCall(callee, None, [obj], [], None, None)
                ),
                py_ast.Assign(py_ast.GetAttr(obj, _existing("payload")), [loaded]),
            ]
        ),
        params=(first_value, second_value),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(caller, loaded)
    first_value_location = heap.locations_for_local(caller, first_value)[0]
    second_value_location = heap.locations_for_local(caller, second_value)[0]

    assert first_value_location not in loaded_locations
    assert second_value_location not in loaded_locations
    assert not any(
        graph.may_alias(location, second_value_location)
        for location in loaded_locations
    )


def test_binds_assigned_import_to_module_object():
    module = py_ast.Local("json_module")
    code = _code(
        "main",
        py_ast.Suite([py_ast.Assign(py_ast.Import("json", [], 0), [module])]),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    module_location = heap.locations_for_local(code, module)[0]

    assert module_location.root.kind is HeapObjectKind.GLOBAL
    assert module_location.root.type_hint == "module"
    assert graph.get(module_location) is not None


def test_tracks_instance_field_store_and_load_values():
    self_local = py_ast.Local("self")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    ret = py_ast.Local("ret0")
    code = _code(
        "method",
        py_ast.Suite(
            [
                py_ast.SetAttr(value, self_local, _existing("payload")),
                py_ast.Assign(
                    py_ast.GetAttr(self_local, _existing("payload")),
                    [loaded],
                ),
                py_ast.Return([loaded]),
            ]
        ),
        params=(self_local, value),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    value_location = heap.locations_for_local(code, value)[0]
    loaded_location = heap.locations_for_local(code, loaded)[0]
    return_location = heap.locations_for_local(code, ret)[0]

    assert graph.aliased(loaded_location, value_location)
    assert graph.aliased(return_location, value_location)


def test_keeps_distinct_instance_fields_separate():
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    va = py_ast.Local("va")
    vb = py_ast.Local("vb")
    loaded_a = py_ast.Local("loaded_a")
    loaded_b = py_ast.Local("loaded_b")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [a]),
                py_ast.Assign(py_ast.BuildList([]), [b]),
                py_ast.SetAttr(va, a, _existing("payload")),
                py_ast.SetAttr(vb, b, _existing("payload")),
                py_ast.Assign(py_ast.GetAttr(a, _existing("payload")), [loaded_a]),
                py_ast.Assign(py_ast.GetAttr(b, _existing("payload")), [loaded_b]),
            ]
        ),
        params=(va, vb),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    a_field = heap.dynamic_attribute_location(
        heap.locations_for_local(code, a)[0],
        "payload",
    )
    b_field = heap.dynamic_attribute_location(
        heap.locations_for_local(code, b)[0],
        "payload",
    )
    loaded_a_location = heap.locations_for_local(code, loaded_a)[0]
    loaded_b_location = heap.locations_for_local(code, loaded_b)[0]

    assert not graph.may_alias_path(a_field, b_field)
    assert not graph.may_alias(loaded_a_location, loaded_b_location)


def test_recursive_direct_call_terminates_conservatively():
    x = py_ast.Local("x")
    recursive_result = py_ast.Local("recursive_result")
    ret = py_ast.Local("ret0")
    recursive = _code("recursive", py_ast.Suite([]), params=(x,), returns=(ret,))
    recursive.ast = py_ast.Suite(
        [
            py_ast.Assign(
                py_ast.DirectCall(recursive, None, [x], [], None, None),
                [recursive_result],
            ),
            py_ast.Return([recursive_result]),
        ]
    )
    caller_arg = py_ast.Local("caller_arg")
    caller_result = py_ast.Local("caller_result")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [caller_arg]),
                py_ast.Assign(
                    py_ast.DirectCall(recursive, None, [caller_arg], [], None, None),
                    [caller_result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    result_location = heap.locations_for_local(caller, caller_result)[0]

    assert result_location.root.kind.value == "return"
    assert graph.get(result_location) is not None


def test_param_return_preserves_alias_through_direct_call():
    formal = py_ast.Local("formal")
    callee_ret = py_ast.Local("callee_ret")
    result = py_ast.Local("result")
    arg = py_ast.Local("arg")
    callee = _code(
        "identity",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(callee_ret,),
    )
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [arg]),
                py_ast.Assign(
                    py_ast.DirectCall(callee, None, [arg], [], None, None),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    arg_location = heap.locations_for_local(caller, arg)[0]
    result_location = heap.locations_for_local(caller, result)[0]
    assert graph.aliased(result_location, arg_location), (
        "Call result from identity function should alias the argument"
    )


def test_param_escape_tracked_through_direct_call():
    formal = py_ast.Local("formal")
    callee_ret = py_ast.Local("callee_ret")
    arg = py_ast.Local("arg")
    callee = _code(
        "store_global",
        py_ast.Suite(
            [
                py_ast.SetAttr(
                    formal,
                    py_ast.GetGlobal(_existing("payload")),
                    _existing("x"),
                ),
                py_ast.Return([formal]),
            ]
        ),
        params=(formal,),
        returns=(callee_ret,),
    )
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [arg]),
                py_ast.Assign(
                    py_ast.DirectCall(callee, None, [arg], [], None, None),
                    [py_ast.Local("result")],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    arg_location = heap.locations_for_local(caller, arg)[0]
    assert graph.is_escaped(arg_location), (
        "Argument should be escaped after callee stores it in a global"
    )
