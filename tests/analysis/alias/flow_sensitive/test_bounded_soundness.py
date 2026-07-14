"""Adversarial soundness tests for bounded, resolved-call programs."""

from __future__ import annotations

from copy import copy

from pyflow.analysis.alias.flow_sensitive import HeapAnalysis
from pyflow.analysis.alias.flow_sensitive.heap_effects import HeapEffectBuilder
from pyflow.analysis.alias.flow_sensitive.model import HeapLocation
from pyflow.analysis.ir_utils import register_code_definition_metadata
from pyflow.language.python import ast as py_ast


def _existing(value):
    return py_ast.Existing(py_ast.program.Object(value))


def _code(
    name: str,
    body: py_ast.Suite,
    *,
    params=(),
    returns=(),
    vparam=None,
    kparam=None,
):
    return py_ast.Code(
        name,
        py_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=list(params),
            paramnames=[param.name for param in params],
            defaults=[],
            vparam=vparam,
            kparam=kparam,
            returnparams=list(returns),
            type_params=None,
        ),
        body,
    )


def test_resolved_call_reads_call_site_heap_and_recomputes_after_write():
    formal = py_ast.Local("formal")
    ret = py_ast.Local("ret")
    callee = _code(
        "read_payload",
        py_ast.Suite([py_ast.Return([py_ast.GetAttr(formal, _existing("x"))])]),
        params=(formal,),
        returns=(ret,),
    )
    obj = py_ast.Local("obj")
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    first_call = py_ast.DirectCall(callee, None, [obj], [], None, None)
    second_call = py_ast.DirectCall(callee, None, [obj], [], None, None)
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [left]),
                py_ast.Assign(py_ast.BuildList([]), [right]),
                py_ast.SetAttr(left, obj, _existing("x")),
                py_ast.Assign(first_call, [first]),
                py_ast.SetAttr(right, obj, _existing("x")),
                py_ast.Assign(second_call, [second]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    assert graph.aliased(
        heap.locations_for_local(caller, first)[0],
        heap.locations_for_local(caller, left)[0],
    )
    assert graph.aliased(
        heap.locations_for_local(caller, second)[0],
        heap.locations_for_local(caller, right)[0],
    )


def test_uncertain_reorder_and_dynamic_delete_preserve_may_values():
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    sequence = py_ast.Local("sequence")
    key = py_ast.Local("key")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([left, right]), [sequence]),
                py_ast.Discard(
                    py_ast.MethodCall(
                        sequence,
                        _existing("reverse"),
                        [],
                        [],
                        None,
                        None,
                    )
                ),
                py_ast.DeleteSubscript(sequence, key),
                py_ast.Assign(py_ast.GetSubscript(sequence, _existing(0)), [loaded]),
            ]
        ),
        params=(left, right, key),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    loaded_locations = heap.locations_for_local(code, loaded)
    assert heap.locations_for_local(code, left)[0] in loaded_locations
    assert heap.locations_for_local(code, right)[0] in loaded_locations


def test_known_intrinsic_return_models_bind_values_and_none_clears():
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    selected = py_ast.Local("selected")
    cleared = py_ast.Local("cleared")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [left]),
                py_ast.Assign(py_ast.BuildList([]), [right]),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("max"), [left, right], [], None, None),
                    [selected],
                ),
                py_ast.Assign(left, [cleared]),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("print"), [], [], None, None),
                    [cleared],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    selected_locations = heap.locations_for_local(code, selected)
    assert heap.locations_for_local(code, left)[0] in selected_locations
    assert heap.locations_for_local(code, right)[0] in selected_locations
    assert not heap.locations_for_local(code, cleared)


def test_getattr_next_and_sorted_return_stored_values():
    value = py_ast.Local("value")
    obj = py_ast.Local("obj")
    source = py_ast.Local("source")
    attr = py_ast.Local("attr")
    next_value = py_ast.Local("next_value")
    copied = py_ast.Local("copied")
    copied_value = py_ast.Local("copied_value")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(py_ast.BuildMap([]), [obj]),
                py_ast.SetAttr(value, obj, _existing("payload")),
                py_ast.Assign(py_ast.BuildList([value]), [source]),
                py_ast.Assign(
                    py_ast.Call(
                        py_ast.Local("getattr"),
                        [obj, _existing("payload")],
                        [],
                        None,
                        None,
                    ),
                    [attr],
                ),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("next"), [source], [], None, None),
                    [next_value],
                ),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("sorted"), [source], [], None, None),
                    [copied],
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(copied, _existing(0)),
                    [copied_value],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    value_location = heap.locations_for_local(code, value)[0]
    assert graph.aliased(heap.locations_for_local(code, attr)[0], value_location)
    assert graph.aliased(
        heap.locations_for_local(code, next_value)[0], value_location
    )
    assert graph.aliased(
        heap.locations_for_local(code, copied_value)[0], value_location
    )


def test_packed_varargs_and_kwargs_are_indexable_containers():
    varargs = py_ast.Local("args")
    kwargs = py_ast.Local("kwargs")
    var_ret = py_ast.Local("var_ret")
    kw_ret = py_ast.Local("kw_ret")
    var_callee = _code(
        "first_arg",
        py_ast.Suite([py_ast.Return([py_ast.GetSubscript(varargs, _existing(0))])]),
        returns=(var_ret,),
        vparam=varargs,
    )
    kw_callee = _code(
        "named_arg",
        py_ast.Suite(
            [py_ast.Return([py_ast.GetSubscript(kwargs, _existing("named"))])]
        ),
        returns=(kw_ret,),
        kparam=kwargs,
    )
    actual = py_ast.Local("actual")
    var_result = py_ast.Local("var_result")
    kw_result = py_ast.Local("kw_result")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [actual]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        var_callee, None, [actual], [], None, None
                    ),
                    [var_result],
                ),
                py_ast.Assign(
                    py_ast.DirectCall(
                        kw_callee,
                        None,
                        [],
                        [("named", actual)],
                        None,
                        None,
                    ),
                    [kw_result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None
    actual_location = heap.locations_for_local(caller, actual)[0]
    assert graph.aliased(
        heap.locations_for_local(caller, var_result)[0], actual_location
    )
    assert graph.aliased(
        heap.locations_for_local(caller, kw_result)[0], actual_location
    )


def test_spread_arguments_bind_regular_formals_conservatively():
    formal = py_ast.Local("named")
    ret = py_ast.Local("ret")
    callee = _code(
        "identity",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(ret,),
    )
    actual = py_ast.Local("actual")
    positional_spread = py_ast.Local("positional_spread")
    keyword_spread = py_ast.Local("keyword_spread")
    positional_result = py_ast.Local("positional_result")
    keyword_result = py_ast.Local("keyword_result")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [actual]),
                py_ast.Assign(py_ast.BuildList([actual]), [positional_spread]),
                py_ast.Assign(
                    py_ast.BuildMap([_existing("named"), actual]),
                    [keyword_spread],
                ),
                py_ast.Assign(
                    py_ast.DirectCall(
                        callee,
                        None,
                        [],
                        [],
                        positional_spread,
                        None,
                    ),
                    [positional_result],
                ),
                py_ast.Assign(
                    py_ast.DirectCall(
                        callee,
                        None,
                        [],
                        [],
                        None,
                        keyword_spread,
                    ),
                    [keyword_result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None
    actual_location = heap.locations_for_local(caller, actual)[0]
    assert actual_location in heap.locations_for_local(caller, positional_result)
    assert actual_location in heap.locations_for_local(caller, keyword_result)


def test_repeated_callee_allocation_site_is_not_must_alias():
    allocated = py_ast.Local("allocated")
    ret = py_ast.Local("ret")
    callee = _code(
        "make",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [allocated]),
                py_ast.Return([allocated]),
            ]
        ),
        returns=(ret,),
    )
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(
                    py_ast.DirectCall(callee, None, [], [], None, None),
                    [first],
                ),
                py_ast.Assign(
                    py_ast.DirectCall(callee, None, [], [], None, None),
                    [second],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None
    assert not graph.aliased(
        heap.locations_for_local(caller, first)[0],
        heap.locations_for_local(caller, second)[0],
    )


def test_returned_singleton_still_receives_strong_field_updates():
    allocated = py_ast.Local("allocated")
    ret = py_ast.Local("ret")
    callee = _code(
        "make",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [allocated]),
                py_ast.Return([allocated]),
            ]
        ),
        returns=(ret,),
    )
    obj = py_ast.Local("obj")
    old = py_ast.Local("old")
    new = py_ast.Local("new")
    loaded = py_ast.Local("loaded")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(
                    py_ast.DirectCall(callee, None, [], [], None, None),
                    [obj],
                ),
                py_ast.Assign(py_ast.BuildList([]), [old]),
                py_ast.Assign(py_ast.BuildList([]), [new]),
                py_ast.SetAttr(old, obj, _existing("field")),
                py_ast.SetAttr(new, obj, _existing("field")),
                py_ast.Assign(py_ast.GetAttr(obj, _existing("field")), [loaded]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None
    loaded_locations = heap.locations_for_local(caller, loaded)
    assert heap.locations_for_local(caller, new)[0] in loaded_locations
    assert heap.locations_for_local(caller, old)[0] not in loaded_locations


def test_subscript_evaluation_captures_base_before_key_side_effect():
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    selected = py_ast.Local("selected")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildMap([]), [first]),
                py_ast.Assign(py_ast.BuildMap([]), [second]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.SetSubscript(value, first, _existing("key")),
                py_ast.Assign(first, [selected]),
                py_ast.Assign(
                    py_ast.GetSubscript(
                        selected,
                        py_ast.NamedExpr(selected, second),
                    ),
                    [loaded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert heap.locations_for_local(code, value)[0] in heap.locations_for_local(
        code, loaded
    )
    assert heap.locations_for_local(code, selected) == heap.locations_for_local(
        code, second
    )


def test_write_through_branch_join_weakly_updates_each_possible_root():
    condition = py_ast.Local("condition")
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    selected = py_ast.Local("selected")
    left_old = py_ast.Local("left_old")
    right_old = py_ast.Local("right_old")
    new = py_ast.Local("new")
    left_loaded = py_ast.Local("left_loaded")
    right_loaded = py_ast.Local("right_loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [left]),
                py_ast.Assign(py_ast.BuildList([]), [right]),
                py_ast.Assign(py_ast.BuildList([]), [left_old]),
                py_ast.Assign(py_ast.BuildList([]), [right_old]),
                py_ast.Assign(py_ast.BuildList([]), [new]),
                py_ast.SetAttr(left_old, left, _existing("field")),
                py_ast.SetAttr(right_old, right, _existing("field")),
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), condition),
                    py_ast.Suite([py_ast.Assign(left, [selected])]),
                    py_ast.Suite([py_ast.Assign(right, [selected])]),
                ),
                py_ast.SetAttr(new, selected, _existing("field")),
                py_ast.Assign(
                    py_ast.GetAttr(left, _existing("field")),
                    [left_loaded],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(right, _existing("field")),
                    [right_loaded],
                ),
            ]
        ),
        params=(condition,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert heap.locations_for_local(code, left_old)[0] in heap.locations_for_local(
        code,
        left_loaded,
    )
    assert heap.locations_for_local(code, right_old)[0] in heap.locations_for_local(
        code,
        right_loaded,
    )
    assert heap.locations_for_local(code, new)[0] in heap.locations_for_local(
        code,
        left_loaded,
    )
    assert heap.locations_for_local(code, new)[0] in heap.locations_for_local(
        code,
        right_loaded,
    )


def test_assigned_yield_evaluates_and_escapes_yielded_value():
    value = py_ast.Local("value")
    resumed = py_ast.Local("resumed")
    code = _code(
        "generator",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(py_ast.Yield(value), [resumed]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.is_escaped(heap.locations_for_local(code, value)[0])


def test_generator_direct_call_is_lazy_until_next():
    formal = py_ast.Local("formal")
    generator = _code(
        "generator",
        py_ast.Suite([py_ast.Discard(py_ast.Yield(formal))]),
        params=(formal,),
    )
    generator.annotation = copy(generator.annotation)
    generator.annotation.origin = ["converted_generator"]
    value = py_ast.Local("value")
    iterator = py_ast.Local("iterator")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.DirectCall(generator, None, [value], [], None, None),
                    [iterator],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert not graph.is_escaped(heap.locations_for_local(code, value)[0])


def test_next_resumes_generator_and_returns_yielded_value():
    formal = py_ast.Local("formal")
    generator = _code(
        "generator",
        py_ast.Suite([py_ast.Discard(py_ast.Yield(formal))]),
        params=(formal,),
    )
    generator.annotation = copy(generator.annotation)
    generator.annotation.origin = ["converted_generator"]
    value = py_ast.Local("value")
    iterator = py_ast.Local("iterator")
    yielded = py_ast.Local("yielded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.DirectCall(generator, None, [value], [], None, None),
                    [iterator],
                ),
                py_ast.Assign(
                    py_ast.Call(
                        py_ast.Local("next"),
                        [iterator],
                        [],
                        None,
                        None,
                    ),
                    [yielded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.aliased(
        heap.locations_for_local(code, yielded)[0],
        heap.locations_for_local(code, value)[0],
    )


def test_generator_resume_stops_at_the_current_yield_boundary():
    obj_formal = py_ast.Local("obj_formal")
    first_formal = py_ast.Local("first_formal")
    second_formal = py_ast.Local("second_formal")
    generator = _code(
        "generator",
        py_ast.Suite(
            [
                py_ast.SetAttr(first_formal, obj_formal, _existing("field")),
                py_ast.Discard(py_ast.Yield(first_formal)),
                py_ast.SetAttr(second_formal, obj_formal, _existing("field")),
            ]
        ),
        params=(obj_formal, first_formal, second_formal),
    )
    generator.annotation = copy(generator.annotation)
    generator.annotation.origin = ["converted_generator"]
    obj = py_ast.Local("obj")
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    iterator = py_ast.Local("iterator")
    yielded = py_ast.Local("yielded")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [first]),
                py_ast.Assign(py_ast.BuildList([]), [second]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        generator,
                        None,
                        [obj, first, second],
                        [],
                        None,
                        None,
                    ),
                    [iterator],
                ),
                py_ast.Assign(
                    py_ast.Call(
                        py_ast.Local("next"),
                        [iterator],
                        [],
                        None,
                        None,
                    ),
                    [yielded],
                ),
                py_ast.Assign(py_ast.GetAttr(obj, _existing("field")), [loaded]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    loaded_locations = heap.locations_for_local(code, loaded)
    assert heap.locations_for_local(code, first)[0] in loaded_locations
    assert heap.locations_for_local(code, second)[0] not in loaded_locations


def test_await_resumes_coroutine_and_returns_resolved_value():
    formal = py_ast.Local("formal")
    ret = py_ast.Local("ret")
    coroutine = _code(
        "coroutine",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(ret,),
    )
    coroutine.annotation = copy(coroutine.annotation)
    coroutine.annotation.origin = ["converted_async_function"]
    value = py_ast.Local("value")
    awaitable = py_ast.Local("awaitable")
    resolved = py_ast.Local("resolved")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.DirectCall(coroutine, None, [value], [], None, None),
                    [awaitable],
                ),
                py_ast.Assign(py_ast.Await(awaitable), [resolved]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert heap.locations_for_local(code, value)[0] in heap.locations_for_local(
        code,
        resolved,
    )


def test_resolved_call_propagates_explicit_exception_value_to_handler():
    formal = py_ast.Local("formal")
    callee = _code(
        "raise_it",
        py_ast.Suite([py_ast.Raise(formal, None, None)]),
        params=(formal,),
    )
    exception = py_ast.Local("exception")
    caught = py_ast.Local("caught")
    captured = py_ast.Local("captured")
    handler = py_ast.ExceptionHandler(
        preamble=py_ast.Suite([]),
        type=_existing("Exception"),
        value=caught,
        body=py_ast.Suite([py_ast.Assign(caught, [captured])]),
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [exception]),
                py_ast.TryExceptFinally(
                    body=py_ast.Suite(
                        [
                            py_ast.Discard(
                                py_ast.DirectCall(
                                    callee,
                                    None,
                                    [exception],
                                    [],
                                    None,
                                    None,
                                )
                            )
                        ]
                    ),
                    handlers=[handler],
                    defaultHandler=None,
                    else_=None,
                    finally_=None,
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert heap.locations_for_local(code, exception)[0] in heap.locations_for_local(
        code,
        captured,
    )
    assert not heap.locations_for_local(code, caught)


def test_mapping_keys_escape_and_cells_with_same_name_remain_distinct():
    key = py_ast.Local("key")
    value = py_ast.Local("value")
    mapping = py_ast.Local("mapping")
    ret = py_ast.Local("ret")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [key]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(py_ast.BuildMap([key, value]), [mapping]),
                py_ast.Return([mapping]),
            ]
        ),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.is_escaped(heap.locations_for_local(code, key)[0])

    first_cell = py_ast.Cell("same")
    second_cell = py_ast.Cell("same")
    builder = HeapEffectBuilder(heap, heap.locations_for_local)
    assert builder.cell_location(first_cell) != builder.cell_location(second_cell)


def test_global_and_nonlocal_declarations_redirect_local_assignments():
    global_name = py_ast.Local("global_name")
    nonlocal_name = py_ast.Local("nonlocal_name")
    global_value = py_ast.Local("global_value")
    nonlocal_value = py_ast.Local("nonlocal_value")
    global_loaded = py_ast.Local("global_loaded")
    nonlocal_loaded = py_ast.Local("nonlocal_loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [global_value]),
                py_ast.Assign(py_ast.BuildList([]), [nonlocal_value]),
                py_ast.GlobalDecl(global_name),
                py_ast.Assign(global_value, [global_name]),
                py_ast.NonlocalDecl(nonlocal_name),
                py_ast.Assign(nonlocal_value, [nonlocal_name]),
                py_ast.Assign(
                    py_ast.GetGlobal(_existing("global_name")),
                    [global_loaded],
                ),
                py_ast.Assign(nonlocal_name, [nonlocal_loaded]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.aliased(
        heap.locations_for_local(code, global_loaded)[0],
        heap.locations_for_local(code, global_value)[0],
    )
    assert graph.aliased(
        heap.locations_for_local(code, nonlocal_loaded)[0],
        heap.locations_for_local(code, nonlocal_value)[0],
    )


def test_resolved_call_evaluates_argument_before_rebinding_same_target():
    formal = py_ast.Local("formal")
    ret = py_ast.Local("ret")
    identity = _code(
        "identity",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(ret,),
    )
    value = py_ast.Local("value")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.DirectCall(identity, None, [value], [], None, None),
                    [value],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    value_location = heap.locations_for_local(code, value)[0]
    assert graph.aliased(value_location, value_location)
    assert value_location.root.kind.value == "allocation"


def test_known_call_evaluates_operands_and_delete_clears_binding():
    value = py_ast.Local("value")
    argument = py_ast.Local("argument")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.Call(
                        py_ast.Local("print"),
                        [py_ast.NamedExpr(argument, value)],
                        [],
                        None,
                        None,
                    ),
                    [result],
                ),
                py_ast.Delete(argument),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert not heap.locations_for_local(code, argument)
    assert not heap.locations_for_local(code, result)


def test_mutator_effect_precedes_rebinding_receiver_to_none():
    container = py_ast.Local("container")
    alias = py_ast.Local("alias")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [container]),
                py_ast.Assign(container, [alias]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.MethodCall(
                        container,
                        _existing("append"),
                        [value],
                        [],
                        None,
                        None,
                    ),
                    [container],
                ),
                py_ast.Assign(py_ast.GetSubscript(alias, _existing(0)), [loaded]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    # A name-only ``append`` method may be user-defined and return an object;
    # retaining an opaque result is the sound receiver-type-insensitive model.
    assert heap.locations_for_local(code, container)
    assert heap.locations_for_local(code, value)[0] in heap.locations_for_local(
        code,
        loaded,
    )


def test_annotated_assignment_evaluates_annotation_after_value_assignment():
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    target = py_ast.Local("target")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [left]),
                py_ast.Assign(py_ast.BuildList([]), [right]),
                py_ast.AnnAssign(
                    target,
                    py_ast.NamedExpr(target, right),
                    left,
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.aliased(
        heap.locations_for_local(code, target)[0],
        heap.locations_for_local(code, right)[0],
    )


def test_assert_message_side_effect_is_absent_from_normal_successor():
    condition = py_ast.Local("condition")
    normal_obj = py_ast.Local("normal_obj")
    raised_obj = py_ast.Local("raised_obj")
    selected = py_ast.Local("selected")
    value = py_ast.Local("value")
    normal_loaded = py_ast.Local("normal_loaded")
    raised_loaded = py_ast.Local("raised_loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [normal_obj]),
                py_ast.Assign(py_ast.BuildList([]), [raised_obj]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(normal_obj, [selected]),
                py_ast.Assert(
                    condition,
                    py_ast.NamedExpr(selected, raised_obj),
                ),
                py_ast.SetAttr(value, selected, _existing("field")),
                py_ast.Assign(
                    py_ast.GetAttr(normal_obj, _existing("field")),
                    [normal_loaded],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(raised_obj, _existing("field")),
                    [raised_loaded],
                ),
            ]
        ),
        params=(condition,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert heap.locations_for_local(code, value)[0] in heap.locations_for_local(
        code,
        normal_loaded,
    )
    assert not heap.locations_for_local(code, raised_loaded)


def test_negative_index_and_pop_reindex_preserve_sequence_values():
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    sequence = py_ast.Local("sequence")
    negative = py_ast.Local("negative")
    shifted = py_ast.Local("shifted")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [first]),
                py_ast.Assign(py_ast.BuildList([]), [second]),
                py_ast.Assign(py_ast.BuildList([first, second]), [sequence]),
                py_ast.Assign(
                    py_ast.GetSubscript(sequence, _existing(-1)),
                    [negative],
                ),
                py_ast.Discard(
                    py_ast.MethodCall(
                        sequence,
                        _existing("pop"),
                        [_existing(0)],
                        [],
                        None,
                        None,
                    )
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(sequence, _existing(0)),
                    [shifted],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    second_location = heap.locations_for_local(code, second)[0]
    assert second_location in heap.locations_for_local(code, negative)
    assert second_location in heap.locations_for_local(code, shifted)


def test_keyword_only_direct_call_binds_the_named_actual():
    formal = py_ast.Local("formal")
    ret = py_ast.Local("ret")
    callee = py_ast.Code(
        "callee",
        py_ast.CodeParameters(
            None,
            [],
            [],
            [formal],
            ["kwonly:formal"],
            [],
            None,
            None,
            [ret],
            None,
        ),
        py_ast.Suite([py_ast.Return([formal])]),
    )
    actual = py_ast.Local("actual")
    result = py_ast.Local("result")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [actual]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        callee,
                        None,
                        [],
                        [("formal", actual)],
                        None,
                        None,
                    ),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None
    assert graph.aliased(
        heap.locations_for_local(caller, actual)[0],
        heap.locations_for_local(caller, result)[0],
    )


def test_values_stored_in_external_objects_escape_transitively():
    module = py_ast.Local("module")
    value = py_ast.Local("value")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.Import("pkg", [], 0), [module]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.SetAttr(value, module, _existing("payload")),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.is_escaped(heap.locations_for_local(code, value)[0])


def test_shared_known_call_results_are_not_modeled_as_fresh():
    value = py_ast.Local("value")
    first_type = py_ast.Local("first_type")
    second_type = py_ast.Local("second_type")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("type"), [value], [], None, None),
                    [first_type],
                ),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("type"), [value], [], None, None),
                    [second_type],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.aliased(
        heap.locations_for_local(code, first_type)[0],
        heap.locations_for_local(code, second_type)[0],
    )


def test_definitely_raising_direct_call_has_no_normal_successor():
    exception = py_ast.Local("exception")
    callee = _code(
        "raise_only",
        py_ast.Suite([py_ast.Raise(exception, None, None)]),
        params=(exception,),
    )
    obj = py_ast.Local("obj")
    before = py_ast.Local("before")
    unreachable = py_ast.Local("unreachable")
    call = py_ast.Discard(
        py_ast.DirectCall(callee, None, [before], [], None, None)
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [before]),
                py_ast.Assign(py_ast.BuildList([]), [unreachable]),
                py_ast.SetAttr(before, obj, _existing("field")),
                call,
                py_ast.SetAttr(unreachable, obj, _existing("field")),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    field = heap.dynamic_attribute_location(
        heap.locations_for_local(code, obj)[0],
        "field",
    )
    assert heap.locations_for_local(code, before)[0] in graph.values_at(field)
    assert heap.locations_for_local(code, unreachable)[0] not in graph.values_at(field)


def test_returned_function_retains_and_escapes_its_closure_cells():
    cell = py_ast.Cell("captured")
    inner = _code("inner", py_ast.Suite([]))
    register_code_definition_metadata(inner, closure_cells=(cell,))
    value = py_ast.Local("value")
    outer_ret = py_ast.Local("outer_ret")
    outer = _code(
        "outer",
        py_ast.Suite(
            [
                py_ast.SetCellDeref(value, cell),
                py_ast.FunctionDef("inner", inner, [], None),
                py_ast.Return([py_ast.Local("inner")]),
            ]
        ),
        params=(value,),
        returns=(outer_ret,),
    )
    actual = py_ast.Local("actual")
    returned = py_ast.Local("returned")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [actual]),
                py_ast.Assign(
                    py_ast.DirectCall(outer, None, [actual], [], None, None),
                    [returned],
                )
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None
    captured = heap.locations_for_local(caller, actual)[0]
    assert graph.is_escaped(captured)


def test_program_point_queries_expose_before_and_after_heap_values():
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    write = py_ast.SetAttr(value, obj, _existing("field"))
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                write,
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    field = heap.dynamic_attribute_location(
        heap.locations_for_local(code, obj)[0],
        "field",
    )
    assert not graph.values_at(field, write, before=True)
    assert heap.locations_for_local(code, value)[0] in graph.values_at(field, write)


def test_generator_instances_advance_one_yield_per_resume():
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    generator = _code(
        "generator",
        py_ast.Suite(
            [
                py_ast.Discard(py_ast.Yield(first)),
                py_ast.Discard(py_ast.Yield(second)),
            ]
        ),
        params=(first, second),
    )
    generator.annotation = copy(generator.annotation)
    generator.annotation.origin = ["converted_generator"]
    actual_first = py_ast.Local("actual_first")
    actual_second = py_ast.Local("actual_second")
    iterator = py_ast.Local("iterator")
    yielded_first = py_ast.Local("yielded_first")
    yielded_second = py_ast.Local("yielded_second")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [actual_first]),
                py_ast.Assign(py_ast.BuildList([]), [actual_second]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        generator,
                        None,
                        [actual_first, actual_second],
                        [],
                        None,
                        None,
                    ),
                    [iterator],
                ),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("next"), [iterator], [], None, None),
                    [yielded_first],
                ),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("next"), [iterator], [], None, None),
                    [yielded_second],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.aliased(
        heap.locations_for_local(code, yielded_first)[0],
        heap.locations_for_local(code, actual_first)[0],
    )
    assert graph.aliased(
        heap.locations_for_local(code, yielded_second)[0],
        heap.locations_for_local(code, actual_second)[0],
    )


def test_known_class_instances_read_inherited_class_members():
    class_local = py_ast.Local("member")
    class_node = py_ast.ClassDef(
        "C",
        [],
        [],
        py_ast.Suite([py_ast.Assign(py_ast.BuildList([]), [class_local])]),
        [],
        None,
    )
    instance = py_ast.Local("instance")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                class_node,
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("C"), [], [], None, None),
                    [instance],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(instance, _existing("member")),
                    [loaded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert heap.locations_for_local(code, loaded)


def test_known_class_constructor_applies_resolved_init_effects():
    self_param = py_ast.Local("self")
    value_param = py_ast.Local("value")
    initializer = _code(
        "__init__",
        py_ast.Suite(
            [py_ast.SetAttr(value_param, self_param, _existing("payload"))]
        ),
        params=(self_param, value_param),
    )
    class_node = py_ast.ClassDef(
        "C",
        [],
        [],
        py_ast.Suite([py_ast.FunctionDef("__init__", initializer, [], None)]),
        [],
        None,
    )
    argument = py_ast.Local("argument")
    instance = py_ast.Local("instance")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                class_node,
                py_ast.Assign(py_ast.BuildList([]), [argument]),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("C"), [argument], [], None, None),
                    [instance],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(instance, _existing("payload")),
                    [loaded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert heap.locations_for_local(code, argument)[0] in heap.locations_for_local(
        code,
        loaded,
    )


def test_retaining_known_constructor_keeps_arguments_reachable():
    argument = py_ast.Local("argument")
    partial = py_ast.Local("partial")
    ret = py_ast.Local("ret")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [argument]),
                py_ast.Assign(
                    py_ast.Call(
                        py_ast.Local("functools.partial"),
                        [argument],
                        [],
                        None,
                        None,
                    ),
                    [partial],
                ),
                py_ast.Return([partial]),
            ]
        ),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.is_escaped(heap.locations_for_local(code, argument)[0])


def test_slice_copy_for_starred_unpacking_has_fresh_container_identity():
    element = py_ast.Local("element")
    source = py_ast.Local("source")
    rest = py_ast.Local("rest")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [element]),
                py_ast.Assign(py_ast.BuildList([element]), [source]),
                py_ast.Assign(
                    py_ast.Call(
                        py_ast.Local("interpreter_slice_copy"),
                        [source, py_ast.BuildSlice(_existing(0), _existing(None), None)],
                        [],
                        None,
                        None,
                    ),
                    [rest],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    rest_location = heap.locations_for_local(code, rest)[0]
    element_location = heap.locations_for_local(code, element)[0]
    assert not graph.aliased(rest_location, element_location)
    assert element_location in graph.values_at(
        heap.dynamic_subscript_location(rest_location, "[0]")
    )


def test_conditional_expression_joins_branch_bindings():
    condition = py_ast.Local("condition")
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    selected = py_ast.Local("selected")
    result = py_ast.Local("result")
    expression = py_ast.ConditionalExpr(condition, first, second)
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [first]),
                py_ast.Assign(py_ast.BuildList([]), [second]),
                py_ast.Assign(expression, [selected]),
                py_ast.Assign(selected, [result]),
            ]
        ),
        params=(condition,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    result_locations = heap.locations_for_local(code, result)
    assert heap.locations_for_local(code, first)[0] in result_locations
    assert heap.locations_for_local(code, second)[0] in result_locations


def test_bare_raise_preserves_the_active_exception_identity():
    from pyflow.analysis.alias.flow_sensitive.abstraction import HeapAbstraction
    from pyflow.analysis.alias.flow_sensitive.transfer import HeapTransferEngine

    exception = py_ast.Local("exception")
    caught = py_ast.Local("caught")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.TryExceptFinally(
                    py_ast.Suite([py_ast.Raise(exception, None, None)]),
                    [
                        py_ast.ExceptionHandler(
                            py_ast.Suite([]),
                            _existing("Exception"),
                            caught,
                            py_ast.Suite([py_ast.Raise(None, None, None)]),
                        )
                    ],
                    None,
                    py_ast.Suite([]),
                    py_ast.Suite([]),
                )
            ]
        ),
        params=(exception,),
    )
    heap = HeapAbstraction(lambda _procedure, _local: ())
    engine = HeapTransferEngine(heap)
    outcome = engine.analyze_node(code, code.ast)
    raised = outcome.abrupt["raise"].heap_state.raised.get(code, ())
    assert heap.locations_for_local(code, exception)[0] in raised


def test_globals_from_distinct_source_modules_do_not_share_slots():
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    first = _code(
        "first",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [left]),
                py_ast.SetGlobal(_existing("value"), left),
            ]
        ),
    )
    second = _code(
        "second",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [right]),
                py_ast.SetGlobal(_existing("value"), right),
            ]
        ),
    )
    first.annotation = copy(first.annotation)
    second.annotation = copy(second.annotation)
    first.annotation.origin = ["source(first.py:1)"]
    second.annotation.origin = ["source(second.py:1)"]

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, [first, second])
    heap = analysis.heap
    assert heap is not None
    first_global = HeapLocation(
        heap.global_object("value", module=("source-module", "first.py"))
    )
    second_global = HeapLocation(
        heap.global_object("value", module=("source-module", "second.py"))
    )
    assert graph.values_at(first_global) != graph.values_at(second_global)
