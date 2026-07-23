"""Adversarial soundness tests for bounded, resolved-call programs."""

from __future__ import annotations

from copy import copy

from pyflow.analysis.alias.flow_sensitive import (
    AllocationSensitivity,
    HeapAnalysis,
    HeapPolicy,
)
from pyflow.analysis.alias.flow_sensitive.heap_effects import HeapEffectBuilder
from pyflow.analysis.alias.flow_sensitive.model import HeapLocation
from pyflow.language.python.ir_metadata import register_code_definition_metadata
from pyflow.language.python import ast as py_ast


def _existing(value):
    return py_ast.Existing(py_ast.program.Object(value))


class _OpaqueStatement(py_ast.Statement):
    __slots__ = ("value", "target")


def _init_opaque_statement(self, value, target):
    self.value = value
    self.target = target
    self.annotation = self.__emptyAnnotation__


def _visit_opaque_statement_children(self, callback):
    callback(self.value)
    callback(self.target)


_OpaqueStatement.__init__ = _init_opaque_statement
_OpaqueStatement.visitChildren = _visit_opaque_statement_children


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

    assert graph.must_alias(
        heap.locations_for_local(caller, first)[0],
        heap.locations_for_local(caller, left)[0],
    )
    assert graph.must_alias(
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
    assert graph.must_alias(heap.locations_for_local(code, attr)[0], value_location)
    assert graph.must_alias(
        heap.locations_for_local(code, next_value)[0], value_location
    )
    assert graph.must_alias(
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
    assert graph.must_alias(
        heap.locations_for_local(caller, var_result)[0], actual_location
    )
    assert graph.must_alias(
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
    assert not graph.must_alias(
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
    assert graph.must_alias(
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
    assert graph.must_alias(
        heap.locations_for_local(code, global_loaded)[0],
        heap.locations_for_local(code, global_value)[0],
    )
    assert graph.must_alias(
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
    assert graph.must_alias(value_location, value_location)
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
    assert graph.must_alias(
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
    assert graph.must_alias(
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
    assert graph.must_alias(
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
    values = graph.possible_values_at(field).locations
    assert heap.locations_for_local(code, before)[0] in values
    assert heap.locations_for_local(code, unreachable)[0] not in values


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
    assert graph.possible_values_at(
        field, write, before=True
    ).definitely_absent
    assert heap.locations_for_local(code, value)[0] in graph.possible_values_at(
        field, write
    ).locations


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
    assert graph.must_alias(
        heap.locations_for_local(code, yielded_first)[0],
        heap.locations_for_local(code, actual_first)[0],
    )
    assert graph.must_alias(
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


def test_known_subclass_constructor_applies_inherited_init_effects():
    self_param = py_ast.Local("self")
    value_param = py_ast.Local("value")
    initializer = _code(
        "__init__",
        py_ast.Suite(
            [py_ast.SetAttr(value_param, self_param, _existing("payload"))]
        ),
        params=(self_param, value_param),
    )
    base = py_ast.ClassDef(
        "Base",
        [],
        [],
        py_ast.Suite([py_ast.FunctionDef("__init__", initializer, [], None)]),
        [],
        None,
    )
    subclass = py_ast.ClassDef(
        "Subclass",
        [py_ast.Local("Base")],
        [],
        py_ast.Suite([]),
        [],
        None,
    )
    argument = py_ast.Local("argument")
    instance = py_ast.Local("instance")
    code = _code(
        "main",
        py_ast.Suite(
            [
                base,
                subclass,
                py_ast.Assign(py_ast.BuildList([]), [argument]),
                py_ast.Assign(
                    py_ast.Call(
                        py_ast.Local("Subclass"),
                        [argument],
                        [],
                        None,
                        None,
                    ),
                    [instance],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    concrete_instance = next(
        location
        for location in heap.locations_for_local(code, instance)
        if location.root.kind.value == "allocation"
    )
    payload = heap.dynamic_attribute_location(concrete_instance, "payload")
    assert heap.locations_for_local(code, argument)[0] in graph.possible_values_at(
        payload
    ).locations


def test_known_new_return_is_included_in_constructor_result():
    class_param = py_ast.Local("cls")
    value_param = py_ast.Local("value")
    return_param = py_ast.Local("return")
    allocator = _code(
        "__new__",
        py_ast.Suite([py_ast.Return([value_param])]),
        params=(class_param, value_param),
        returns=(return_param,),
    )
    class_node = py_ast.ClassDef(
        "C",
        [],
        [],
        py_ast.Suite([py_ast.FunctionDef("__new__", allocator, [], None)]),
        [],
        None,
    )
    argument = py_ast.Local("argument")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                class_node,
                py_ast.Assign(py_ast.BuildList([]), [argument]),
                py_ast.Assign(
                    py_ast.Call(
                        py_ast.Local("C"),
                        [argument],
                        [],
                        None,
                        None,
                    ),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert any(
        graph.must_alias(result_location, argument_location)
        for result_location in heap.locations_for_local(code, result)
        for argument_location in heap.locations_for_local(code, argument)
    )


def test_resolved_call_in_condition_preserves_exceptional_heap_effects():
    condition_formal = py_ast.Local("condition")
    object_formal = py_ast.Local("object")
    value_formal = py_ast.Local("value")
    exception_formal = py_ast.Local("exception")
    result_param = py_ast.Local("result")
    callee = _code(
        "condition",
        py_ast.Suite(
            [
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), condition_formal),
                    py_ast.Suite(
                        [
                            py_ast.SetAttr(
                                value_formal,
                                object_formal,
                                _existing("payload"),
                            ),
                            py_ast.Raise(exception_formal, None, None),
                        ]
                    ),
                    py_ast.Suite([py_ast.Return([condition_formal])]),
                )
            ]
        ),
        params=(condition_formal, object_formal, value_formal, exception_formal),
        returns=(result_param,),
    )
    condition = py_ast.Local("condition")
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    exception = py_ast.Local("exception")
    caught = py_ast.Local("caught")
    loaded = py_ast.Local("loaded")
    call = py_ast.DirectCall(
        callee,
        None,
        [condition, obj, value, exception],
        [],
        None,
        None,
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.TryExceptFinally(
                    py_ast.Suite(
                        [
                            py_ast.Switch(
                                py_ast.Condition(py_ast.Suite([]), call),
                                py_ast.Suite([]),
                                py_ast.Suite([]),
                            )
                        ]
                    ),
                    [
                        py_ast.ExceptionHandler(
                            py_ast.Suite([]),
                            _existing("Exception"),
                            caught,
                            py_ast.Suite(
                                [
                                    py_ast.Assign(
                                        py_ast.GetAttr(
                                            obj,
                                            _existing("payload"),
                                        ),
                                        [loaded],
                                    )
                                ]
                            ),
                        )
                    ],
                    None,
                    py_ast.Suite([]),
                    py_ast.Suite([]),
                ),
            ]
        ),
        params=(condition, exception),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert any(
        graph.may_alias(loaded_location, value_location)
        for loaded_location in heap.locations_for_local(code, loaded)
        for value_location in heap.locations_for_local(code, value)
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
    assert not graph.must_alias(rest_location, element_location)
    assert element_location in graph.possible_values_at(
        heap.dynamic_subscript_location(rest_location, "[0]")
    ).locations


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
    assert graph.possible_values_at(first_global) != graph.possible_values_at(
        second_global
    )


def test_generator_branch_yields_join_effects_at_same_resume_depth():
    condition_formal = py_ast.Local("condition")
    object_formal = py_ast.Local("object")
    left_formal = py_ast.Local("left")
    right_formal = py_ast.Local("right")
    generator = _code(
        "generator",
        py_ast.Suite(
            [
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), condition_formal),
                    py_ast.Suite(
                        [
                            py_ast.SetAttr(
                                left_formal,
                                object_formal,
                                _existing("payload"),
                            ),
                            py_ast.Discard(py_ast.Yield(left_formal)),
                        ]
                    ),
                    py_ast.Suite(
                        [
                            py_ast.SetAttr(
                                right_formal,
                                object_formal,
                                _existing("payload"),
                            ),
                            py_ast.Discard(py_ast.Yield(right_formal)),
                        ]
                    ),
                )
            ]
        ),
        params=(condition_formal, object_formal, left_formal, right_formal),
    )
    generator.annotation = copy(generator.annotation)
    generator.annotation.origin = ["converted_generator"]

    condition = py_ast.Local("condition")
    obj = py_ast.Local("obj")
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    iterator = py_ast.Local("iterator")
    yielded = py_ast.Local("yielded")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [left]),
                py_ast.Assign(py_ast.BuildList([]), [right]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        generator,
                        None,
                        [condition, obj, left, right],
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
                py_ast.Assign(
                    py_ast.GetAttr(obj, _existing("payload")),
                    [loaded],
                ),
            ]
        ),
        params=(condition,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert any(
        graph.may_alias(loaded_location, right_location)
        for loaded_location in heap.locations_for_local(code, loaded)
        for right_location in heap.locations_for_local(code, right)
    )


def test_generator_resume_preserves_caller_mutations_between_yields():
    object_formal = py_ast.Local("object")
    first_formal = py_ast.Local("first")
    generator = _code(
        "generator",
        py_ast.Suite(
            [
                py_ast.Discard(py_ast.Yield(first_formal)),
                py_ast.Discard(
                    py_ast.Yield(
                        py_ast.GetAttr(object_formal, _existing("payload"))
                    )
                ),
            ]
        ),
        params=(object_formal, first_formal),
    )
    generator.annotation = copy(generator.annotation)
    generator.annotation.origin = ["converted_generator"]

    obj = py_ast.Local("obj")
    old = py_ast.Local("old")
    new = py_ast.Local("new")
    iterator = py_ast.Local("iterator")
    first_result = py_ast.Local("first_result")
    second_result = py_ast.Local("second_result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [old]),
                py_ast.Assign(py_ast.BuildList([]), [new]),
                py_ast.SetAttr(old, obj, _existing("payload")),
                py_ast.Assign(
                    py_ast.DirectCall(
                        generator,
                        None,
                        [obj, old],
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
                    [first_result],
                ),
                py_ast.SetAttr(new, obj, _existing("payload")),
                py_ast.Assign(
                    py_ast.Call(
                        py_ast.Local("next"),
                        [iterator],
                        [],
                        None,
                        None,
                    ),
                    [second_result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert any(
        graph.may_alias(result_location, new_location)
        for result_location in heap.locations_for_local(code, second_result)
        for new_location in heap.locations_for_local(code, new)
    )


def test_allocation_insensitive_policy_never_strongly_updates_summary_root():
    first_container = py_ast.Local("first_container")
    second_container = py_ast.Local("second_container")
    first_value = py_ast.Local("first_value")
    second_value = py_ast.Local("second_value")
    loaded = py_ast.Local("loaded")
    first_object: list[object] = []
    second_object: list[object] = []
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [first_container]),
                py_ast.Assign(py_ast.BuildList([]), [second_container]),
                py_ast.Assign(_existing(first_object), [first_value]),
                py_ast.Assign(_existing(second_object), [second_value]),
                py_ast.SetSubscript(
                    first_value,
                    first_container,
                    _existing(0),
                ),
                py_ast.SetSubscript(
                    second_value,
                    second_container,
                    _existing(0),
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(first_container, _existing(0)),
                    [loaded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis(
        HeapPolicy(allocation_sensitivity=AllocationSensitivity.NONE)
    )
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert any(
        graph.may_alias(loaded_location, first_location)
        for loaded_location in heap.locations_for_local(code, loaded)
        for first_location in heap.locations_for_local(code, first_value)
    )


def test_indirect_call_resolves_finite_known_function_values():
    formal = py_ast.Local("formal")
    identity = _code(
        "identity",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(py_ast.Local("returned"),),
    )
    argument = py_ast.Local("argument")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.FunctionDef("identity", identity, [], None),
                py_ast.Assign(py_ast.BuildList([]), [argument]),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("identity"), [argument], [], None, None),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.must_alias(
        heap.locations_for_local(code, argument)[0],
        heap.locations_for_local(code, result)[0],
    )


def test_virtual_call_resolves_known_receiver_class_method():
    self_param = py_ast.Local("self")
    value_param = py_ast.Local("value")
    method = _code(
        "echo",
        py_ast.Suite([py_ast.Return([value_param])]),
        params=(self_param, value_param),
        returns=(py_ast.Local("returned"),),
    )
    class_node = py_ast.ClassDef(
        "C",
        [],
        [],
        py_ast.Suite([py_ast.FunctionDef("echo", method, [], None)]),
        [],
        None,
    )
    instance = py_ast.Local("instance")
    value = py_ast.Local("value")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                class_node,
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("C"), [], [], None, None),
                    [instance],
                ),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.MethodCall(
                        instance, _existing("echo"), [value], [], None, None
                    ),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.must_alias(
        heap.locations_for_local(code, value)[0],
        heap.locations_for_local(code, result)[0],
    )


def test_implicit_getitem_protocol_propagates_return_and_side_effects():
    self_param = py_ast.Local("self")
    key_param = py_ast.Local("key")
    getitem = _code(
        "__getitem__",
        py_ast.Suite(
            [
                py_ast.SetAttr(key_param, self_param, _existing("seen")),
                py_ast.Return([key_param]),
            ]
        ),
        params=(self_param, key_param),
        returns=(py_ast.Local("returned"),),
    )
    class_node = py_ast.ClassDef(
        "C",
        [],
        [],
        py_ast.Suite([py_ast.FunctionDef("__getitem__", getitem, [], None)]),
        [],
        None,
    )
    instance = py_ast.Local("instance")
    key = py_ast.Local("key")
    result = py_ast.Local("result")
    seen = py_ast.Local("seen")
    code = _code(
        "main",
        py_ast.Suite(
            [
                class_node,
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("C"), [], [], None, None),
                    [instance],
                ),
                py_ast.Assign(py_ast.BuildList([]), [key]),
                py_ast.Assign(py_ast.GetSubscript(instance, key), [result]),
                py_ast.Assign(py_ast.GetAttr(instance, _existing("seen")), [seen]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    key_location = heap.locations_for_local(code, key)[0]
    assert any(
        graph.may_alias(key_location, location)
        for location in heap.locations_for_local(code, result)
    )
    assert any(
        graph.may_alias(key_location, location)
        for location in heap.locations_for_local(code, seen)
    )


def test_resolved_new_controls_constructed_identity():
    cls_param = py_ast.Local("cls")
    supplied_param = py_ast.Local("supplied")
    allocator = _code(
        "__new__",
        py_ast.Suite([py_ast.Return([supplied_param])]),
        params=(cls_param, supplied_param),
        returns=(py_ast.Local("new_return"),),
    )
    other_class = py_ast.ClassDef(
        "Other", [], [], py_ast.Suite([]), [], None
    )
    constructed_class = py_ast.ClassDef(
        "C",
        [],
        [],
        py_ast.Suite([py_ast.FunctionDef("__new__", allocator, [], None)]),
        [],
        None,
    )
    supplied = py_ast.Local("supplied")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                other_class,
                constructed_class,
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("Other"), [], [], None, None),
                    [supplied],
                ),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("C"), [supplied], [], None, None),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.must_alias(
        heap.locations_for_local(code, supplied)[0],
        heap.locations_for_local(code, result)[0],
    )


def test_program_point_raise_outcome_retains_exceptional_heap_effects():
    obj_param = py_ast.Local("obj")
    value_param = py_ast.Local("value")
    exception_param = py_ast.Local("exception")
    callee = _code(
        "write_then_raise",
        py_ast.Suite(
            [
                py_ast.SetAttr(value_param, obj_param, _existing("payload")),
                py_ast.Raise(exception_param, None, None),
            ]
        ),
        params=(obj_param, value_param, exception_param),
    )
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    exception = py_ast.Local("exception")
    call_operation = py_ast.Assign(
        py_ast.DirectCall(
            callee, None, [obj, value, exception], [], None, None
        ),
        [py_ast.Local("unused")],
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(py_ast.BuildList([]), [exception]),
                call_operation,
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    field = heap.dynamic_attribute_location(
        heap.locations_for_local(code, obj)[0], "payload"
    )
    assert heap.locations_for_local(code, value)[0] in analysis.possible_values_at(
        field, call_operation, outcome="raise"
    ).locations


def test_generator_resume_does_not_replay_consumed_prefix_writes():
    obj_param = py_ast.Local("obj")
    prefix_value_param = py_ast.Local("prefix_value")
    later_value_param = py_ast.Local("later_value")
    generator = _code(
        "generator",
        py_ast.Suite(
            [
                py_ast.SetAttr(
                    prefix_value_param,
                    obj_param,
                    _existing("payload"),
                ),
                py_ast.Discard(py_ast.Yield(prefix_value_param)),
                py_ast.Discard(py_ast.Yield(later_value_param)),
            ]
        ),
        params=(obj_param, prefix_value_param, later_value_param),
    )
    generator.annotation = copy(generator.annotation)
    generator.annotation.origin = ["converted_generator"]
    obj = py_ast.Local("obj")
    prefix_value = py_ast.Local("prefix_value")
    later_value = py_ast.Local("later_value")
    caller_value = py_ast.Local("caller_value")
    iterator = py_ast.Local("iterator")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [prefix_value]),
                py_ast.Assign(py_ast.BuildList([]), [later_value]),
                py_ast.Assign(py_ast.BuildList([]), [caller_value]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        generator,
                        None,
                        [obj, prefix_value, later_value],
                        [],
                        None,
                        None,
                    ),
                    [iterator],
                ),
                py_ast.Discard(
                    py_ast.Call(py_ast.Local("next"), [iterator], [], None, None)
                ),
                py_ast.SetAttr(caller_value, obj, _existing("payload")),
                py_ast.Discard(
                    py_ast.Call(py_ast.Local("next"), [iterator], [], None, None)
                ),
                py_ast.Assign(py_ast.GetAttr(obj, _existing("payload")), [loaded]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.must_alias(
        heap.locations_for_local(code, caller_value)[0],
        heap.locations_for_local(code, loaded)[0],
    )


def test_program_point_yield_outcome_has_suspension_heap_snapshot():
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    yield_operation = py_ast.Discard(py_ast.Yield(value))
    code = _code(
        "generator",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.SetAttr(value, obj, _existing("payload")),
                yield_operation,
            ]
        ),
    )
    code.annotation = copy(code.annotation)
    code.annotation.origin = ["converted_generator"]

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    field = heap.dynamic_attribute_location(
        heap.locations_for_local(code, obj)[0], "payload"
    )
    assert heap.locations_for_local(code, value)[0] in analysis.possible_values_at(
        field, yield_operation, outcome="yield"
    ).locations


def test_nested_indirect_call_executes_inside_collection_literal():
    formal = py_ast.Local("formal")
    identity = _code(
        "identity",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(py_ast.Local("returned"),),
    )
    value = py_ast.Local("value")
    container = py_ast.Local("container")
    loaded = py_ast.Local("loaded")
    nested_call = py_ast.Call(
        py_ast.Local("identity"), [value], [], None, None
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.FunctionDef("identity", identity, [], None),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(py_ast.BuildList([nested_call]), [container]),
                py_ast.Assign(
                    py_ast.GetSubscript(container, _existing(0)),
                    [loaded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.must_alias(
        heap.locations_for_local(code, value)[0],
        heap.locations_for_local(code, loaded)[0],
    )


def test_make_function_value_is_a_finite_callable_target():
    formal = py_ast.Local("formal")
    inner = _code(
        "inner",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(py_ast.Local("returned"),),
    )
    function = py_ast.Local("function")
    value = py_ast.Local("value")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.MakeFunction([], [], inner), [function]),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.Call(function, [value], [], None, None),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.must_alias(
        heap.locations_for_local(code, value)[0],
        heap.locations_for_local(code, result)[0],
    )


def test_stored_bound_method_preserves_receiver_binding():
    self_param = py_ast.Local("self")
    value_param = py_ast.Local("value")
    method = _code(
        "method",
        py_ast.Suite([py_ast.Return([value_param])]),
        params=(self_param, value_param),
        returns=(py_ast.Local("returned"),),
    )
    class_node = py_ast.ClassDef(
        "C",
        [],
        [],
        py_ast.Suite([py_ast.FunctionDef("method", method, [], None)]),
        [],
        None,
    )
    instance = py_ast.Local("instance")
    bound = py_ast.Local("bound")
    value = py_ast.Local("value")
    result = py_ast.Local("result")
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
                    py_ast.GetAttr(instance, _existing("method")),
                    [bound],
                ),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.Call(bound, [value], [], None, None),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.must_alias(
        heap.locations_for_local(code, value)[0],
        heap.locations_for_local(code, result)[0],
    )


def test_callable_instance_dispatches_through_dunder_call():
    self_param = py_ast.Local("self")
    value_param = py_ast.Local("value")
    call_method = _code(
        "__call__",
        py_ast.Suite([py_ast.Return([value_param])]),
        params=(self_param, value_param),
        returns=(py_ast.Local("returned"),),
    )
    class_node = py_ast.ClassDef(
        "Callable",
        [],
        [],
        py_ast.Suite([py_ast.FunctionDef("__call__", call_method, [], None)]),
        [],
        None,
    )
    instance = py_ast.Local("instance")
    value = py_ast.Local("value")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                class_node,
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("Callable"), [], [], None, None),
                    [instance],
                ),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.Call(instance, [value], [], None, None),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.must_alias(
        heap.locations_for_local(code, value)[0],
        heap.locations_for_local(code, result)[0],
    )


def test_class_alias_construction_uses_evaluated_class_root():
    class_node = py_ast.ClassDef("C", [], [], py_ast.Suite([]), [], None)
    class_alias = py_ast.Local("alias")
    instance = py_ast.Local("instance")
    code = _code(
        "main",
        py_ast.Suite(
            [
                class_node,
                py_ast.Assign(py_ast.Local("C"), [class_alias]),
                py_ast.Assign(
                    py_ast.Call(class_alias, [], [], None, None),
                    [instance],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    class_values = graph.possible_values_at(
        heap.dynamic_attribute_location(
            heap.locations_for_local(code, instance)[0],
            "__class__",
        )
    ).locations
    assert any(
        location.root.label == "class C" for location in class_values
    )


def test_generator_keeps_pre_yield_allocation_identity_across_resumes():
    held = py_ast.Local("held")
    generator = _code(
        "generator",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [held]),
                py_ast.Discard(py_ast.Yield(held)),
                py_ast.Discard(py_ast.Yield(held)),
            ]
        ),
    )
    generator.annotation = copy(generator.annotation)
    generator.annotation.origin = ["converted_generator"]
    iterator = py_ast.Local("iterator")
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(
                    py_ast.DirectCall(generator, None, [], [], None, None),
                    [iterator],
                ),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("next"), [iterator], [], None, None),
                    [first],
                ),
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("next"), [iterator], [], None, None),
                    [second],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    assert graph.must_alias(
        heap.locations_for_local(code, first)[0],
        heap.locations_for_local(code, second)[0],
    )


def test_scalar_presence_and_local_program_point_queries_are_distinct():
    obj = py_ast.Local("obj")
    local = py_ast.Local("local")
    assignment = py_ast.Assign(py_ast.BuildList([]), [local])
    scalar_store = py_ast.SetAttr(_existing(1), obj, _existing("payload"))
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                assignment,
                scalar_store,
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    field = heap.dynamic_attribute_location(
        heap.locations_for_local(code, obj)[0], "payload"
    )
    scalar = graph.possible_values_at(field, scalar_store)
    assert scalar.includes_non_reference
    assert not scalar.definitely_absent
    assert not scalar.includes_unknown
    assert heap.locations_for_local(code, local)[0] in graph.possible_local_values_at(
        code,
        local,
        assignment,
        outcome="normal",
    ).locations


def test_static_class_and_property_descriptors_bind_correctly():
    static_value = py_ast.Local("static_value")
    static_code = _code(
        "static",
        py_ast.Suite([py_ast.Return([static_value])]),
        params=(static_value,),
        returns=(py_ast.Local("static_return"),),
    )
    cls_param = py_ast.Local("cls")
    class_value = py_ast.Local("class_value")
    class_code = _code(
        "class_method",
        py_ast.Suite([py_ast.Return([class_value])]),
        params=(cls_param, class_value),
        returns=(py_ast.Local("class_return"),),
    )
    self_param = py_ast.Local("self")
    property_code = _code(
        "property_value",
        py_ast.Suite([py_ast.Return([self_param])]),
        params=(self_param,),
        returns=(py_ast.Local("property_return"),),
    )
    class_node = py_ast.ClassDef(
        "C",
        [],
        [],
        py_ast.Suite(
            [
                py_ast.FunctionDef(
                    "static", static_code, [_existing("staticmethod")], None
                ),
                py_ast.FunctionDef(
                    "class_method",
                    class_code,
                    [_existing("classmethod")],
                    None,
                ),
                py_ast.FunctionDef(
                    "property_value",
                    property_code,
                    [_existing("property")],
                    None,
                ),
            ]
        ),
        [],
        None,
    )
    instance = py_ast.Local("instance")
    value = py_ast.Local("value")
    static_result = py_ast.Local("static_result")
    class_result = py_ast.Local("class_result")
    property_result = py_ast.Local("property_result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                class_node,
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("C"), [], [], None, None),
                    [instance],
                ),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.MethodCall(
                        instance, _existing("static"), [value], [], None, None
                    ),
                    [static_result],
                ),
                py_ast.Assign(
                    py_ast.MethodCall(
                        instance,
                        _existing("class_method"),
                        [value],
                        [],
                        None,
                        None,
                    ),
                    [class_result],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(instance, _existing("property_value")),
                    [property_result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    value_location = heap.locations_for_local(code, value)[0]
    assert graph.must_alias(
        value_location, heap.locations_for_local(code, static_result)[0]
    )
    assert graph.must_alias(
        value_location, heap.locations_for_local(code, class_result)[0]
    )
    assert graph.must_alias(
        heap.locations_for_local(code, instance)[0],
        heap.locations_for_local(code, property_result)[0],
    )


def test_super_method_dispatch_starts_after_current_class():
    base_self = py_ast.Local("self")
    base_value = py_ast.Local("value")
    base_method = _code(
        "method",
        py_ast.Suite([py_ast.Return([base_value])]),
        params=(base_self, base_value),
        returns=(py_ast.Local("base_return"),),
    )
    base_class = py_ast.ClassDef(
        "Base",
        [],
        [],
        py_ast.Suite([py_ast.FunctionDef("method", base_method, [], None)]),
        [],
        None,
    )
    child_self = py_ast.Local("self")
    child_value = py_ast.Local("value")
    child_method = _code(
        "method",
        py_ast.Suite(
            [
                py_ast.Return(
                    [
                        py_ast.MethodCall(
                            py_ast.Call(
                                py_ast.Local("super"), [], [], None, None
                            ),
                            _existing("method"),
                            [child_value],
                            [],
                            None,
                            None,
                        )
                    ]
                )
            ]
        ),
        params=(child_self, child_value),
        returns=(py_ast.Local("child_return"),),
    )
    child_class = py_ast.ClassDef(
        "Child",
        [py_ast.Local("Base")],
        [],
        py_ast.Suite([py_ast.FunctionDef("method", child_method, [], None)]),
        [],
        None,
    )
    instance = py_ast.Local("instance")
    value = py_ast.Local("value")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                base_class,
                child_class,
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("Child"), [], [], None, None),
                    [instance],
                ),
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(
                    py_ast.MethodCall(
                        instance, _existing("method"), [value], [], None, None
                    ),
                    [result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    child_locations = tuple(
        entry.location
        for entry in graph.iter_entries()
        if entry.location.root.label == "class Child"
    )
    assert child_locations
    child_bases = graph.possible_values_at(
        heap.dynamic_attribute_location(child_locations[0], "__bases__")
    ).locations
    assert any(location.root.label == "class Base" for location in child_bases), child_bases
    super_locations = tuple(
        entry.location
        for entry in graph.iter_entries()
        if entry.location.root.label == "super proxy"
    )
    assert super_locations, tuple(
        code.codeName() for code in analysis.procedure_summaries
    )
    super_class_values = graph.possible_values_at(
        heap.dynamic_attribute_location(super_locations[0], "__super_class__")
    ).locations
    assert super_class_values == frozenset(child_locations)
    assert graph.possible_values_at(
        heap.dynamic_attribute_location(super_locations[0], "__super_self__")
    ).locations
    assert base_method in analysis.procedure_summaries, tuple(
        code.codeName() for code in analysis.procedure_summaries
    )
    assert graph.must_alias(
        heap.locations_for_local(code, value)[0],
        heap.locations_for_local(code, result)[0],
    )


def test_definitely_invalid_known_call_has_raise_only_outcome():
    formal = py_ast.Local("formal")
    callee = _code(
        "callee",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(py_ast.Local("returned"),),
    )
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    invalid_call = py_ast.Assign(
        py_ast.DirectCall(
            callee,
            None,
            [first, second],
            [],
            None,
            None,
        ),
        [py_ast.Local("result")],
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [first]),
                py_ast.Assign(py_ast.BuildList([]), [second]),
                invalid_call,
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)

    outcomes = graph.program_point_outcomes[id(invalid_call)]
    assert "raise" in outcomes
    assert "normal" not in outcomes


def _direct_call_outcomes(callee, call):
    operation = py_ast.Assign(call, [py_ast.Local("result")])
    caller = _code("caller", py_ast.Suite([operation]))
    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    return graph.program_point_outcomes[id(operation)]


def test_missing_required_argument_has_raise_only_outcome():
    required = py_ast.Local("required")
    callee = _code(
        "callee",
        py_ast.Suite([py_ast.Return([required])]),
        params=(required,),
        returns=(py_ast.Local("returned"),),
    )

    outcomes = _direct_call_outcomes(
        callee,
        py_ast.DirectCall(callee, None, [], [], None, None),
    )

    assert "raise" in outcomes
    assert "normal" not in outcomes


def test_positional_only_parameter_rejects_keyword_binding():
    positional_only = py_ast.Local("value")
    callee = py_ast.Code(
        "callee",
        py_ast.CodeParameters(
            None,
            [positional_only],
            ["value"],
            [],
            [],
            [],
            None,
            None,
            [py_ast.Local("returned")],
            None,
        ),
        py_ast.Suite([py_ast.Return([positional_only])]),
    )

    outcomes = _direct_call_outcomes(
        callee,
        py_ast.DirectCall(
            callee,
            None,
            [],
            [("value", _existing(object()))],
            None,
            None,
        ),
    )

    assert "raise" in outcomes
    assert "normal" not in outcomes


def test_positional_and_keyword_binding_same_parameter_is_invalid():
    formal = py_ast.Local("value")
    callee = _code(
        "callee",
        py_ast.Suite([py_ast.Return([formal])]),
        params=(formal,),
        returns=(py_ast.Local("returned"),),
    )

    outcomes = _direct_call_outcomes(
        callee,
        py_ast.DirectCall(
            callee,
            None,
            [_existing(object())],
            [("value", _existing(object()))],
            None,
            None,
        ),
    )

    assert "raise" in outcomes
    assert "normal" not in outcomes


def test_unknown_positional_spread_preserves_normal_and_type_error_paths():
    required = py_ast.Local("required")
    callee = _code(
        "callee",
        py_ast.Suite([py_ast.Return([required])]),
        params=(required,),
        returns=(py_ast.Local("returned"),),
    )
    spread = py_ast.Local("spread")
    operation = py_ast.Assign(
        py_ast.DirectCall(callee, None, [], [], spread, None),
        [py_ast.Local("result")],
    )
    caller = _code("caller", py_ast.Suite([operation]))
    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)

    outcomes = graph.program_point_outcomes[id(operation)]
    assert "normal" in outcomes
    assert "raise" in outcomes


def test_unsupported_statement_contaminates_only_reachable_objects():
    value = py_ast.Local("value")
    target = py_ast.Local("target")
    loaded = py_ast.Local("loaded")
    operation = _OpaqueStatement(value, target)
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                operation,
                py_ast.Assign(
                    py_ast.GetAttr(value, _existing("payload")),
                    [loaded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None
    value_location = heap.locations_for_local(caller, value)[0]

    assert graph.is_escaped(value_location)
    assert heap.locations_for_local(caller, target)
    assert heap.locations_for_local(caller, loaded)
    assert graph.degradations_at(operation) == frozenset(
        {"unsupported-_OpaqueStatement"}
    )
    assert graph.has_precision_degradation(operation)
    metrics = graph.analysis_metrics()
    assert metrics["degraded_program_point_count"] == 1
    assert metrics["degradation_reason_counts"] == {
        "unsupported-_OpaqueStatement": 1
    }
    evidence = graph.alias_evidence(value_location, value_location, operation)
    assert evidence["must_alias"]
    assert evidence["precision_degradations"] == [
        "unsupported-_OpaqueStatement"
    ]


def _outer_with_nonlocal_setter(name):
    outer_value = py_ast.Local("value")
    inner_value = py_ast.Local("replacement")
    inner_name = py_ast.Local("value")
    inner = _code(
        f"{name}_inner",
        py_ast.Suite(
            [
                py_ast.NonlocalDecl(inner_name),
                py_ast.Assign(inner_value, [inner_name]),
                py_ast.Return([inner_name]),
            ]
        ),
        params=(inner_value,),
        returns=(py_ast.Local("inner_return"),),
    )
    replacement = py_ast.Local("replacement")
    observed = py_ast.Local("observed")
    outer = _code(
        name,
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [outer_value]),
                py_ast.FunctionDef(f"{name}_inner", inner, [], None),
                py_ast.Discard(
                    py_ast.DirectCall(
                        inner,
                        None,
                        [replacement],
                        [],
                        None,
                        None,
                    )
                ),
                py_ast.Assign(outer_value, [observed]),
                py_ast.Return([observed]),
            ]
        ),
        params=(replacement,),
        returns=(py_ast.Local("outer_return"),),
    )
    return outer


def test_nonlocal_write_updates_nearest_outer_binding():
    outer = _outer_with_nonlocal_setter("outer")
    replacement = py_ast.Local("replacement")
    result = py_ast.Local("result")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [replacement]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        outer,
                        None,
                        [replacement],
                        [],
                        None,
                        None,
                    ),
                    [result],
                )
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    assert graph.must_alias(
        heap.locations_for_local(caller, replacement)[0],
        heap.locations_for_local(caller, result)[0],
    )


def test_same_nonlocal_name_in_unrelated_scopes_does_not_merge():
    left_outer = _outer_with_nonlocal_setter("left_outer")
    right_outer = _outer_with_nonlocal_setter("right_outer")
    left_replacement = py_ast.Local("left_replacement")
    right_replacement = py_ast.Local("right_replacement")
    left_result = py_ast.Local("left_result")
    right_result = py_ast.Local("right_result")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [left_replacement]),
                py_ast.Assign(py_ast.BuildList([]), [right_replacement]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        left_outer,
                        None,
                        [left_replacement],
                        [],
                        None,
                        None,
                    ),
                    [left_result],
                ),
                py_ast.Assign(
                    py_ast.DirectCall(
                        right_outer,
                        None,
                        [right_replacement],
                        [],
                        None,
                        None,
                    ),
                    [right_result],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None
    left_location = heap.locations_for_local(caller, left_replacement)[0]
    right_location = heap.locations_for_local(caller, right_replacement)[0]

    assert graph.must_alias(
        left_location,
        heap.locations_for_local(caller, left_result)[0],
    )
    assert graph.must_alias(
        right_location,
        heap.locations_for_local(caller, right_result)[0],
    )
    assert not graph.must_alias(left_location, right_location)
