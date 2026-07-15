"""Soundness regressions for bounded, closed-world Python IR constructs."""

from __future__ import annotations

from pyflow.analysis.alias.flow_sensitive import HeapAnalysis
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


def test_phi_joins_all_incoming_locations():
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    merged = py_ast.Local("merged")
    body = py_ast.Suite([])
    body.blocks.append(py_ast.Phi([left, None, right], merged))
    code = _code("main", body, params=(left, right))

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    merged_locations = heap.locations_for_local(code, merged)
    assert heap.locations_for_local(code, left)[0] in merged_locations
    assert heap.locations_for_local(code, right)[0] in merged_locations


def test_unpack_sequence_binds_literal_elements_by_index():
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    sequence = py_ast.Local("sequence")
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([left, right]), [sequence]),
                py_ast.UnpackSequence(sequence, [first, second]),
            ]
        ),
        params=(left, right),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, left)[0] in heap.locations_for_local(
        code, first
    )
    assert heap.locations_for_local(code, right)[0] in heap.locations_for_local(
        code, second
    )


def test_input_block_uses_shared_external_summary():
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.InputBlock(
                    [
                        py_ast.Input(py_ast.IOName("first"), first),
                        py_ast.Input(py_ast.IOName("second"), second),
                    ]
                )
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    first_location = heap.locations_for_local(code, first)[0]
    second_location = heap.locations_for_local(code, second)[0]
    assert first_location == second_location
    assert graph.may_alias(first_location, second_location)


def test_unconstrained_parameters_may_alias_each_other():
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    code = _code("main", py_ast.Suite([]), params=(first, second))

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert graph.may_alias(
        heap.locations_for_local(code, first)[0],
        heap.locations_for_local(code, second)[0],
    )


def test_named_expression_binds_inside_discard():
    value = py_ast.Local("value")
    target = py_ast.Local("target")
    code = _code(
        "main",
        py_ast.Suite([py_ast.Discard(py_ast.NamedExpr(target, value))]),
        params=(value,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, value)[0] in heap.locations_for_local(
        code, target
    )


def test_low_level_allocate_store_and_load_flow():
    value = py_ast.Local("value")
    obj = py_ast.Local("obj")
    loaded = py_ast.Local("loaded")
    field = _existing("payload")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.Allocate(_existing("Object")), [obj]),
                py_ast.Store(obj, "Attribute", field, value),
                py_ast.Assign(py_ast.Load(obj, "Attribute", field), [loaded]),
            ]
        ),
        params=(value,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, value)[0] in heap.locations_for_local(
        code, loaded
    )


def test_caught_exception_value_flows_to_handler_local():
    exception = py_ast.Local("exception")
    caught = py_ast.Local("caught")
    ret = py_ast.Local("ret")
    handler = py_ast.ExceptionHandler(
        py_ast.Suite([]),
        _existing("Exception"),
        caught,
        py_ast.Suite([py_ast.Return([caught])]),
    )
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.TryExceptFinally(
                    py_ast.Suite([py_ast.Raise(exception, None, None)]),
                    [handler],
                    None,
                    None,
                    None,
                )
            ]
        ),
        params=(exception,),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, exception)[0] in heap.locations_for_local(
        code, ret
    )


def test_finally_return_overrides_pending_return():
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    ret = py_ast.Local("ret")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.TryExceptFinally(
                    py_ast.Suite([py_ast.Return([first])]),
                    [],
                    None,
                    None,
                    py_ast.Suite([py_ast.Return([second])]),
                )
            ]
        ),
        params=(first, second),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    second_location = heap.locations_for_local(code, second)[0]
    return_locations = heap.locations_for_local(code, ret)
    assert second_location in return_locations
    assert heap.locations_for_local(code, first)[0] not in return_locations


def test_two_returning_switch_branches_make_following_code_unreachable():
    cond = py_ast.Local("cond")
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    ret = py_ast.Local("ret")
    unreachable = py_ast.Local("unreachable")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), cond),
                    py_ast.Suite([py_ast.Return([left])]),
                    py_ast.Suite([py_ast.Return([right])]),
                ),
                py_ast.Assign(py_ast.BuildList([]), [unreachable]),
            ]
        ),
        params=(cond, left, right),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    return_locations = heap.locations_for_local(code, ret)
    assert heap.locations_for_local(code, left)[0] in return_locations
    assert heap.locations_for_local(code, right)[0] in return_locations
    assert not heap.locations_for_local(code, unreachable)


def test_type_alias_and_function_definition_populate_global_bindings():
    value = py_ast.Local("value")
    alias_loaded = py_ast.Local("alias_loaded")
    alias_value_loaded = py_ast.Local("alias_value_loaded")
    function_loaded = py_ast.Local("function_loaded")
    inner = _code("inner", py_ast.Suite([]))
    code = _code(
        "module",
        py_ast.Suite(
            [
                py_ast.TypeAlias("Alias", [], value),
                py_ast.Assign(py_ast.GetGlobal(_existing("Alias")), [alias_loaded]),
                py_ast.Assign(
                    py_ast.GetAttr(alias_loaded, _existing("__value__")),
                    [alias_value_loaded],
                ),
                py_ast.FunctionDef("defined", inner, [], None),
                py_ast.Assign(
                    py_ast.GetGlobal(_existing("defined")),
                    [function_loaded],
                ),
            ]
        ),
        params=(value,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, value)[0] in heap.locations_for_local(
        code, alias_value_loaded
    )
    assert heap.locations_for_local(code, function_loaded)[0].root.label == (
        "function defined"
    )


def test_output_block_marks_values_escaped():
    value = py_ast.Local("value")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.OutputBlock(
                    [py_ast.Output(value, py_ast.IOName("result"))]
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert graph.is_escaped(heap.locations_for_local(code, value)[0])


def test_await_result_conservatively_includes_awaitable():
    awaitable = py_ast.Local("awaitable")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite([py_ast.Assign(py_ast.Await(awaitable), [result])]),
        params=(awaitable,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, awaitable)[0] in heap.locations_for_local(
        code, result
    )


def test_build_slice_and_class_definition_allocate_objects():
    slice_value = py_ast.Local("slice_value")
    class_value = py_ast.Local("class_value")
    body_value = py_ast.Local("body_value")
    body_loaded = py_ast.Local("body_loaded")
    code = _code(
        "module",
        py_ast.Suite(
            [
                py_ast.Assign(
                    py_ast.BuildSlice(_existing(0), _existing(2), None),
                    [slice_value],
                ),
                py_ast.ClassDef(
                    "Defined",
                    [],
                    [],
                    py_ast.Suite(
                        [py_ast.SetGlobal(_existing("body"), body_value)]
                    ),
                    [],
                    None,
                ),
                py_ast.Assign(
                    py_ast.GetGlobal(_existing("Defined")),
                    [class_value],
                ),
                py_ast.Assign(
                    py_ast.GetGlobal(_existing("body")),
                    [body_loaded],
                ),
            ]
        ),
        params=(body_value,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, slice_value)[0].root.label == "slice literal"
    assert heap.locations_for_local(code, class_value)[0].root.label == "class Defined"
    assert heap.locations_for_local(code, body_value)[0] in heap.locations_for_local(
        code, body_loaded
    )


def test_class_name_is_bound_after_class_body_executes():
    original = py_ast.Local("original")
    seen_in_body = py_ast.Local("seen_in_body")
    class_value = py_ast.Local("class_value")
    seen_loaded = py_ast.Local("seen_loaded")
    code = _code(
        "module",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [original]),
                py_ast.SetGlobal(_existing("Defined"), original),
                py_ast.ClassDef(
                    "Defined",
                    [],
                    [],
                    py_ast.Suite(
                        [
                            py_ast.Assign(
                                py_ast.GetGlobal(_existing("Defined")),
                                [seen_in_body],
                            )
                        ]
                    ),
                    [],
                    None,
                ),
                py_ast.Assign(
                    py_ast.GetGlobal(_existing("Defined")),
                    [class_value],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(class_value, _existing("seen_in_body")),
                    [seen_loaded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    seen_locations = heap.locations_for_local(code, seen_loaded)
    assert heap.locations_for_local(code, original)[0] in seen_locations
    assert any(
        location.root.label == "class Defined"
        for location in heap.locations_for_local(code, class_value)
    )


def test_function_defaults_are_evaluated_at_definition_and_reused():
    formal = py_ast.Local("formal")
    callee_return = py_ast.Local("callee_return")
    default_expression = py_ast.BuildList([])
    callee = py_ast.Code(
        "factory",
        py_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[formal],
            paramnames=["formal"],
            defaults=[default_expression],
            vparam=None,
            kparam=None,
            returnparams=[callee_return],
            type_params=None,
        ),
        py_ast.Suite([py_ast.Return([formal])]),
    )
    function = py_ast.Local("function")
    default_loaded = py_ast.Local("default_loaded")
    result = py_ast.Local("result")
    module = _code(
        "module",
        py_ast.Suite(
            [
                py_ast.FunctionDef("factory", callee, [], None),
                py_ast.Assign(
                    py_ast.GetGlobal(_existing("factory")),
                    [function],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(function, _existing("__defaults__")),
                    [default_loaded],
                ),
                py_ast.Assign(
                    py_ast.DirectCall(
                        callee,
                        None,
                        [],
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
    graph = analysis.analyze(None, module)
    heap = analysis.heap
    assert heap is not None

    assert graph.must_alias(
        heap.locations_for_local(module, result)[0],
        heap.locations_for_local(module, default_loaded)[0],
    )


def test_short_circuit_joins_skipped_and_executed_named_expression():
    condition = py_ast.Local("condition")
    original = py_ast.Local("original")
    replacement = py_ast.Local("replacement")
    selected = py_ast.Local("selected")
    result = py_ast.Local("result")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [original]),
                py_ast.Assign(py_ast.BuildList([]), [replacement]),
                py_ast.Assign(original, [selected]),
                py_ast.Assign(
                    py_ast.ShortCircutAnd(
                        [condition, py_ast.NamedExpr(selected, replacement)]
                    ),
                    [result],
                ),
            ]
        ),
        params=(condition,),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    selected_locations = heap.locations_for_local(code, selected)
    assert heap.locations_for_local(code, original)[0] in selected_locations
    assert heap.locations_for_local(code, replacement)[0] in selected_locations


def test_store_evaluates_rhs_before_rebound_target_base():
    original = py_ast.Local("original")
    replacement = py_ast.Local("replacement")
    selected = py_ast.Local("selected")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [original]),
                py_ast.Assign(py_ast.BuildList([]), [replacement]),
                py_ast.Assign(original, [selected]),
                py_ast.SetAttr(
                    py_ast.NamedExpr(selected, replacement),
                    selected,
                    _existing("payload"),
                ),
                py_ast.Assign(
                    py_ast.GetAttr(replacement, _existing("payload")),
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
        heap.locations_for_local(code, loaded)[0],
        heap.locations_for_local(code, replacement)[0],
    )


def test_returned_collection_literal_retains_element_edges():
    payload = py_ast.Local("payload")
    callee_return = py_ast.Local("callee_return")
    callee = _code(
        "wrap",
        py_ast.Suite([py_ast.Return([py_ast.BuildList([payload])])]),
        params=(payload,),
        returns=(callee_return,),
    )
    actual = py_ast.Local("actual")
    wrapped = py_ast.Local("wrapped")
    loaded = py_ast.Local("loaded")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildMap([]), [actual]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        callee,
                        None,
                        [actual],
                        [],
                        None,
                        None,
                    ),
                    [wrapped],
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(wrapped, _existing(0)),
                    [loaded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    assert graph.must_alias(
        heap.locations_for_local(caller, loaded)[0],
        heap.locations_for_local(caller, actual)[0],
    )


def test_returned_function_retains_default_value_edges():
    default = py_ast.Local("default")
    callee_return = py_ast.Local("callee_return")
    inner = _code("inner", py_ast.Suite([]))
    callee = _code(
        "factory",
        py_ast.Suite(
            [
                py_ast.Return(
                    [py_ast.MakeFunction([default], [], inner)]
                )
            ]
        ),
        params=(default,),
        returns=(callee_return,),
    )
    actual = py_ast.Local("actual")
    function = py_ast.Local("function")
    loaded = py_ast.Local("loaded")
    caller = _code(
        "caller",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [actual]),
                py_ast.Assign(
                    py_ast.DirectCall(
                        callee,
                        None,
                        [actual],
                        [],
                        None,
                        None,
                    ),
                    [function],
                ),
                py_ast.Assign(
                    py_ast.GetAttr(function, _existing("__defaults__")),
                    [loaded],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, caller)
    heap = analysis.heap
    assert heap is not None

    assert graph.must_alias(
        heap.locations_for_local(caller, loaded)[0],
        heap.locations_for_local(caller, actual)[0],
    )
