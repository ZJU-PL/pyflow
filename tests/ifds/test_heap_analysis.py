"""Tests for standalone heap analysis transfers."""

from __future__ import annotations

from pyflow.analysis.heap import (
    DEFAULT_HEAP_INTRINSICS,
    HeapAnalysis,
    HeapAbstraction,
    HeapIntrinsicModels,
    HeapObjectKind,
    HeapSelector,
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


def test_heap_analysis_applies_standalone_transfers_for_alias_escape_and_return():
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
                    py_ast.MethodCall(y, _existing("append"), [value], [], None, None)
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


def test_points_to_graph_may_alias_accounts_for_nested_selector_overlap():
    heap = HeapAbstraction(lambda _procedure, _local: ())
    obj = heap.allocation_object(None, object(), label="obj")
    root = heap.location_for_raw(obj)
    exact = heap.dynamic_subscript_location(root, "['payload']")
    other = heap.dynamic_subscript_location(root, "['other']")
    wildcard = heap.dynamic_subscript_location(root, "[*]")
    graph = heap.to_points_to_graph()

    assert graph.may_alias(exact, wildcard)
    assert graph.may_alias(wildcard, other)
    assert not graph.may_alias(exact, other)
    assert not graph.aliased(exact, wildcard)
    assert wildcard.selectors == (HeapSelector.unknown_element(),)


def test_heap_analysis_instantiates_direct_call_formals_and_returns():
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


def test_heap_analysis_summary_cache_key_distinguishes_actual_selectors():
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


def test_heap_analysis_uses_custom_intrinsic_models():
    target = py_ast.Local("target")
    source = py_ast.Local("source")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(
                    py_ast.Call(py_ast.Local("numpy.array"), [source], [], None, None),
                    [target],
                )
            ]
        ),
        params=(source,),
    )
    intrinsics = HeapIntrinsicModels(return_kinds={"numpy.array": "fresh"})

    analysis = HeapAnalysis(intrinsics=intrinsics)
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    target_location = heap.locations_for_local(code, target)[0]

    assert target_location.root.kind is HeapObjectKind.ALLOCATION
    assert graph.get(target_location) is not None


def test_heap_analysis_replays_cached_direct_call_summary_side_effects():
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


def test_heap_analysis_replays_cached_direct_call_summary_deletes():
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


def test_heap_analysis_binds_assigned_import_to_module_object():
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


def test_heap_analysis_tracks_instance_field_store_and_load_values():
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


def test_heap_analysis_keeps_distinct_instance_fields_separate():
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


def test_heap_intrinsic_table_describes_collection_and_copy_models():
    assert DEFAULT_HEAP_INTRINSICS.return_kind("copy.deepcopy") == "copy"
    insert = DEFAULT_HEAP_INTRINSICS.collection_mutator("insert")
    pop = DEFAULT_HEAP_INTRINSICS.collection_mutator("pop")

    assert insert is not None
    assert insert.value_args(("index", "value")) == ("value",)
    assert pop is not None
    assert pop.deletes_value


def test_heap_analysis_keeps_literal_dict_keys_precise():
    mapping = py_ast.Local("mapping")
    va = py_ast.Local("va")
    vb = py_ast.Local("vb")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildMap([]), [mapping]),
                py_ast.SetSubscript(va, mapping, _existing("a")),
                py_ast.SetSubscript(vb, mapping, _existing("b")),
                py_ast.Assign(py_ast.GetSubscript(mapping, _existing("a")), [loaded]),
            ]
        ),
        params=(va, vb),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_location = heap.locations_for_local(code, loaded)[0]
    va_location = heap.locations_for_local(code, va)[0]
    vb_location = heap.locations_for_local(code, vb)[0]

    assert graph.aliased(loaded_location, va_location)
    assert not graph.may_alias(loaded_location, vb_location)


def test_heap_analysis_wildcard_subscript_write_contaminates_exact_key_reads():
    mapping = py_ast.Local("mapping")
    exact_value = py_ast.Local("exact_value")
    dynamic_value = py_ast.Local("dynamic_value")
    dynamic_key = py_ast.Local("dynamic_key")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildMap([]), [mapping]),
                py_ast.SetSubscript(exact_value, mapping, _existing("a")),
                py_ast.SetSubscript(dynamic_value, mapping, dynamic_key),
                py_ast.Assign(py_ast.GetSubscript(mapping, _existing("a")), [loaded]),
            ]
        ),
        params=(exact_value, dynamic_value, dynamic_key),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    exact_location = heap.locations_for_local(code, exact_value)[0]
    dynamic_location = heap.locations_for_local(code, dynamic_value)[0]

    assert exact_location in loaded_locations
    assert dynamic_location in loaded_locations
    assert graph.may_alias(loaded_locations[0], exact_location)


def test_heap_analysis_joins_switch_branch_field_values():
    obj = py_ast.Local("obj")
    cond = py_ast.Local("cond")
    left = py_ast.Local("left")
    right = py_ast.Local("right")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
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


def test_heap_analysis_loop_fixed_point_keeps_wildcard_contamination():
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


def test_heap_analysis_recursive_direct_call_terminates_conservatively():
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


def test_binary_op_result_creates_fresh_binding():
    """BinaryOp creates a new object — result must NOT alias operands."""
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    z = py_ast.Local("z")
    code = _code(
        "test",
        py_ast.Suite([
            py_ast.Assign(py_ast.BuildList([]), [x]),
            py_ast.Assign(x, [y]),
            py_ast.Assign(py_ast.BinaryOp(x, "+", y), [z]),
        ]),
    )
    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap

    x_loc = heap.locations_for_local(code, x)[0]
    # BinaryOp result is a fresh unknown — z has no tracked heap location,
    # so it cannot alias with any operand
    z_locs = heap.locations_for_local(code, z)
    assert len(z_locs) == 0


def test_unary_op_result_creates_fresh_binding():
    x = py_ast.Local("x")
    z = py_ast.Local("z")
    code = _code(
        "test",
        py_ast.Suite([
            py_ast.Assign(py_ast.BuildList([]), [x]),
            py_ast.Assign(py_ast.UnaryPrefixOp("-", x), [z]),
        ]),
    )
    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap

    # Unary op creates a new value — z has no tracked heap location
    z_locs = heap.locations_for_local(code, z)
    assert len(z_locs) == 0


def test_named_expr_result_flows_value_locations():
    x = py_ast.Local("x")
    z = py_ast.Local("z")
    code = _code(
        "test",
        py_ast.Suite([
            py_ast.Assign(py_ast.BuildList([]), [x]),
            py_ast.Assign(py_ast.NamedExpr(z, x), [z]),
        ]),
    )
    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap

    x_loc = heap.locations_for_local(code, x)[0]
    z_loc = heap.locations_for_local(code, z)[0]

    assert graph.may_alias(z_loc, x_loc)


def test_heap_analysis_tracks_closure_allocation_and_cell_escape():
    x = py_ast.Local("x")
    inner = py_ast.Local("inner")
    inner_code = py_ast.Code(
        "inner",
        py_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[],
            type_params=None,
        ),
        py_ast.Suite([]),
    )
    code = _code(
        "outer",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [x]),
                py_ast.Assign(
                    py_ast.MakeFunction([], [py_ast.Cell("x")], inner_code),
                    [inner],
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    inner_location = heap.locations_for_local(code, inner)[0]
    assert inner_location.root.kind is HeapObjectKind.ALLOCATION
    assert inner_location.root.label == "function"

    cell_obj = heap.cell_object("x")
    cell_loc = heap.location_for_raw(cell_obj)
    assert graph.is_escaped(cell_loc)
