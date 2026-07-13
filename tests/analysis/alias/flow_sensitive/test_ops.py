"""Tests for operations, closures, delete, and slices."""

from __future__ import annotations

from pyflow.analysis.alias.flow_sensitive import (
    HeapAnalysis,
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


def test_binary_op_result_conservatively_includes_overloaded_operands():
    """An overloaded binary operator may return either operand."""
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
    z_locs = heap.locations_for_local(code, z)
    assert x_loc in z_locs
    assert any(graph.may_alias(location, x_loc) for location in z_locs)


def test_unary_op_result_conservatively_includes_overloaded_operand():
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

    x_loc = heap.locations_for_local(code, x)[0]
    z_locs = heap.locations_for_local(code, z)
    assert x_loc in z_locs
    assert any(graph.may_alias(location, x_loc) for location in z_locs)


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


def test_tracks_closure_allocation_without_forcing_local_cell_escape():
    x = py_ast.Local("x")
    inner = py_ast.Local("inner")
    cell = py_ast.Cell("x")
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
                    py_ast.MakeFunction([], [cell], inner_code),
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

    cell_obj = heap.cell_object(cell)
    cell_loc = heap.location_for_raw(cell_obj)
    assert not graph.is_escaped(cell_loc)


def test_returned_closure_transitively_escapes_captured_cell():
    inner = py_ast.Local("inner")
    returned = py_ast.Local("returned")
    cell = py_ast.Cell("x")
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
                py_ast.Assign(
                    py_ast.MakeFunction([], [cell], inner_code),
                    [inner],
                ),
                py_ast.Return([inner]),
            ]
        ),
        returns=(returned,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    cell_loc = heap.location_for_raw(heap.cell_object(cell))
    assert graph.is_escaped(cell_loc)


def test_discarded_yield_escapes_value():
    value = py_ast.Local("value")
    code = _code(
        "generator",
        py_ast.Suite([py_ast.Discard(py_ast.Yield(value))]),
        params=(value,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    value_location = heap.locations_for_local(code, value)[0]
    assert graph.is_escaped(value_location)


def test_returned_function_escapes_default_values():
    default_value = py_ast.Local("default_value")
    fn = py_ast.Local("fn")
    ret = py_ast.Local("ret")
    inner_code = _code("inner", py_ast.Suite([]))
    code = _code(
        "outer",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [default_value]),
                py_ast.Assign(
                    py_ast.MakeFunction([default_value], [], inner_code),
                    [fn],
                ),
                py_ast.Return([fn]),
            ]
        ),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    default_location = heap.locations_for_local(code, default_value)[0]
    fn_location = heap.locations_for_local(code, fn)[0]
    ret_location = heap.locations_for_local(code, ret)[0]

    assert graph.is_escaped(fn_location)
    assert graph.is_escaped(default_location)
    assert graph.aliased(ret_location, fn_location)


def test_single_return_expression_preserves_all_possible_locations():
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    merged = py_ast.Local("merged")
    ret = py_ast.Local("ret")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.ShortCircutOr([a, b]), [merged]),
                py_ast.Return([merged]),
            ]
        ),
        params=(a, b),
        returns=(ret,),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    ret_locations = heap.locations_for_local(code, ret)
    a_location = heap.locations_for_local(code, a)[0]
    b_location = heap.locations_for_local(code, b)[0]

    assert a_location in ret_locations
    assert b_location in ret_locations
    assert any(graph.may_alias(loc, b_location) for loc in ret_locations)


def test_local_delete_removes_binding():
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    code = _code(
        "test",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [x]),
                py_ast.Assign(x, [y]),
                py_ast.Delete(x),
            ]
        ),
    )
    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    y_locations = heap.locations_for_local(code, y)
    assert len(y_locations) == 1, "y should still have the old location"
    x_locations = heap.locations_for_local(code, x)
    assert len(x_locations) == 0, (
        "x should have no locations after delete"
    )


def test_getslice_conservatively_allows_custom_getitem_to_return_container():
    lst = py_ast.Local("lst")
    result = py_ast.Local("result")
    code = _code(
        "test",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([_existing("a")]), [lst]),
                py_ast.Assign(
                    py_ast.GetSlice(lst, _existing(0), _existing(2), None),
                    [result],
                ),
            ]
        ),
    )
    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    lst_location = heap.locations_for_local(code, lst)[0]
    result_locations = heap.locations_for_local(code, result)

    assert lst_location in result_locations
    assert any(graph.may_alias(location, lst_location) for location in result_locations)
