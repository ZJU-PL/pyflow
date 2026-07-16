"""Tests for collection literals, subscript access, and mutator methods."""

from __future__ import annotations

from pyflow.analysis.alias.flow_sensitive import (
    HeapAnalysis,
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


def test_keeps_literal_dict_keys_precise():
    mapping = py_ast.Local("mapping")
    va = py_ast.Local("va")
    vb = py_ast.Local("vb")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildMap([]), [mapping]),
                py_ast.Assign(py_ast.BuildList([]), [va]),
                py_ast.Assign(py_ast.BuildList([]), [vb]),
                py_ast.SetSubscript(va, mapping, _existing("a")),
                py_ast.SetSubscript(vb, mapping, _existing("b")),
                py_ast.Assign(py_ast.GetSubscript(mapping, _existing("a")), [loaded]),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_location = heap.locations_for_local(code, loaded)[0]
    va_location = heap.locations_for_local(code, va)[0]
    vb_location = heap.locations_for_local(code, vb)[0]

    assert graph.must_alias(loaded_location, va_location)
    assert not graph.may_alias(loaded_location, vb_location)


def test_wildcard_subscript_write_contaminates_exact_key_reads():
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


def test_list_literal_writes_element_values():
    """``lst = [a, b]`` must write ``a`` and ``b`` to indices 0 and 1."""
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    lst = py_ast.Local("lst")
    loaded_0 = py_ast.Local("loaded_0")
    loaded_1 = py_ast.Local("loaded_1")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([a, b]), [lst]),
                py_ast.Assign(
                    py_ast.GetSubscript(lst, _existing(0)),
                    [loaded_0],
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(lst, _existing(1)),
                    [loaded_1],
                ),
            ]
        ),
        params=(a, b),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_0_locs = heap.locations_for_local(code, loaded_0)
    loaded_1_locs = heap.locations_for_local(code, loaded_1)
    a_loc = heap.locations_for_local(code, a)[0]
    b_loc = heap.locations_for_local(code, b)[0]

    assert a_loc in loaded_0_locs
    assert b_loc in loaded_1_locs


def test_dict_literal_writes_key_values():
    """``d = {'x': a, 'y': b}`` must write ``a`` to key ``'x'`` and
    ``b`` to key ``'y'``."""
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    d = py_ast.Local("d")
    loaded_x = py_ast.Local("loaded_x")
    loaded_y = py_ast.Local("loaded_y")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(
                    py_ast.BuildMap([_existing("x"), a, _existing("y"), b]),
                    [d],
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(d, _existing("x")),
                    [loaded_x],
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(d, _existing("y")),
                    [loaded_y],
                ),
            ]
        ),
        params=(a, b),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_x_locs = heap.locations_for_local(code, loaded_x)
    loaded_y_locs = heap.locations_for_local(code, loaded_y)
    a_loc = heap.locations_for_local(code, a)[0]
    b_loc = heap.locations_for_local(code, b)[0]

    assert a_loc in loaded_x_locs
    assert b_loc in loaded_y_locs


def test_dict_literal_with_dynamic_key_writes_wildcard_value():
    key = py_ast.Local("key")
    value = py_ast.Local("value")
    mapping = py_ast.Local("mapping")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildMap([key, value]), [mapping]),
                py_ast.Assign(py_ast.GetSubscript(mapping, key), [loaded]),
            ]
        ),
        params=(key, value),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    assert heap.locations_for_local(code, value)[0] in heap.locations_for_local(
        code, loaded
    )


def test_append_writes_value_to_container():
    """``container.append(value)`` must write value locations to wildcard subscript."""
    container = py_ast.Local("container")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [container]),
                py_ast.Discard(
                    py_ast.MethodCall(
                        container, _existing("append"), [value], [], None, None
                    )
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(container, _existing("0")), [loaded]
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
        "Value written via .append() should be readable from container"
    )


def test_extend_writes_all_values():
    """``container.extend([a, b])`` must write all element values."""
    container = py_ast.Local("container")
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [container]),
                py_ast.Discard(
                    py_ast.MethodCall(
                        container, _existing("extend"), [a, b], [], None, None
                    )
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(container, _existing("0")), [loaded]
                ),
            ]
        ),
        params=(a, b),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    a_location = heap.locations_for_local(code, a)[0]
    b_location = heap.locations_for_local(code, b)[0]

    assert a_location in loaded_locations
    assert b_location in loaded_locations


def test_extend_reads_elements_from_iterable_argument():
    container = py_ast.Local("container")
    source = py_ast.Local("source")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [container]),
                py_ast.Assign(py_ast.BuildList([value]), [source]),
                py_ast.Discard(
                    py_ast.MethodCall(
                        container,
                        _existing("extend"),
                        [source],
                        [],
                        None,
                        None,
                    )
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(container, _existing(0)),
                    [loaded],
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
        code, loaded
    )


def test_slice_assignment_reads_elements_from_iterable_value():
    target = py_ast.Local("target")
    source = py_ast.Local("source")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [target]),
                py_ast.Assign(py_ast.BuildList([value]), [source]),
                py_ast.SetSlice(source, target, None, None, None),
                py_ast.Assign(
                    py_ast.GetSubscript(target, _existing(0)),
                    [loaded],
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
        code, loaded
    )


def test_setdefault_writes_value():
    """``container.setdefault(key, value)`` must write the value."""
    mapping = py_ast.Local("mapping")
    key = _existing("k")
    value = py_ast.Local("value")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildMap([]), [mapping]),
                py_ast.Discard(
                    py_ast.MethodCall(
                        mapping,
                        _existing("setdefault"),
                        [key, value],
                        [],
                        None,
                        None,
                    )
                ),
                py_ast.Assign(
                    py_ast.GetSubscript(mapping, key), [loaded]
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

    assert value_location in loaded_locations


def test_storing_value_in_local_container_does_not_escape_value():
    """A heap edge is not an escape until the container becomes reachable
    from outside the procedure."""
    value = py_ast.Local("value")
    container = py_ast.Local("container")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [value]),
                py_ast.Assign(py_ast.BuildList([]), [container]),
                py_ast.SetSubscript(value, container, _existing(0)),
            ]
        ),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    value_location = heap.locations_for_local(code, value)[0]
    container_location = heap.locations_for_local(code, container)[0]

    assert not graph.is_escaped(value_location)
    assert not graph.is_escaped(container_location)
