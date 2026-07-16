"""Tests for strong writes that clear previous bindings."""

from __future__ import annotations

from pyflow.analysis.alias.flow_sensitive import (
    HeapAnalysis,
    HeapPolicy,
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


def test_strong_write_none_clears_field():
    """A strong write to an attribute field replaces the previous binding."""
    obj = py_ast.Local("obj")
    old_value = py_ast.Local("old_value")
    new_value = py_ast.Local("new_value")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.SetAttr(old_value, obj, _existing("field")),
                py_ast.SetAttr(new_value, obj, _existing("field")),
                py_ast.Assign(
                    py_ast.GetAttr(obj, _existing("field")), [loaded]
                ),
            ]
        ),
        params=(old_value, new_value),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    new_location = heap.locations_for_local(code, new_value)[0]

    assert new_location in loaded_locations


def test_strong_write_constant_clears_nested_field():
    """STRONG write of a non-heap value (constant) to a nested field on a
    fresh singleton root must clear the previous binding."""
    obj = py_ast.Local("obj")
    old_value = py_ast.Local("old_value")
    loaded = py_ast.Local("loaded")
    code = _code(
        "main",
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [obj]),
                py_ast.SetAttr(old_value, obj, _existing("field")),
                py_ast.SetAttr(_existing(None), obj, _existing("field")),
                py_ast.Assign(
                    py_ast.GetAttr(obj, _existing("field")),
                    [loaded],
                ),
            ]
        ),
        params=(old_value,),
    )

    analysis = HeapAnalysis(
        policy=HeapPolicy(allow_strong_nested_fresh=True)
    )
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, loaded)
    old_location = heap.locations_for_local(code, old_value)[0]

    assert old_location not in loaded_locations, (
        "Constant STRONG write should clear the previous binding"
    )
