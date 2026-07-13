"""Tests for intrinsic models and the default intrinsics table."""

from __future__ import annotations

from pyflow.analysis.alias.flow_sensitive import (
    DEFAULT_HEAP_INTRINSICS,
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


def test_uses_custom_intrinsic_models():
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


def test_intrinsic_table_describes_collection_and_copy_models():
    assert DEFAULT_HEAP_INTRINSICS.return_kind("copy.deepcopy") == "copy"
    insert = DEFAULT_HEAP_INTRINSICS.collection_mutator("insert")
    pop = DEFAULT_HEAP_INTRINSICS.collection_mutator("pop")

    assert insert is not None
    assert insert.value_args(("index", "value")) == ("value",)
    assert pop is not None
    assert pop.deletes_value
