from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.alias.flow_sensitive import (
    HeapAbstraction,
    HeapObjectKind,
    HeapPolicy,
)
from pyflow.analysis.alias.flow_sensitive.heap_effects import HeapEffectBuilder
from pyflow.language.python import ast as py_ast


@dataclass(frozen=True, eq=False)
class RawStorage:
    label: str


def _existing(value):
    return py_ast.Existing(py_ast.program.Object(value))


def _dummy_code(name="test"):
    return py_ast.Code(
        name,
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


def test_make_function_escapes_captured_cells():
    x_raw = RawStorage("x")
    x = py_ast.Local("x")
    raw = {id(x): (x_raw,)}
    heap = HeapAbstraction(
        lambda _procedure, local: raw.get(id(local), ()),
        policy=HeapPolicy(escape_on_return=True),
    )
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(
        None,
        py_ast.MakeFunction([], [py_ast.Cell("x")], _dummy_code()),
    )

    cell_loc = builder.cell_location(py_ast.Cell("x"))
    assert cell_loc in effect.reads
    assert cell_loc in effect.escapes


def test_make_function_reads_defaults():
    default_raw = RawStorage("default")
    default = py_ast.Local("default")
    x_raw = RawStorage("x")
    x = py_ast.Local("x")
    raw = {id(default): (default_raw,), id(x): (x_raw,)}
    heap = HeapAbstraction(
        lambda _procedure, local: raw.get(id(local), ()),
        policy=HeapPolicy(escape_on_return=True),
    )
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(
        None,
        py_ast.MakeFunction([default], [py_ast.Cell("x")], _dummy_code()),
    )

    default_loc = heap.location_for_raw(default_raw)
    cell_loc = builder.cell_location(py_ast.Cell("x"))
    assert default_loc in effect.reads
    assert cell_loc in effect.reads
    assert cell_loc in effect.escapes


def test_make_function_creates_allocation():
    target = py_ast.Local("fn")
    heap = HeapAbstraction(lambda _procedure, _local: ())
    builder = HeapEffectBuilder(heap, heap.locations_for_local)
    operation = py_ast.Assign(
        py_ast.MakeFunction([], [py_ast.Cell("x")], _dummy_code()),
        [target],
    )

    effect = builder.operation_effect(None, operation)

    assert len(effect.allocations) == 1
    assert effect.allocations[0].kind is HeapObjectKind.ALLOCATION
    assert effect.allocations[0].label == "function"
