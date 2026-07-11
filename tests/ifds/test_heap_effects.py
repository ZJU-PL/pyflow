"""Tests for IFDS heap-effect extraction."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.ifds.heap import (
    HeapAbstraction,
    HeapObjectKind,
    HeapPolicy,
    UpdatePolicy,
)
from pyflow.analysis.ifds.heap_effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_SUMMARY,
    HeapEffectBuilder,
)
from pyflow.language.python import ast as py_ast


@dataclass(frozen=True, eq=False)
class RawStorage:
    label: str


def _existing(value):
    return py_ast.Existing(py_ast.program.Object(value))


def test_heap_effect_extracts_dynamic_subscript_writes_and_escapes():
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    key = _existing("payload")
    raw = {id(value): (RawStorage("value"),)}
    heap = HeapAbstraction(
        lambda _procedure, local: raw.get(id(local), ()),
        policy=HeapPolicy(allow_strong_nested_fresh=True),
    )
    heap.bind_allocation_targets(None, (obj,), object(), label="fresh object")
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(None, py_ast.SetSubscript(value, obj, key))

    writes = {write.location: write.policy for write in effect.writes}
    base = heap.locations_for_local(None, obj)[0]
    exact = heap.dynamic_subscript_location(base, "['payload']")
    wildcard = heap.dynamic_subscript_location(base, "[*]")
    assert writes[exact] is UpdatePolicy.STRONG
    assert writes[wildcard] is UpdatePolicy.WEAK
    assert heap.locations_for_local(None, value)[0] in effect.escapes


def test_heap_effect_extracts_return_locations_and_escape():
    value = py_ast.Local("value")
    raw = {id(value): (RawStorage("value"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(None, py_ast.Return([value]))

    location = heap.locations_for_local(None, value)[0]
    assert effect.returns == (location,)
    assert effect.escapes == (location,)


def test_heap_effect_extracts_unresolved_call_argument_escape():
    arg = py_ast.Local("arg")
    raw = {id(arg): (RawStorage("arg"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)
    call = py_ast.Call(py_ast.Local("external"), [arg], [], None, None)

    effect = builder.unresolved_call_effect(None, call)

    location = heap.locations_for_local(None, arg)[0]
    assert effect.reads == (location,)
    assert effect.escapes == (location,)


def test_heap_effect_extracts_allocation_objects_for_literal_assignment():
    target = py_ast.Local("target")
    heap = HeapAbstraction(lambda _procedure, _local: ())
    builder = HeapEffectBuilder(heap, heap.locations_for_local)
    operation = py_ast.Assign(py_ast.BuildList([]), [target])

    effect = builder.operation_effect(None, operation)

    assert len(effect.allocations) == 1
    assert effect.allocations[0].kind is HeapObjectKind.ALLOCATION
    assert effect.allocations[0].label == "list literal"


def test_heap_effect_classifies_constructor_calls_as_fresh_allocations():
    target = py_ast.Local("target")
    call = py_ast.Call(py_ast.Local("User"), [], [], None, None)
    heap = HeapAbstraction(lambda _procedure, _local: ())
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(None, py_ast.Assign(call, [target]))

    assert builder.call_return_kind(call) == CALL_RETURN_FRESH
    assert len(effect.allocations) == 1
    assert effect.allocations[0].kind is HeapObjectKind.ALLOCATION
    assert effect.allocations[0].label == "User()"


def test_heap_effect_classifies_configured_summary_returns():
    call = py_ast.Call(py_ast.Local("library_value"), [], [], None, None)
    heap = HeapAbstraction(
        lambda _procedure, _local: (),
        policy=HeapPolicy(summary_return_names=frozenset({"library_value"})),
    )
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    obj = builder.call_return_object(None, call)

    assert builder.call_return_kind(call) == CALL_RETURN_SUMMARY
    assert obj.kind is HeapObjectKind.SUMMARY
    assert obj.label == "library_value()"


def test_heap_effect_classifies_copy_returns_as_fresh_allocations():
    target = py_ast.Local("target")
    source = py_ast.Local("source")
    call = py_ast.Call(py_ast.Local("list"), [source], [], None, None)
    heap = HeapAbstraction(lambda _procedure, _local: ())
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(None, py_ast.Assign(call, [target]))

    assert builder.call_return_kind(call) == CALL_RETURN_COPY
    assert len(effect.allocations) == 1
    assert effect.allocations[0].kind is HeapObjectKind.ALLOCATION
