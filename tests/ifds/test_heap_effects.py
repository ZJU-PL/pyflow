"""Tests for IFDS heap-effect extraction."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.heap import (
    CollectionMutatorModel,
    HeapAbstraction,
    HeapIntrinsicModels,
    HeapObjectKind,
    HeapPolicy,
    UpdatePolicy,
)
from pyflow.analysis.heap.heap_effects import (
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


def test_heap_effect_classifies_qualified_copy_returns_as_fresh_allocations():
    target = py_ast.Local("target")
    source = py_ast.Local("source")
    call = py_ast.Call(py_ast.Local("copy.deepcopy"), [source], [], None, None)
    heap = HeapAbstraction(lambda _procedure, _local: ())
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(None, py_ast.Assign(call, [target]))

    assert builder.call_return_kind(call) == CALL_RETURN_COPY
    assert len(effect.allocations) == 1
    assert effect.allocations[0].kind is HeapObjectKind.ALLOCATION


def test_heap_effect_models_pop_as_collection_delete_not_value_escape():
    container = py_ast.Local("items")
    key = _existing("payload")
    raw = {id(container): (RawStorage("items"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)
    operation = py_ast.Discard(
        py_ast.MethodCall(container, _existing("pop"), [key], [], None, None)
    )

    effect = builder.operation_effect(
        None,
        operation,
        collection_mutator_names=frozenset({"pop"}),
    )

    assert effect.escapes == ()
    assert heap.dynamic_subscript_location(
        heap.locations_for_local(None, container)[0],
        "['payload']",
    ) in effect.deletes


def test_heap_effect_insert_escapes_inserted_value_not_index():
    container = py_ast.Local("items")
    value = py_ast.Local("value")
    index = _existing(0)
    raw = {
        id(container): (RawStorage("items"),),
        id(value): (RawStorage("value"),),
    }
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)
    operation = py_ast.Discard(
        py_ast.MethodCall(
            container,
            _existing("insert"),
            [index, value],
            [],
            None,
            None,
        )
    )

    effect = builder.operation_effect(
        None,
        operation,
        collection_mutator_names=frozenset({"insert"}),
    )

    assert heap.locations_for_local(None, value)[0] in effect.escapes
    assert all(location.root.label != "0" for location in effect.escapes)


def test_heap_effect_models_deque_appendleft_as_collection_write():
    container = py_ast.Local("items")
    value = py_ast.Local("value")
    raw = {
        id(container): (RawStorage("items"),),
        id(value): (RawStorage("value"),),
    }
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)
    operation = py_ast.Discard(
        py_ast.MethodCall(container, _existing("appendleft"), [value], [], None, None)
    )

    effect = builder.operation_effect(
        None,
        operation,
        collection_mutator_names=frozenset({"appendleft"}),
    )

    assert heap.locations_for_local(None, value)[0] in effect.escapes
    assert any(
        "[*]" in heap.display_label_for_location(w.location) for w in effect.writes
    )


def test_heap_effect_classifies_common_iterator_and_string_returns_as_fresh():
    target = py_ast.Local("target")
    source = py_ast.Local("source")
    heap = HeapAbstraction(lambda _procedure, _local: ())
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    sorted_call = py_ast.Call(py_ast.Local("sorted"), [source], [], None, None)
    split_call = py_ast.MethodCall(source, _existing("split"), [], [], None, None)

    sorted_effect = builder.operation_effect(None, py_ast.Assign(sorted_call, [target]))
    split_effect = builder.operation_effect(None, py_ast.Assign(split_call, [target]))

    assert builder.call_return_kind(sorted_call) == CALL_RETURN_FRESH
    assert builder.call_return_kind(split_call) == CALL_RETURN_FRESH
    assert len(sorted_effect.allocations) == 1
    assert len(split_effect.allocations) == 1


def test_heap_effect_accepts_project_specific_intrinsic_models():
    target = py_ast.Local("target")
    source = py_ast.Local("source")
    container = py_ast.Local("container")
    value = py_ast.Local("value")
    raw = {
        id(container): (RawStorage("container"),),
        id(value): (RawStorage("value"),),
    }
    intrinsics = HeapIntrinsicModels(
        return_kinds={"numpy.array": CALL_RETURN_FRESH},
        collection_mutators={"push": CollectionMutatorModel(writes_value=True)},
    )
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(
        heap,
        heap.locations_for_local,
        intrinsics=intrinsics,
    )
    array_call = py_ast.Call(py_ast.Local("numpy.array"), [source], [], None, None)
    push = py_ast.Discard(
        py_ast.MethodCall(container, _existing("push"), [value], [], None, None)
    )

    array_effect = builder.operation_effect(None, py_ast.Assign(array_call, [target]))
    push_effect = builder.operation_effect(
        None,
        push,
        collection_mutator_names=intrinsics.collection_mutator_names(),
    )

    assert builder.call_return_kind(array_call) == CALL_RETURN_FRESH
    assert len(array_effect.allocations) == 1
    assert heap.locations_for_local(None, value)[0] in push_effect.escapes


def test_heap_effect_extracts_global_read_write_and_delete_locations():
    value = py_ast.Local("value")
    name = _existing("CONFIG")
    raw = {id(value): (RawStorage("value"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    read = builder.operation_effect(None, py_ast.GetGlobal(name))
    write = builder.operation_effect(None, py_ast.SetGlobal(name, value))
    delete = builder.operation_effect(None, py_ast.DeleteGlobal(name))
    global_location = heap.location_for_raw(heap.global_object("CONFIG"))

    assert read.reads == (global_location,)
    assert write.writes[0].location == global_location
    assert heap.locations_for_local(None, value)[0] in write.escapes
    assert delete.deletes == (global_location,)


def test_heap_effect_extracts_cell_read_and_write_locations():
    value = py_ast.Local("value")
    cell = py_ast.Cell("closed")
    raw = {id(value): (RawStorage("value"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    read = builder.operation_effect(None, py_ast.GetCellDeref(cell))
    write = builder.operation_effect(None, py_ast.SetCellDeref(value, cell))
    cell_location = heap.location_for_raw(heap.cell_object("closed"))

    assert read.reads == (cell_location,)
    assert write.writes[0].location == cell_location
    assert heap.locations_for_local(None, value)[0] in write.escapes


def test_heap_effect_extracts_slice_write_locations():
    container = py_ast.Local("lst")
    value = py_ast.Local("value")
    raw = {id(container): (RawStorage("container"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)
    start = _existing(1)
    stop = _existing(3)
    step = _existing(1)

    effect = builder.operation_effect(
        None, py_ast.SetSlice(value, container, start, stop, step)
    )

    assert len(effect.writes) >= 1
    write_locations = {w.location for w in effect.writes}
    assert any(
        "[*]" in heap.display_label_for_location(loc)
        for loc in write_locations
    )


def test_heap_effect_extracts_slice_delete_locations():
    container = py_ast.Local("lst")
    raw = {id(container): (RawStorage("container"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)
    start = _existing(1)
    stop = _existing(3)
    step = _existing(1)

    effect = builder.operation_effect(
        None, py_ast.DeleteSlice(container, start, stop, step)
    )

    assert len(effect.deletes) >= 1


def test_heap_effect_extracts_getiter_read_locations():
    iterable = py_ast.Local("items")
    raw = {id(iterable): (RawStorage("items"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(None, py_ast.GetIter(iterable))

    assert len(effect.reads) == 1


def test_heap_effect_yield_escapes_value():
    value = py_ast.Local("value")
    raw = {id(value): (RawStorage("value"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(None, py_ast.Yield(value))

    assert len(effect.escapes) == 1


def test_heap_effect_yield_with_value_escapes():
    value = py_ast.Local("value")
    raw = {id(value): (RawStorage("value"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(None, py_ast.Yield(value))

    assert len(effect.escapes) == 1


def test_heap_effect_models_raise_exception_payloads_as_escaped():
    exception = py_ast.Local("exception")
    parameter = py_ast.Local("parameter")
    traceback = py_ast.Local("traceback")
    raw = {
        id(exception): (RawStorage("exception"),),
        id(parameter): (RawStorage("parameter"),),
        id(traceback): (RawStorage("traceback"),),
    }
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(
        None,
        py_ast.Raise(exception, parameter, traceback),
    )

    assert set(effect.escapes) == {
        heap.locations_for_local(None, exception)[0],
        heap.locations_for_local(None, parameter)[0],
        heap.locations_for_local(None, traceback)[0],
    }


def test_heap_effect_models_assert_reads_and_message_escape():
    test_value = py_ast.Local("test_value")
    message = py_ast.Local("message")
    raw = {
        id(test_value): (RawStorage("test_value"),),
        id(message): (RawStorage("message"),),
    }
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(None, py_ast.Assert(test_value, message))

    assert set(effect.reads) == {
        heap.locations_for_local(None, test_value)[0],
        heap.locations_for_local(None, message)[0],
    }
    assert effect.escapes == (heap.locations_for_local(None, message)[0],)


def test_heap_effect_records_import_module_object_for_assignment():
    target = py_ast.Local("module")
    heap = HeapAbstraction(lambda _procedure, _local: ())
    builder = HeapEffectBuilder(heap, heap.locations_for_local)

    effect = builder.operation_effect(
        None,
        py_ast.Assign(py_ast.Import("json", [], 0), [target]),
    )

    assert len(effect.allocations) == 1
    assert effect.allocations[0].kind is HeapObjectKind.GLOBAL
    assert effect.allocations[0].type_hint == "module"
