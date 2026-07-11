"""Tests for PointsToGraph extraction and query API."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.heap import (
    HeapAbstraction,
    HeapPolicy,
    HeapSelector,
    UpdatePolicy,
    PointsToEntry,
    PointsToGraph,
)
from pyflow.language.python import ast as py_ast


@dataclass(frozen=True, eq=False)
class RawStorage:
    label: str


def _heap():
    return HeapAbstraction(lambda _p, _l: ())


def _build_graph_with_two_objects():
    heap = HeapAbstraction(lambda _p, _l: ())
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    heap.bind_allocation_targets(None, (a,), object(), label="first")
    heap.bind_allocation_targets(None, (b,), object(), label="second")
    return heap.to_points_to_graph()


# ── PointsToEntry ──────────────────────────────────────────────────────


def test_entry_has_label_and_aliases():
    graph = _build_graph_with_two_objects()
    for entry in graph.iter_entries():
        assert isinstance(entry.label, str)
        assert len(entry.aliases) >= 1
        assert entry.location in entry.aliases


def test_entry_ref_count_defaults_to_one_for_single_binding():
    heap = _heap()
    x = py_ast.Local("x")
    heap.bind_allocation_targets(None, (x,), object(), label="solo")
    graph = heap.to_points_to_graph()
    for entry in graph.iter_entries():
        assert entry.ref_count == 1


def test_entry_is_singleton_for_fresh_local_object():
    heap = _heap()
    x = py_ast.Local("x")
    heap.bind_allocation_targets(None, (x,), object(), label="obj")
    graph = heap.to_points_to_graph()
    for entry in graph.iter_entries():
        assert entry.is_singleton
        assert not entry.is_escaped


def test_entry_is_strong_for_singleton_root():
    heap = _heap()
    x = py_ast.Local("x")
    heap.bind_allocation_targets(None, (x,), object(), label="obj")
    graph = heap.to_points_to_graph()
    for entry in graph.iter_entries():
        assert entry.is_strong
        assert entry.update_policy is UpdatePolicy.STRONG


# ── PointsToGraph queries ──────────────────────────────────────────────


def test_points_to_returns_self():
    graph = _build_graph_with_two_objects()
    for entry in graph.iter_entries():
        result = graph.points_to(entry.location)
        assert entry.location in result


def test_points_to_for_nested_location_returns_root_aliases():
    heap = _heap()
    x = py_ast.Local("x")
    heap.bind_allocation_targets(None, (x,), object(), label="obj")
    graph = heap.to_points_to_graph()
    root = next(iter(graph.entries))
    nested = root.field("payload")
    aliased = graph.points_to(nested)
    assert root in aliased


def test_never_escapes_for_fresh_object():
    heap = _heap()
    x = py_ast.Local("x")
    heap.bind_allocation_targets(None, (x,), object(), label="obj")
    graph = heap.to_points_to_graph()
    loc = next(iter(graph.entries))
    assert graph.never_escapes(loc)


def test_is_escaped_after_mark():
    heap = HeapAbstraction(lambda _p, _l: (), policy=HeapPolicy(track_escapes=True))
    x = py_ast.Local("x")
    heap.bind_allocation_targets(None, (x,), object(), label="obj")
    heap.mark_escaped(heap.locations_for_local(None, x)[0])
    graph = heap.to_points_to_graph()
    for entry in graph.iter_entries():
        assert entry.is_escaped
        assert graph.is_escaped(entry.location)
        assert not graph.never_escapes(entry.location)


def test_single_reference_after_alias_is_false():
    heap = _heap()
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    heap.bind_allocation_targets(None, (a,), object(), label="obj")
    heap.alias_locals(None, b, a)
    graph = heap.to_points_to_graph()
    for entry in graph.iter_entries():
        assert not graph.single_reference(entry.location)
        assert entry.ref_count > 1


def test_strong_update_possible_after_alias_is_false():
    heap = _heap()
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    heap.bind_allocation_targets(None, (a,), object(), label="obj")
    heap.alias_locals(None, b, a)
    graph = heap.to_points_to_graph()
    for entry in graph.iter_entries():
        assert not graph.strong_update_possible(entry.location)


def test_aliased_two_unrelated_objects():
    graph = _build_graph_with_two_objects()
    entries = list(graph.iter_entries())
    if len(entries) >= 2:
        assert not graph.aliased(entries[0].location, entries[1].location)


def test_aliased_same_object():
    graph = _build_graph_with_two_objects()
    entries = list(graph.iter_entries())
    assert graph.aliased(entries[0].location, entries[0].location)


def test_aliased_after_alias_locals():
    heap = _heap()
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    heap.bind_allocation_targets(None, (a,), object(), label="obj")
    heap.alias_locals(None, b, a)
    graph = heap.to_points_to_graph()
    loc_a = heap.locations_for_local(None, a)[0]
    loc_b = heap.locations_for_local(None, b)[0]
    assert graph.aliased(loc_a, loc_b)


def test_may_alias_for_aliased_pair_is_true():
    heap = _heap()
    a = py_ast.Local("a")
    b = py_ast.Local("b")
    heap.bind_allocation_targets(None, (a,), object(), label="obj")
    heap.alias_locals(None, b, a)
    graph = heap.to_points_to_graph()
    loc_a = heap.locations_for_local(None, a)[0]
    loc_b = heap.locations_for_local(None, b)[0]
    assert graph.may_alias(loc_a, loc_b)


def test_may_alias_for_unrelated_is_false():
    graph = _build_graph_with_two_objects()
    entries = list(graph.iter_entries())
    if len(entries) >= 2:
        assert not graph.may_alias(entries[0].location, entries[1].location)


def test_may_alias_for_unknown_is_true():
    graph = _build_graph_with_two_objects()
    from pyflow.analysis.heap import HeapLocation, HeapObject, HeapObjectKind

    unknown = HeapLocation(
        HeapObject(HeapObjectKind.UNKNOWN, "unknown", "unknown")
    )
    entries = list(graph.iter_entries())
    assert graph.may_alias(unknown, entries[0].location)


def test_escaped_locations_singleton_locations():
    heap = HeapAbstraction(lambda _p, _l: (), policy=HeapPolicy(track_escapes=True))
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    heap.bind_allocation_targets(None, (x,), object(), label="escaped")
    heap.bind_allocation_targets(None, (y,), object(), label="local")
    heap.mark_escaped(heap.locations_for_local(None, x)[0])
    graph = heap.to_points_to_graph()
    assert len(graph.escaped_locations()) == 1
    assert len(graph.singleton_locations()) == 1


def test_graph_len_and_bool():
    graph = _build_graph_with_two_objects()
    assert len(graph) == 2
    assert bool(graph)


def test_empty_graph():
    heap = _heap()
    graph = heap.to_points_to_graph()
    assert len(graph) == 0
    assert not bool(graph)


def test_to_dict():
    graph = _build_graph_with_two_objects()
    d = graph.to_dict()
    assert d["entry_count"] == 2
    assert "entries" in d


def test_entry_to_dict():
    graph = _build_graph_with_two_objects()
    for entry in graph.iter_entries():
        d = entry.to_dict()
        assert "label" in d
        assert "alias_count" in d
        assert "update_policy" in d


# ── edge cases ─────────────────────────────────────────────────────────


def test_never_escapes_for_unknown_location():
    graph = _build_graph_with_two_objects()
    from pyflow.analysis.heap import HeapLocation, HeapObject, HeapObjectKind

    unknown = HeapLocation(
        HeapObject(HeapObjectKind.UNKNOWN, "unknown", "unknown")
    )
    assert graph.never_escapes(unknown)


def test_single_reference_for_unknown_location():
    graph = _build_graph_with_two_objects()
    from pyflow.analysis.heap import HeapLocation, HeapObject, HeapObjectKind

    unknown = HeapLocation(
        HeapObject(HeapObjectKind.UNKNOWN, "unknown", "unknown")
    )
    assert graph.single_reference(unknown)


def test_points_to_for_unknown_location_returns_self():
    graph = _build_graph_with_two_objects()
    from pyflow.analysis.heap import HeapLocation, HeapObject, HeapObjectKind

    unknown = HeapLocation(
        HeapObject(HeapObjectKind.UNKNOWN, "unknown", "unknown")
    )
    result = graph.points_to(unknown)
    assert unknown in result


def test_get_returns_none_for_unknown():
    graph = _build_graph_with_two_objects()
    from pyflow.analysis.heap import HeapLocation, HeapObject, HeapObjectKind

    unknown = HeapLocation(
        HeapObject(HeapObjectKind.UNKNOWN, "unknown", "unknown")
    )
    assert graph.get(unknown) is None
