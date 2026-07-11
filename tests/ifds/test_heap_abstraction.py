"""Tests for the explicit IFDS heap abstraction layer."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.ifds.heap import (
    AllocationSensitivity,
    ContainerSensitivity,
    FieldSensitivity,
    HeapAbstraction,
    HeapEscapeState,
    HeapLocation,
    HeapObjectFreshness,
    HeapObjectKind,
    HeapPolicy,
    HeapSelector,
    UpdatePolicy,
)
from pyflow.language.python import ast as py_ast


@dataclass(frozen=True, eq=False)
class RawStorage:
    label: str


@dataclass(frozen=True)
class LocationFact:
    location: object
    access_path: tuple[str, ...] = ()


def test_heap_abstraction_aliases_direct_local_assignments():
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    raw = {id(x): (RawStorage("x"),), id(y): (RawStorage("y"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw[id(local)])

    heap.alias_locals(None, y, x)

    assert heap.locations_for_local(None, y) == heap.locations_for_local(None, x)
    assert heap.allocation_sites[(id(None), id(y))] == heap.allocation_sites[
        (id(None), id(x))
    ]


def test_heap_abstraction_strong_update_breaks_local_alias():
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    raw = {id(x): (RawStorage("x"),), id(y): (RawStorage("y"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw[id(local)])

    heap.alias_locals(None, y, x)
    old_site = heap.allocation_sites[(id(None), id(y))]
    heap.unalias_local(None, y)

    assert tuple(location.root.label for location in heap.locations_for_local(None, y)) == (
        "y",
    )
    assert heap.allocation_sites[(id(None), id(y))] != old_site


def test_heap_abstraction_matches_location_access_path_prefixes():
    location = RawStorage("obj")

    assert HeapAbstraction.access_path_prefix_matches(
        LocationFact(location, ("payload",)),
        LocationFact(location, ("payload", "value")),
    )
    assert not HeapAbstraction.access_path_prefix_matches(
        LocationFact(location, ("payload", "value")),
        LocationFact(location, ("payload",)),
    )


def test_dynamic_heap_locations_are_structural():
    base = RawStorage("obj")
    heap = HeapAbstraction(lambda _procedure, _local: ())

    assert heap.dynamic_attribute_location(base, "payload") == (
        heap.dynamic_attribute_location(base, "payload")
    )
    assert heap.dynamic_subscript_location(base, "[*]") == (
        heap.dynamic_subscript_location(base, "[*]")
    )


def test_heap_abstraction_canonicalizes_dynamic_attribute_locations():
    base = RawStorage("obj")
    heap = HeapAbstraction(lambda _procedure, _local: ())
    location = heap.dynamic_attribute_location(base, "payload")

    assert isinstance(location, HeapLocation)
    assert location.root.label == "obj"
    assert location.selectors == (HeapSelector.field("payload"),)


def test_heap_abstraction_canonicalizes_dynamic_subscript_locations():
    base = RawStorage("items")
    heap = HeapAbstraction(lambda _procedure, _local: ())
    location = heap.dynamic_subscript_location(base, "[*]")

    assert location.root.label == "items"
    assert location.selectors == (HeapSelector.unknown_element(),)


def test_heap_abstraction_write_policy_is_weak_for_nested_locations():
    base = RawStorage("obj")
    heap = HeapAbstraction(lambda _procedure, _local: ())

    root_write = heap.write_for_location(heap.location_for_raw(base))
    field_write = heap.write_for_location(
        heap.dynamic_attribute_location(base, "payload")
    )

    assert root_write.policy is UpdatePolicy.STRONG
    assert field_write.policy is UpdatePolicy.WEAK


def test_heap_abstraction_matches_canonical_location_prefixes():
    base = RawStorage("obj")
    heap = HeapAbstraction(lambda _procedure, _local: ())
    payload = heap.dynamic_attribute_location(base, "payload")
    nested = payload.field("value")

    assert HeapAbstraction.access_path_prefix_matches(
        LocationFact(payload),
        LocationFact(nested),
    )


def test_heap_abstraction_classifies_raw_storage_roots():
    raw = RawStorage("value")
    heap = HeapAbstraction(lambda _procedure, _local: ())
    location = heap.location_for_raw(raw)

    assert location.root.kind is HeapObjectKind.STORAGE
    assert location.root.label == "value"
    assert location.root.freshness is HeapObjectFreshness.FRESH
    assert location.root.escape is HeapEscapeState.LOCAL


def test_heap_abstraction_binds_allocation_targets_to_site_objects():
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    site = object()
    heap = HeapAbstraction(lambda _procedure, _local: ())

    heap.bind_allocation_targets(None, (x, y), site, label="list literal")

    x_location = heap.locations_for_local(None, x)[0]
    y_location = heap.locations_for_local(None, y)[0]
    assert x_location == y_location
    assert x_location.root.kind is HeapObjectKind.ALLOCATION
    assert x_location.root.label == "list literal"
    assert x_location.root.allocation_site == ("allocation", id(site))


def test_heap_abstraction_distinguishes_allocation_sites_by_default():
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    heap = HeapAbstraction(lambda _procedure, _local: ())
    first_site = object()
    second_site = object()

    heap.bind_allocation_targets(None, (x,), first_site, label="list literal")
    heap.bind_allocation_targets(None, (y,), second_site, label="list literal")

    assert heap.locations_for_local(None, x) != heap.locations_for_local(None, y)


def test_heap_abstraction_can_collapse_allocation_sites_by_policy():
    x = py_ast.Local("x")
    y = py_ast.Local("y")
    heap = HeapAbstraction(
        lambda _procedure, _local: (),
        policy=HeapPolicy(allocation_sensitivity=AllocationSensitivity.NONE),
    )

    heap.bind_allocation_targets(None, (x,), object(), label="list literal")
    heap.bind_allocation_targets(None, (y,), object(), label="list literal")

    assert heap.locations_for_local(None, x) == heap.locations_for_local(None, y)


def test_heap_abstraction_binds_call_result_targets():
    x = py_ast.Local("x")
    call_site = object()
    heap = HeapAbstraction(lambda _procedure, _local: ())

    heap.bind_call_result_targets(None, (x,), call_site, label="factory()")

    location = heap.locations_for_local(None, x)[0]
    assert location.root.kind is HeapObjectKind.CALL_RESULT
    assert location.root.label == "factory()"
    assert location.root.escape is HeapEscapeState.UNKNOWN


def test_heap_abstraction_binds_summary_targets_as_weak_objects():
    x = py_ast.Local("x")
    heap = HeapAbstraction(lambda _procedure, _local: ())

    heap.bind_summary_targets(None, (x,), "library", label="library()")

    location = heap.locations_for_local(None, x)[0]
    assert location.root.kind is HeapObjectKind.SUMMARY
    assert location.root.label == "library()"
    assert heap.update_policy_for_location(location) is UpdatePolicy.WEAK


def test_heap_abstraction_binds_formals_to_actual_locations():
    actual = py_ast.Local("actual")
    formal = py_ast.Local("formal")
    raw = {id(formal): (RawStorage("formal raw"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))
    heap.bind_allocation_targets(None, (actual,), object(), label="fresh object")

    heap.bind_parameter(None, formal, 0, heap.locations_for_local(None, actual))

    formal_locations = heap.locations_for_local(None, formal)
    assert formal_locations[0] == heap.locations_for_local(None, actual)[0]
    assert formal_locations[0].root.kind is HeapObjectKind.ALLOCATION
    assert formal_locations[1].root.kind is HeapObjectKind.STORAGE


def test_heap_abstraction_binds_unknown_formals_to_parameter_objects():
    formal = py_ast.Local("formal")
    raw = {id(formal): (RawStorage("formal raw"),)}
    heap = HeapAbstraction(lambda _procedure, local: raw.get(id(local), ()))

    heap.bind_parameter(None, formal, 2, ())

    formal_locations = heap.locations_for_local(None, formal)
    assert formal_locations[0].root.kind is HeapObjectKind.PARAMETER
    assert formal_locations[0].root.label == "formal"
    assert formal_locations[1].root.kind is HeapObjectKind.STORAGE


def test_heap_abstraction_exposes_global_cell_and_module_roots():
    heap = HeapAbstraction(lambda _procedure, _local: ())

    global_location = heap.location_for_raw(heap.global_object("CONFIG"))
    cell_location = heap.location_for_raw(heap.cell_object("closed_over"))
    module_location = heap.location_for_raw(heap.module_object("pkg.mod"))

    assert global_location.root.kind is HeapObjectKind.GLOBAL
    assert global_location.root.label == "CONFIG"
    assert global_location.root.escape is HeapEscapeState.EXTERNAL
    assert cell_location.root.kind is HeapObjectKind.CELL
    assert cell_location.root.escape is HeapEscapeState.UNKNOWN
    assert module_location.root.kind is HeapObjectKind.GLOBAL
    assert module_location.root.type_hint == "module"


def test_heap_policy_enables_fixed_escape_knobs_by_default():
    policy = HeapPolicy()

    assert policy.track_escapes
    assert policy.escape_on_unresolved_call
    assert policy.escape_on_return


def test_heap_abstraction_field_policy_can_collapse_fields():
    base = RawStorage("obj")
    heap = HeapAbstraction(
        lambda _procedure, _local: (),
        policy=HeapPolicy(field_sensitivity=FieldSensitivity.NONE),
    )

    assert heap.dynamic_attribute_location(base, "a") == (
        heap.dynamic_attribute_location(base, "b")
    )


def test_heap_abstraction_literal_key_container_selectors():
    base = RawStorage("items")
    heap = HeapAbstraction(lambda _procedure, _local: ())

    exact = heap.dynamic_subscript_location(base, "['safe']")
    wildcard = heap.dynamic_subscript_location(base, "[*]")

    assert exact.selectors == (HeapSelector.key("safe"),)
    assert wildcard.selectors == (HeapSelector.unknown_element(),)


def test_heap_abstraction_bounded_index_container_selectors():
    base = RawStorage("items")
    heap = HeapAbstraction(
        lambda _procedure, _local: (),
        policy=HeapPolicy(container_sensitivity=ContainerSensitivity.BOUNDED_INDICES),
    )

    exact = heap.dynamic_subscript_location(base, "[0]")
    wide = heap.dynamic_subscript_location(base, "[99]")

    assert exact.selectors == (HeapSelector.index(0),)
    assert wide.selectors == (HeapSelector.key("99"),)


def test_heap_abstraction_strong_update_for_precise_fresh_nested_location():
    heap = HeapAbstraction(
        lambda _procedure, _local: (),
        policy=HeapPolicy(allow_strong_nested_fresh=True),
    )
    obj = heap.allocation_object(None, object(), label="object")
    field = heap.dynamic_attribute_location(obj, "payload")

    assert heap.update_policy_for_location(field) is UpdatePolicy.STRONG


def test_heap_abstraction_weak_update_for_summary_or_imprecise_locations():
    heap = HeapAbstraction(
        lambda _procedure, _local: (),
        policy=HeapPolicy(allow_strong_nested_fresh=True),
    )
    summary = heap.summary_object("lib", label="library object")
    summary_field = heap.dynamic_attribute_location(summary, "payload")
    imprecise = heap.dynamic_subscript_location(
        heap.allocation_object(None, object(), label="list"),
        "[*]",
    )

    assert heap.update_policy_for_location(summary_field) is UpdatePolicy.WEAK
    assert heap.update_policy_for_location(imprecise) is UpdatePolicy.WEAK


def test_heap_abstraction_escaped_fresh_object_uses_weak_updates():
    heap = HeapAbstraction(
        lambda _procedure, _local: (),
        policy=HeapPolicy(allow_strong_nested_fresh=True),
    )
    obj = heap.allocation_object(None, object(), label="object")
    field = heap.dynamic_attribute_location(obj, "payload")

    assert heap.update_policy_for_location(field) is UpdatePolicy.STRONG
    heap.mark_escaped(field)
    assert heap.update_policy_for_location(field) is UpdatePolicy.WEAK
