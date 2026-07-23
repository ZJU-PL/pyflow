from __future__ import annotations

from pyflow.analysis.ifds.analyses.base import build_entry_seeds
from pyflow.analysis.alias.flow_sensitive import HeapAbstraction, HeapSelector


def test_build_entry_seeds_single_node():
    from pyflow.analysis.ifds import CFGNode

    node = CFGNode(None, None, "entry")
    seeds = build_entry_seeds([node], "ZERO")
    assert node in seeds
    assert seeds[node] == frozenset({"ZERO"})


def test_build_entry_seeds_multiple_nodes():
    from pyflow.analysis.ifds import CFGNode

    n1 = CFGNode(None, None, "entry")
    n2 = CFGNode(None, None, "exit")
    seeds = build_entry_seeds([n1, n2], "Z")
    assert len(seeds) == 2
    assert seeds[n1] == frozenset({"Z"})
    assert seeds[n2] == frozenset({"Z"})


def test_dynamic_attribute_location_creation():
    heap = HeapAbstraction(lambda _procedure, _local: ())
    location = heap.dynamic_attribute_location("obj", "attr")
    assert location.root.label == "'obj'"
    assert location.selectors == (HeapSelector.field("attr"),)


def test_dynamic_attribute_location_equality():
    heap = HeapAbstraction(lambda _procedure, _local: ())
    a = heap.dynamic_attribute_location("x", "y")
    b = heap.dynamic_attribute_location("x", "y")
    c = heap.dynamic_attribute_location("x", "z")
    assert a == b
    assert a != c
    assert hash(a) == hash(b)


def test_dynamic_subscript_location_creation():
    heap = HeapAbstraction(lambda _procedure, _local: ())
    location = heap.dynamic_subscript_location("base", "[*]")
    assert location.root.label == "'base'"
    assert location.selectors == (HeapSelector.unknown_element(),)


def test_dynamic_subscript_location_equality():
    heap = HeapAbstraction(lambda _procedure, _local: ())
    a = heap.dynamic_subscript_location("x", "[0]")
    b = heap.dynamic_subscript_location("x", "[0]")
    c = heap.dynamic_subscript_location("x", "[1]")
    assert a == b
    assert a != c
    assert hash(a) == hash(b)


def test_dynamic_attribute_wildcard():
    heap = HeapAbstraction(lambda _procedure, _local: ())
    location = heap.dynamic_attribute_location("obj", "*")
    assert location.selectors == (HeapSelector.unknown_field(),)


def test_dynamic_subscript_wildcard():
    heap = HeapAbstraction(lambda _procedure, _local: ())
    location = heap.dynamic_subscript_location("obj", "[*]")
    assert location.selectors == (HeapSelector.unknown_element(),)
