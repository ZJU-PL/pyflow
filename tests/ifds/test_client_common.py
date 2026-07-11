from __future__ import annotations

from pyflow.analysis.ifds.clients._client_common import (
    DynamicAttributeSlot,
    DynamicSubscriptSlot,
    build_entry_seeds,
)


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


def test_dynamic_attribute_slot_creation():
    slot = DynamicAttributeSlot("obj", "attr")
    assert slot.base == "obj"
    assert slot.attribute == "attr"


def test_dynamic_attribute_slot_equality():
    a = DynamicAttributeSlot("x", "y")
    b = DynamicAttributeSlot("x", "y")
    c = DynamicAttributeSlot("x", "z")
    assert a == b
    assert a != c
    assert hash(a) == hash(b)


def test_dynamic_subscript_slot_creation():
    slot = DynamicSubscriptSlot("base", "[*]")
    assert slot.base == "base"
    assert slot.subscript == "[*]"


def test_dynamic_subscript_slot_equality():
    a = DynamicSubscriptSlot("x", "[0]")
    b = DynamicSubscriptSlot("x", "[0]")
    c = DynamicSubscriptSlot("x", "[1]")
    assert a == b
    assert a != c
    assert hash(a) == hash(b)


def test_dynamic_attribute_wildcard():
    slot = DynamicAttributeSlot("obj", "*")
    assert slot.attribute == "*"


def test_dynamic_subscript_wildcard():
    slot = DynamicSubscriptSlot("obj", "[*]")
    assert slot.subscript == "[*]"
