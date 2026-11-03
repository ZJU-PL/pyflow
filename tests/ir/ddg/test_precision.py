"""Precision assumptions and per-binding dependencies from repository audits."""

import pytest

from pyflow.ir.ddg import construct_ddg, DDGConstructionOptions
from pyflow.ir.dataflow import graph as df

from tests.ir.cfg.test_reported_semantics import lower
from tests.ir.ddg.test_construction_and_dump import _memory_edges_by_line

CONSERVATIVE = DDGConstructionOptions(False, False)


def ddg_for(source, options=DDGConstructionOptions()):
    _, cfg = lower(source)
    return construct_ddg(cfg, options=options)


def test_primitive_math_has_no_external_ordering_by_default():
    source = "def f(a,b,c):\n    x=a+b\n    y=b*c\n    z=a<c\n    return x\n"
    assert not _memory_edges_by_line(ddg_for(source))
    edges = _memory_edges_by_line(ddg_for(source, CONSERVATIVE))
    assert ("EXTERNAL", 2, 3) in edges
    assert ("EXTERNAL", 3, 4) in edges


def test_bounded_intrinsic_keeps_nested_ordinary_call_effects():
    graph = ddg_for("def f(a, callback, other):\n    x=callback()+a\n    other()\n    return x\n")
    assert ("EXTERNAL", 2, 3) in _memory_edges_by_line(graph)


def test_getitem_keeps_subscript_hazards_without_unknown_heap_effects():
    graph = ddg_for("def f(items):\n    value=items[0]\n    items[0]=2\n    return value\n")
    edges = _memory_edges_by_line(graph)
    assert ("WAR", 2, 3) in edges
    assert not any(label == "EXTERNAL" for label, _, _ in edges)


def test_isinstance_assumption_does_not_apply_to_a_local_callable():
    builtin = ddg_for("def f(x):\n    a=isinstance(x,int)\n    b=x+1\n    return a,b\n")
    assert not any(label == "EXTERNAL" for label, _, _ in _memory_edges_by_line(builtin))
    shadowed = ddg_for(
        "def f(isinstance,x,other):\n    a=isinstance(x,int)\n    other()\n    return a\n"
    )
    assert ("EXTERNAL", 2, 3) in _memory_edges_by_line(shadowed)


@pytest.mark.parametrize(
    "expression,bindings", [("callback(x:=1,x)", 1), ("callback((x:=1),x,(x:=2),x)", 2)]
)
def test_walrus_use_has_an_explicit_intra_statement_definition(expression, bindings):
    graph = ddg_for(f"def f(callback):\n    {expression}\n")
    local_slots = [
        node
        for node in graph.nodes
        if isinstance(node.ir_node, df.LocalNode)
        and any(local.name == "x" for local in node.ir_node.names)
    ]
    assert len(local_slots) == bindings
    for slot in local_slots:
        producers = {edge.source for edge in slot.edges_in}
        assert any(edge.target in producers and edge.label == "x" for edge in slot.edges_out)


def test_walrus_self_update_retains_both_incoming_and_internal_uses():
    graph = ddg_for("def f(x):\n    y=(x:=x+1)+x\n    return y\n")
    entry = next(node for node in graph.nodes if isinstance(node.ir_node, df.Entry))
    incoming = [edge.target for edge in entry.edges_out if edge.label == "x"]
    assert any(slot.edges_out for slot in incoming)
    assert any(
        any(use.target is definition.source for use in node.edges_out)
        for node in graph.nodes
        if isinstance(node.ir_node, df.LocalNode)
        and any(local.name == "x" for local in node.ir_node.names)
        for definition in node.edges_in
    )


def test_alias_reassignment_does_not_retarget_captured_copies():
    source = "def f(obj1,obj2):\n    a=obj1\n    b=a\n    b.x=1\n    a=obj2\n    c=a\n    r=c.x\n    return r\n"
    assert ("RAW", 4, 7) not in _memory_edges_by_line(ddg_for(source))
    assert ("RAW", 4, 7) in _memory_edges_by_line(ddg_for(source, CONSERVATIVE))
    captured = "def f(obj1,obj2):\n    a=obj1\n    b=a\n    b.x=1\n    a=obj2\n    return b.x\n"
    assert ("RAW", 4, 6) in _memory_edges_by_line(ddg_for(captured))


def test_distinct_parameters_do_not_form_a_waw_clique():
    source = "def f(user,config,logger,db):\n    user.name='Alice'\n    config.name='prod'\n    logger.name='root'\n    db.name='db'\n    return user.name\n"
    edges = _memory_edges_by_line(ddg_for(source))
    assert ("RAW", 2, 6) in edges
    assert not any(label == "WAW" for label, _, _ in edges)
    assert not any(label == "RAW" and source != 2 for label, source, _ in edges)
    assert ("RAW", 5, 6) in _memory_edges_by_line(ddg_for(source, CONSERVATIVE))


def test_alias_join_keeps_all_reaching_objects():
    source = "def f(flag,left,right):\n    left.x=1\n    right.x=2\n    a=left\n    if flag:\n        a=right\n    return a.x\n"
    edges = _memory_edges_by_line(ddg_for(source))
    assert ("RAW", 2, 7) in edges
    assert ("RAW", 3, 7) in edges


def test_reusing_a_name_for_a_fresh_allocation_does_not_merge_objects():
    source = "def f():\n    a=[0]\n    b=a\n    a=[0]\n    b[0]=1\n    return a[0]\n"
    assert ("RAW", 5, 6) not in _memory_edges_by_line(ddg_for(source))
