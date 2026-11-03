"""Dependence paths must follow CFG branches and back-edges, not line order."""

from pyflow.ir.cfg import graph
from pyflow.ir.dataflow import convert, graph as dataflow_graph
from pyflow.ir.ddg import construct_ddg
from pyflow.ir.ddg.cfg_construction import CFGOperation
from pyflow.ir.core.source import syntax_source_span
from pyflow.language.python import ast

from tests.ir.cfg.test_reported_semantics import lower
from tests.ir.ddg.test_construction_and_dump import _lower_ddg, _memory_edges_by_line


def value_edges(ddg):
    result = set()
    for producer in ddg.nodes:
        if producer.category != "op":
            continue
        source = syntax_source_span(getattr(producer.ir_node, "op", None))
        if source is None:
            continue
        for definition in producer.edges_out:
            if definition.kind != "def-use" or definition.target.category != "slot":
                continue
            for use in definition.target.edges_out:
                target = syntax_source_span(getattr(use.target.ir_node, "op", None))
                if target is not None:
                    result.add((source.start_line, target.start_line, use.label))
    return result


def test_accumulator_has_initial_and_loop_carried_def_use():
    ddg = _lower_ddg("def f(flag):\n    x = 0\n    while flag:\n        x = x + 1\n    return x\n")
    edges = value_edges(ddg)
    assert (2, 4, "x") in edges
    assert (4, 4, "x") in edges
    assert (4, 5, "x") in edges


def test_pointer_traversal_links_back_to_next_iteration_sink():
    ddg = _lower_ddg(
        "def f(node, sink):\n    curr = node\n    while curr:\n        sink(curr.val)\n        curr = curr.next\n    return curr\n"
    )
    edges = value_edges(ddg)
    assert (5, 4, "curr") in edges
    conditions = [
        node
        for node in ddg.nodes
        if isinstance(getattr(node.ir_node, "cfg_block", None), graph.Switch)
    ]
    assert any(
        syntax_source_span(getattr(definition.source.ir_node, "op", None)).start_line == 5
        for condition in conditions
        for use in condition.edges_in
        if use.source.category == "slot"
        for definition in use.source.edges_in
        if syntax_source_span(getattr(definition.source.ir_node, "op", None)) is not None
    )


def test_mutually_exclusive_calls_and_operators_are_unordered():
    for body in (
        "        f()\n    else:\n        g()\n",
        "        c = a + b\n    else:\n        c = a - b\n",
    ):
        ddg = _lower_ddg("def f(flag, a, b, g):\n    if flag:\n" + body)
        edges = _memory_edges_by_line(ddg)
        assert ("EXTERNAL", 3, 5) not in edges
        assert ("EXTERNAL", 5, 3) not in edges


def test_branch_write_does_not_reach_else_read_but_reaches_join_read():
    branch = _lower_ddg(
        "def f(flag, obj):\n    if flag:\n        obj.x = 1\n    else:\n        return obj.x\n    return 0\n"
    )
    assert ("RAW", 3, 5) not in _memory_edges_by_line(branch)
    joined = _lower_ddg("def f(flag, obj):\n    if flag:\n        obj.x = 1\n    return obj.x\n")
    assert ("RAW", 3, 4) in _memory_edges_by_line(joined)


def test_loop_memory_hazards_include_reverse_line_order_and_self_edges():
    ddg = _lower_ddg(
        "def f(flag, obj):\n    while flag:\n        value = obj.x\n        obj.x = value + 1\n"
    )
    edges = _memory_edges_by_line(ddg)
    assert ("RAW", 4, 3) in edges
    assert ("WAW", 4, 4) in edges
    assert ("WAR", 3, 4) in edges


def test_single_loop_store_has_loop_carried_waw():
    ddg = _lower_ddg("def f(items, obj):\n    for item in items:\n        obj.x = 1\n")
    assert ("WAW", 3, 3) in _memory_edges_by_line(ddg)


def test_zero_iteration_loop_keeps_parameter_binding():
    code, cfg = lower("def f(items, x):\n    for x in items:\n        pass\n    return x\n")
    ddg = construct_ddg(cfg)
    returned = next(
        node for node in ddg.nodes if isinstance(getattr(node.ir_node, "op", None), ast.Return)
    )
    producers = {
        definition.source.ir_node
        for use in returned.edges_in
        if use.source.category == "slot"
        for definition in use.source.edges_in
    }
    assert any(isinstance(producer, dataflow_graph.Entry) for producer in producers)
    assert any(
        isinstance(producer, CFGOperation) and producer.phase == "index" for producer in producers
    )


def test_dataflow_conversion_retains_cfg_snapshot_for_ddg():
    code, cfg = lower("def f(flag):\n    x = 0\n    while flag:\n        x = x + 1\n    return x\n")
    dataflow = convert.evaluateCode(None, code)
    assert dataflow.control_flow is not None
    # The snapshot survives a caller replacing the source AST after lowering.
    code.ast = ast.Suite([])
    ddg = construct_ddg(dataflow)
    assert any(isinstance(getattr(node.ir_node, "op", None), ast.Assign) for node in ddg.nodes)


def test_global_heap_slots_can_be_rendered():
    ddg = _lower_ddg("def f():\n    global cache\n    cache = 1\n    return cache\n")
    text = "\n".join(repr(node.ir_node) for node in ddg.nodes)
    assert "'global'" in text
    assert "cache" in text
