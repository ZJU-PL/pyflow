"""Regression coverage for nested-code IR/CPG generation."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pyflow.application.context import CompilerContext
from pyflow.application.cpg import build_cpg
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cpg import CPGEdgeKind
from pyflow.ir.core.source import syntax_source_span
from pyflow.ir.dataflow import convert
from pyflow.ir.ddg import construct_ddg
from pyflow.ir.ddg.dump import DDGDumper


def _extract(source: str, filename: str = "<nested-test>"):
    compiler = CompilerContext(None)
    compiler.extractor = Extractor(compiler, verbose=False)
    program = compiler.extractor.extract_from_source(source, filename=filename)
    return compiler, program


def _lower_ddg(source: str, function: str):
    compiler, program = _extract(source)
    code = next(code for code in program.liveCode if code.codeName() == function)
    return construct_ddg(convert.evaluateCode(compiler, code))


def _edges_with_lines(ddg):
    edges = set()
    for node in ddg.nodes:
        for edge in node.edges_out:
            source_span = syntax_source_span(getattr(edge.source.ir_node, "op", None))
            target_span = syntax_source_span(getattr(edge.target.ir_node, "op", None))
            if source_span is None or target_span is None:
                continue
            edges.add((edge.kind, edge.label, source_span.start_line, target_span.start_line))
    return edges


class TestNestedCodeExtraction:
    def test_nested_functions_lambdas_and_comprehensions_are_registered(self):
        source = """
def outer(a):
    def inner(b):
        return a + b
    xs = [x * a for x in a]
    ys = {x for x in a}
    zs = {x: a for x in a}
    gs = list(x + a for x in a)
    fn = lambda y: y + a
    return inner(1) + xs[0] + len(ys) + len(zs) + gs[0] + fn(2)
"""
        _, program = _extract(source)
        names = {code.codeName() for code in program.liveCode}
        assert "outer" in names
        assert any(name.endswith(".inner") for name in names)
        assert any("<listcomp>" in name for name in names)
        assert any("<setcomp>" in name for name in names)
        assert any("<dictcomp>" in name for name in names)
        assert any("<genexpr>" in name for name in names)
        assert any("<lambda" in name for name in names)

    def test_default_argument_lambdas_and_comprehensions_are_registered(self):
        source = """
def f(cb=lambda x: x + 1, fs=[x for x in range(3)]):
    return cb
"""
        _, program = _extract(source)
        names = {code.codeName() for code in program.liveCode}
        assert "f" in names
        assert any("<lambda" in name for name in names)
        assert any("<listcomp>" in name for name in names)

    def test_nested_codes_are_not_top_level_entry_points(self):
        source = """
def outer(a):
    def inner(b):
        return a + b
    return [x + a for x in a] + [inner(1)]
"""
        compiler, program = _extract(source)
        from pyflow.application.program import Program
        from pyflow.frontend.extractor import extract_program

        compiler.extractor.source_code = source
        target = Program()
        extract_program(compiler, target)
        entry_codes = {entry.code.codeName() for entry in target.entryPoints}
        assert len(entry_codes) == 1
        assert not any("<locals>" in name for name in entry_codes)
        assert "outer" not in entry_codes


class TestCpgNestedCoverage:
    def test_cpg_includes_nested_codes_and_comprehension_call_edges(self):
        source = """
def outer(a):
    def inner(b):
        return a + b
    xs = [x * a for x in a]
    return inner(1) + xs[0]
"""
        cpg = build_cpg(source, filename="<nested-cpg>")
        cpg.build()
        names = set(cpg.functions)
        assert any(name.endswith(".inner") for name in names)
        assert any("<listcomp>" in name for name in names)
        labels = {edge.label for edge in cpg.all_edges(kinds={CPGEdgeKind.CALL})}
        assert any("<listcomp>" in label for label in labels)
        assert "inner" in {name.rsplit(".", 1)[-1] for name in names}

    def test_self_method_call_is_not_resolved_across_unrelated_classes(self):
        source = """
class A:
    def m(self):
        return 1

class B:
    def n(self):
        return self.m()
"""
        cpg = build_cpg(source, filename="<false-call>")
        cpg.build()
        assert not list(cpg.all_edges(kinds={CPGEdgeKind.CALL}))

    def test_self_method_call_resolves_within_the_same_class(self):
        source = """
class A:
    def m(self):
        return 1
    def n(self):
        return self.m()
"""
        cpg = build_cpg(source, filename="<self-call>")
        cpg.build()
        labels = {edge.label for edge in cpg.all_edges(kinds={CPGEdgeKind.CALL})}
        assert labels == {"A.m"}


class TestCpgAstLayer:
    def test_ast_children_include_nested_expression_nodes(self):
        cpg = build_cpg("def f(a):\n    x = a + 1\n    return x\n")
        cpg.build()
        assign = next(
            node for node in cpg.nodes("f") if node.kind == "stmt" and node.label == "Assign"
        )
        children = cpg.ast_children(assign)
        assert children
        assert any(child.kind == "ast" for child in children)
        assert any(child.label == "Call" for child in children)


class TestCpgCallQueries:
    def test_callees_and_callers_accept_function_names(self):
        source = """
class A:
    def m(self):
        return 1
    def n(self):
        return self.m()
"""
        cpg = build_cpg(source)
        cpg.build()
        assert cpg.callees("A.n")
        assert cpg.callers("A.m")


class TestNestedHeapDependences:
    def test_attribute_read_inside_compound_expression_feeds_memory_dependences(self):
        source = """def f(a):
    x = a.b
    y = a.b + 1
    a.b = 2
    return x + y
"""
        ddg = _lower_ddg(source, "f")
        edges = _edges_with_lines(ddg)
        assert ("memory", "WAR", 3, 4) in edges
        assert ("memory", "WAR", 2, 4) in edges

    def test_unhashable_subscript_literal_does_not_break_semantics(self):
        source = """def f(xs):
    return xs[{'a': 1}]
"""
        ddg = _lower_ddg(source, "f")
        assert ddg.nodes

    def test_match_class_pattern_attribute_reads_are_tracked(self):
        source = """class Point:
    pass

def f(obj):
    match obj:
        case Point(x=px, y=py):
            return px + py
        case _:
            return None
"""
        ddg = _lower_ddg(source, "f")
        slots = [repr(node.ir_node) for node in ddg.nodes if node.category == "slot"]
        assert any("AttributeStorage" in slot and "field='x'" in slot for slot in slots)
        assert any("AttributeStorage" in slot and "field='y'" in slot for slot in slots)

    def test_dynamic_subscript_read_aliases_later_write(self):
        source = """def f(xs, i, j):
    y = xs[i]
    xs[j] = 1
    return y
"""
        ddg = _lower_ddg(source, "f")
        edges = _edges_with_lines(ddg)
        assert ("memory", "WAR", 2, 3) in edges

    def test_closure_cell_write_reaches_later_cell_read(self):
        source = """def outer(a):
    b = 1
    def inner(c):
        nonlocal b
        b += c
        return a + b
    return inner
"""
        ddg = _lower_ddg(source, "outer.<locals>.inner")
        edges = _edges_with_lines(ddg)
        assert any(line_from == 5 and line_to == 6 for _, _, line_from, line_to in edges)

    def test_cyclic_ast_aliases_do_not_recurse_forever(self):
        source = """def f(a, b):
    a = b.x
    b = a.y
    return a.x + b.y
"""
        ddg = _lower_ddg(source, "f")
        assert ddg.nodes

    def test_stable_ids_are_unique_for_duplicate_value_versions(self):
        source = """def f(a):
    x = a.b
    y = a.b + 1
    a.b = 2
    return x + y
"""
        ddg = _lower_ddg(source, "f")
        ids = [node.stable_id for node in ddg.nodes]
        assert len(ids) == len(set(ids))

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ddg.json"
            DDGDumper(ddg).dump_json(str(path))
            payload = json.loads(path.read_text())
        dumped_ids = [node["id"] for node in payload["nodes"]]
        assert len(dumped_ids) == len(set(dumped_ids))


class TestCpgVariableIndexes:
    def test_defs_and_uses_only_contain_source_identifiers(self):
        source = """
def f(data):
    return {(k, v) for k, v in data.items() if (w := v * 2) > 0}
"""
        cpg = build_cpg(source)
        cpg.build()
        for index in (cpg.defs, cpg.uses):
            assert index
            for name, nodes in index.items():
                assert name.isidentifier(), name
                assert not name.startswith("__pyflow_tmp_"), name
                assert not name.startswith("__exc_group__"), name
                node_ids = [node.node_id for node in nodes]
                assert len(node_ids) == len(set(node_ids))


def test_predicate_slots_are_not_projected_as_data_edges():
    source = """def f(a):
    if a:
        return 1
    return 0
"""
    cpg = build_cpg(source)
    cpg.build()
    labels = {edge.label for edge in cpg.all_edges(kinds={CPGEdgeKind.DATA})}
    assert labels == {"a"}
