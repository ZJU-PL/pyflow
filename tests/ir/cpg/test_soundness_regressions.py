"""Regression contracts for CPG identity, semantic metadata, and snapshots."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from pyflow.application.cpg import build_cpg
from pyflow.ir.core import ValueId, ensure_code_indexed
from pyflow.ir.cpg import CPGEdge, CPGEdgeKind, CodePropertyGraph
from pyflow.ir.cpg.persist import CPGStore
from pyflow.ir.pdg.graph import PDGNode, ProgramDependenceGraph
from pyflow.language.python import ast as py_ast


def _parallel_data_graph():
    pdg = ProgramDependenceGraph(SimpleNamespace(code=None))
    source = pdg.add_node("entry", label="source")
    target = pdg.add_node("stmt", label="target")
    pdg.entry = source
    source.add_edge_to(target, "data", "left")
    source.add_edge_to(target, "data", "right")
    source.add_edge_to(target, "data", "left")
    cpg = CodePropertyGraph()
    cpg.add_function("registered", pdg)
    return cpg, source, target


@pytest.mark.parametrize("kind", list(CPGEdgeKind))
def test_edge_identity_includes_label_and_deduplicates_exact_matches(kind):
    source, target = PDGNode(0, "stmt"), PDGNode(1, "stmt")
    left = CPGEdge(source, target, kind, "left")
    same = CPGEdge(source, target, kind, "left")
    right = CPGEdge(source, target, kind, "right")
    assert left == same
    assert hash(left) == hash(same)
    assert left != right
    assert len({left, same, right}) == 2
    assert left != CPGEdge(target, source, kind, "left")
    assert left != object()


def test_parallel_data_edges_survive_queries_json_sqlite_and_rebuild():
    cpg, source, target = _parallel_data_graph()
    assert cpg.build()
    expected = {"left", "right"}
    assert {edge.label for edge in cpg.find_edges(kind=CPGEdgeKind.DATA)} == expected
    assert {edge.label for edge in cpg._cpg_edges_in[target.node_id]} == expected
    assert cpg.successors(source, kinds={CPGEdgeKind.DATA}) == {target}
    before = json.loads(json.dumps(cpg.to_dict()))
    assert {edge["label"] for edge in before["edges"]} == expected
    assert cpg.build()
    assert cpg.to_dict() == before
    store = CPGStore(":memory:")
    try:
        for _ in range(2):
            store.save_cpg(cpg, file_path="graph.py")
            edges = store.get_cpg_edges("graph.py")
            assert len(edges) == 2
            assert {edge["label"] for edge in edges} == expected
    finally:
        store.close()


def test_pdg_data_labels_are_not_rewritten_by_unrelated_assignments():
    class RenderedAssignment:
        def __init__(self, text):
            self.text = text

        def toStr(self):
            return self.text

    cpg, source, target = _parallel_data_graph()
    pdg = cpg.pdgs["registered"]
    source.ast_node = RenderedAssignment("left_1 = input()")
    pdg.add_node("stmt", ast_node=RenderedAssignment("left_2 = clean()"))
    assert {edge.label for edge in cpg.find_edges(kind=CPGEdgeKind.DATA)} == {"left", "right"}


def test_ordinary_underscore_names_are_not_parsed_as_ssa_versions():
    cpg = build_cpg("def f(user_name, version_1):\n    return user_name + version_1\n")
    for node in cpg.nodes("f"):
        for key in ("ssa_defs", "ssa_uses"):
            for entry in cpg.node_meta(node).get(key, []):
                if entry["name"] in {"user_name", "version_1"}:
                    assert entry["var"] == entry["name"]
                    assert "version" not in entry


def test_unused_assignment_still_has_definition_metadata():
    cpg = build_cpg("def f():\n    unused_name = 1\n    return 0\n")
    assignment = next(node for node in cpg.nodes("f") if isinstance(node.ast_node, py_ast.Assign))
    assert {entry["var"] for entry in cpg.node_meta(assignment)["ssa_defs"]} == {"unused_name"}


def test_phi_defines_its_result_and_connects_to_return_with_exact_ssa_metadata():
    cpg = build_cpg(
        "def f(flag):\n    x = input()\n    if flag:\n        x = 'clean'\n    return x\n",
        run_ssa=True,
    )
    pdg = cpg.pdgs["f"]
    code = pdg.cfg.code
    catalog = ensure_code_indexed(code)
    phi = next(node for node in cpg.nodes("f") if isinstance(node.ast_node, py_ast.Phi))
    ret = next(node for node in cpg.nodes("f") if isinstance(node.ast_node, py_ast.Return))
    semantics = catalog.semantics.operation(catalog.node_id(phi.ast_node, code))
    value = catalog.value_id(phi.ast_node.target, code)
    assert semantics.definitions == (value,)
    assert value not in semantics.uses
    assert cpg.path_between(phi, ret, kinds={CPGEdgeKind.DATA}) == [phi, ret]
    for node in cpg.nodes("f"):
        if node.ast_node is None:
            continue
        semantics = catalog.semantics.operation(catalog.node_id(node.ast_node, code))
        meta = cpg.node_meta(node)
        for key, identities in (("ssa_defs", semantics.definitions), ("ssa_uses", semantics.uses)):
            actual = {(entry["var"], entry.get("version")) for entry in meta.get(key, [])}
            expected = {
                (
                    (catalog.symbols[identity.symbol].display_name, identity.version)
                    if isinstance(identity, ValueId)
                    else (catalog.symbols[identity].display_name, None)
                )
                for identity in identities
            }
            assert actual == expected
    assert cpg.node_meta(phi)["phi_vars"] == ["x"]


@pytest.mark.parametrize("run_ssa", [False, True])
def test_serialization_is_stable_across_rebuilds_with_phi_and_synthetic_statements(run_ssa):
    cpg = build_cpg(
        "def f(flag):\n    class Carrier:\n        pass\n"
        "    x = 1\n    if flag:\n        x = 2\n    return x\n",
        run_ssa=run_ssa,
    )
    before = json.loads(json.dumps(cpg.to_dict()))
    for _ in range(2):
        assert cpg.build()
        assert cpg.to_dict() == before
        assert len({node.node_id for node in cpg.nodes()}) == cpg.stats().nodes
        ids = {node.node_id for node in cpg.nodes()}
        assert all(
            edge.source.node_id in ids and edge.target.node_id in ids for edge in cpg.all_edges()
        )


def test_serialization_uses_registered_function_name():
    cpg, _, _ = _parallel_data_graph()
    assert {node["func"] for node in cpg.to_dict()["nodes"]} == {"registered"}


def test_exported_metadata_does_not_mutate_graph():
    cpg = build_cpg("def f(value):\n    return value\n")
    ret = next(node for node in cpg.nodes("f") if isinstance(node.ast_node, py_ast.Return))
    original = cpg.node_meta(ret)["ssa_uses"][:]
    cpg.node_to_dict(ret)["meta"]["ssa_uses"].clear()
    assert cpg.node_meta(ret)["ssa_uses"] == original
    exported = cpg.to_dict()
    next(node for node in exported["nodes"] if node["id"] == ret.node_id)["meta"][
        "ssa_uses"
    ].clear()
    assert cpg.node_meta(ret)["ssa_uses"] == original


def test_failed_rebuild_invalidates_previous_built_flag(monkeypatch):
    cpg, _, _ = _parallel_data_graph()
    assert cpg.build()

    def fail(*args):
        raise RuntimeError("failed assembly")

    monkeypatch.setattr(cpg, "_build_node_metadata", fail)
    with pytest.raises(RuntimeError, match="failed assembly"):
        cpg.build()
    assert not cpg._built


def test_adding_colliding_function_ids_preserves_all_dependencies():
    cpg, _, _ = _parallel_data_graph()
    cpg.build()
    other, _, _ = _parallel_data_graph()
    cpg.add_function("other", other.pdgs["registered"])
    assert cpg.build()
    assert cpg.stats().nodes == len({node.node_id for node in cpg.nodes()}) == 4
    assert cpg.stats().edge_kinds["data"] == 4
    before = cpg.to_dict()
    assert cpg.build()
    assert cpg.to_dict() == before


def test_failed_sqlite_save_keeps_previous_complete_graph(monkeypatch):
    cpg, _, _ = _parallel_data_graph()
    store = CPGStore(":memory:")
    try:
        store.save_cpg(cpg, file_path="graph.py")
        previous_nodes = store.get_cpg_nodes("graph.py")
        previous_edges = store.get_cpg_edges("graph.py")
        original_meta = cpg.node_meta
        calls = 0

        def fail_after_first_node(node):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("failed export")
            return original_meta(node)

        monkeypatch.setattr(cpg, "node_meta", fail_after_first_node)
        with pytest.raises(RuntimeError, match="failed export"):
            store.save_cpg(cpg, file_path="graph.py")
        assert store.get_cpg_nodes("graph.py") == previous_nodes
        assert store.get_cpg_edges("graph.py") == previous_edges
    finally:
        store.close()


def test_legacy_lambda_synthetic_nodes_and_edges_are_stable_across_rebuilds():
    # Normalized source lambdas use MakeFunction. This exercises the supported
    # Lambda-shaped extension path directly, including distinct captures.
    class Lambda:
        lineno = 1

        def __init__(self, name):
            self.body = py_ast.Local(name)

        def children(self):
            return (self.body,)

    pdg = ProgramDependenceGraph(SimpleNamespace(code=None))
    pdg.entry = pdg.add_node("entry")
    pdg.add_node("stmt", ast_node=Lambda("left"))
    pdg.add_node("stmt", ast_node=Lambda("right"))
    cpg = CodePropertyGraph()
    cpg.add_function("f", pdg)
    before = cpg.to_dict()
    assert len([node for node in before["nodes"] if node["meta"].get("lambda_name")]) == 2
    for _ in range(2):
        assert cpg.build()
        assert cpg.to_dict() == before
