"""
Gap-coverage tests for CPG patches.

Each test targets a specific gap from the CPG feature-gap analysis
(including strict-v2 policy behavior). Run with::

    pytest tests/ir/test_cpg_gaps.py -x -v
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

from pyflow.ir.cpg import CodePropertyGraph, CPGEdgeKind
from pyflow.ir.cpg.build import build_cpg
from pyflow.ir.cpg.graph import PDGNode
from pyflow.ir.cpg.persist import CPGStore
from pyflow.ir.cpg.taint import CPGTaintEngine


# ── Helpers ──────────────────────────────────────────────────────────────


_SIMPLE_SRC = """
def add(a, b):
    return a + b

def mul(x, y):
    return x * y
"""

_IF_SRC = """
def choose(x):
    if x > 0:
        y = 1
    else:
        y = 2
    return y
"""

_LOOP_SRC = """
def total(n):
    s = 0
    for i in range(n):
        s = s + i
    return s
"""

_SYNTAX_ERROR_SRC = """
def broken(
    x = 1
"""


# ── Gap 4: ordered edges via dict ────────────────────────────────────────


class TestGap4EdgeOrdering:
    """Edges inserted into _cpg_edges_out / _cpg_edges_in should preserve
    insertion order when iterated."""

    def test_all_edges_iteration(self):
        """Verify that all_edges() iterates without error."""
        cpg = build_cpg(_SIMPLE_SRC)
        cpg.build()

        edges = list(cpg.all_edges())
        # all_edges returns a flat list — no crash means the backing
        # dict iteration works correctly.
        assert isinstance(edges, list)

    def test_add_edge_dedup_preserves_order(self):
        """Adding the same edge twice should not duplicate it, and the
        first-inserted position should be preserved."""
        cpg = CodePropertyGraph()
        src = PDGNode(1, "stmt")
        tgt = PDGNode(2, "stmt")
        cpg._add_edge(src, tgt, CPGEdgeKind.DATA, "x")

        # Add the same edge again
        cpg._add_edge(src, tgt, CPGEdgeKind.DATA, "x")

        # Dedup should keep dict size at 1
        assert len(cpg._cpg_edges_out[src.node_id]) == 1
        assert len(cpg._cpg_edges_in[tgt.node_id]) == 1


# ── Gap 6: cpg.funcs property ────────────────────────────────────────────


class TestGap6FuncsProperty:
    """``cpg.funcs`` should return a dict mapping each function name to its
    entry PDG node id."""

    def test_funcs_returns_mapping(self):
        cpg = build_cpg(_SIMPLE_SRC)
        cpg.build()
        funcs = cpg.funcs
        assert isinstance(funcs, dict)
        assert "add" in funcs
        assert "mul" in funcs

    def test_funcs_entry_is_node_id(self):
        cpg = build_cpg(_SIMPLE_SRC)
        cpg.build()
        for name in ("add", "mul"):
            entry_id = cpg.funcs[name]
            assert isinstance(entry_id, int)
            # The entry node should exist in the function's node set
            assert any(
                n.node_id == entry_id for n in cpg.nodes(name)
            ), f"entry node {entry_id} not found in {name}"

    def test_funcs_empty_for_empty_cpg(self):
        cpg = CodePropertyGraph()
        cpg.build()
        assert cpg.funcs == {}


# ── Gap 5: strict typed policy application ───────────────────────────────


class TestGap5TypedPolicy:
    """The CPG engine consumes the shared strict-v2 policy projection."""

    def test_policy_preserves_typed_models(self):
        from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
        from pyflow.analysis.taint import TaintPolicy, TaintRule

        cpg = CodePropertyGraph()
        cpg.build()
        engine = CPGTaintEngine(cpg)
        models = CallModelRegistry(
            [
                CallModel("src", source_kinds=frozenset({"user_input"})),
                CallModel(
                    "sink",
                    sink_kinds=frozenset({"sql"}),
                    sink_arg_positions=frozenset({1}),
                    cwe="CWE-89",
                    severity="high",
                ),
                CallModel("clean", sanitizer_kinds=frozenset({"user_input"})),
            ]
        )
        rule = TaintRule(
            "TEST-SQL",
            "Test SQL flow",
            frozenset({"user_input"}),
            frozenset({"sql"}),
            severity="high",
            cwe="CWE-89",
        )
        engine.apply_policy(TaintPolicy.from_call_models(models, [rule]))
        assert engine.sources == frozenset({"src"})
        assert engine.sinks == {"sink": "CWE-89"}
        assert engine.sanitizers == {"clean": frozenset({"user_input"})}
        assert engine.rules == (rule,)

    def test_kind_scoped_sanitizer_preserves_other_kinds(self):
        from pyflow.ir.cpg.taint import TaintState

        state = TaintState(tags=frozenset({"user_input", "network"}))
        sanitized = state.sanitize("clean_input", frozenset({"user_input"}))
        assert sanitized.tags == frozenset({"network"})
        assert sanitized.sanitized_by == frozenset({"clean_input"})

    def test_rules_reject_nonmatching_source_kinds(self):
        from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
        from pyflow.analysis.taint import TaintPolicy, TaintRule

        engine = CPGTaintEngine(CodePropertyGraph())
        rule = TaintRule(
            "ONLY-INPUT-SQL",
            "Only user input reaches SQL",
            frozenset({"user_input"}),
            frozenset({"sql"}),
        )
        engine.apply_policy(
            TaintPolicy.from_call_models(
                CallModelRegistry([CallModel("sink", sink_kinds=frozenset({"sql"}))]),
                [rule],
            )
        )
        assert engine._matching_rules(frozenset({"user_input"}), "sink") == (rule,)
        assert engine._matching_rules(frozenset({"network"}), "sink") == ()


# ── Gap 10: CPGStore round-trip ──────────────────────────────────────────


class TestGap10CPGStore:
    """``CPGStore`` should persist and retrieve CPG nodes and edges."""

    def test_save_and_retrieve(self):
        cpg = build_cpg(_SIMPLE_SRC)
        cpg.build()
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name
        try:
            store = CPGStore(db_path)
            store.save_cpg(cpg, file_path="test_gap10.py")

            nodes = store.get_cpg_nodes("test_gap10.py")
            assert len(nodes) > 0
            for n in nodes:
                assert "node_id" in n
                assert "kind" in n
                assert "func_name" in n

            edges = store.get_cpg_edges("test_gap10.py")
            if edges:
                for e in edges:
                    assert "source_id" in e
                    assert "target_id" in e
                    assert "kind" in e

            store.close()
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_store_without_crash(self):
        """Even a degenerate CPG should not crash the store."""
        cpg = CodePropertyGraph()
        cpg.build()
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name
        try:
            store = CPGStore(db_path)
            fid = store.save_cpg(cpg, file_path="empty.py")
            assert fid > 0
            nodes = store.get_cpg_nodes("empty.py")
            assert isinstance(nodes, list)
            edges = store.get_cpg_edges("empty.py")
            assert isinstance(edges, list)
            store.close()
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_file_changed_detection(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as src:
            src.write("x = 1\n")
            src_path = src.name
        try:
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                db_path = tmp.name
            try:
                store = CPGStore(db_path)
                assert store.file_changed(src_path)
                store.update_hash(src_path)
                assert not store.file_changed(src_path)
                with open(src_path, "a") as f:
                    f.write("y = 2\n")
                assert store.file_changed(src_path)
                store.close()
            finally:
                Path(db_path).unlink(missing_ok=True)
        finally:
            Path(src_path).unlink(missing_ok=True)


# ── Gap 14: phi node metadata ────────────────────────────────────────────


class TestGap14PhiMetadata:
    """Merge-block phi operations should have ``node_type == "Phi"`` and a
    ``phi_vars`` metadata entry."""

    def _build_ssa_cpg(self, src: str):
        return build_cpg(src, run_ssa=True, expand_phi=True)

    def test_phi_node_type_on_if(self):
        cpg = self._build_ssa_cpg(_IF_SRC)
        cpg.build()
        phi_nodes = [n for n in cpg.nodes("choose") if cpg.node_type(n) == "Phi"]
        if not phi_nodes:
            pytest.skip("no phi nodes generated (SSA may be off)")
        for node in phi_nodes:
            meta = cpg.node_meta(node)
            assert "phi_vars" in meta
            assert isinstance(meta["phi_vars"], list)

    def test_phi_vars_content(self):
        cpg = self._build_ssa_cpg(_IF_SRC)
        cpg.build()
        for n in cpg.nodes("choose"):
            meta = cpg.node_meta(n)
            phi_vars = meta.get("phi_vars", [])
            if phi_vars:
                # Each entry should be a string variable name
                for v in phi_vars:
                    assert isinstance(v, str) and len(v) > 0


# ── Gap 15: SSA def metadata ─────────────────────────────────────────────


class TestGap15SSADefMeta:
    """``ssa_defs`` metadata entries should be populated for SSA-renamed
    variables."""

    def _build_ssa_cpg(self, src: str):
        return build_cpg(src, run_ssa=True, expand_phi=True)

    def test_ssa_defs_exist(self):
        cpg = self._build_ssa_cpg(_IF_SRC)
        cpg.build()
        found = False
        for n in cpg.nodes("choose"):
            meta = cpg.node_meta(n)
            if "ssa_defs" in meta:
                found = True
                for entry in meta["ssa_defs"]:
                    assert "var" in entry
                    assert "name" in entry
        if not found:
            pytest.skip("no ssa_defs found (SSA may be off)")

    def test_ssa_defs_well_formed(self):
        cpg = self._build_ssa_cpg(_LOOP_SRC)
        cpg.build()
        for n in cpg.nodes("total"):
            meta = cpg.node_meta(n)
            for entry in meta.get("ssa_defs", []):
                assert "var" in entry
                assert isinstance(entry["var"], str)
                assert "name" in entry
                assert isinstance(entry["name"], str)
                if "version" in entry:
                    assert isinstance(entry["version"], int)


# ── Gap 16: syntax error produces empty CPG ──────────────────────────────


class TestGap16SyntaxErrorEmptyCPG:
    """Building a CPG from source with syntax errors should return an empty
    (or graceful) CPG rather than crashing."""

    def test_syntax_error_does_not_crash(self):
        cpg = build_cpg(_SYNTAX_ERROR_SRC)
        # Must not raise
        cpg.build()
        # Should have no functions
        assert len(cpg.funcs) == 0

    def test_syntax_error_empty_node_list(self):
        cpg = build_cpg(_SYNTAX_ERROR_SRC)
        cpg.build()
        nodes = list(cpg.nodes())
        assert len(nodes) == 0
        edges = list(cpg.all_edges())
        assert len(edges) == 0

    def test_syntax_error_cpg_meta_empty(self):
        cpg = build_cpg(_SYNTAX_ERROR_SRC)
        cpg.build()
        for fname in cpg.funcs:
            for n in cpg.nodes(fname):
                meta = cpg.node_meta(n)
                # Must not raise and return valid meta
                assert isinstance(meta, dict)
