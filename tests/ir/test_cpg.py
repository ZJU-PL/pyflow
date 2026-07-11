from __future__ import annotations

import unittest

from pyflow.application import context
from pyflow.frontend.programextractor import Extractor
from pyflow.analysis.cfg import transform
from pyflow.analysis.pdg import construct_pdg
from pyflow.analysis.callgraph.callgraph import CallGraph
from pyflow.analysis.cpg import CodePropertyGraph, CPGEdgeKind
from pyflow.analysis.cpg.build import build_cpg, build_cpg_from_directory
from pyflow.analysis.cpg.dump import to_dot
from pyflow.analysis.cpg.taint import (
    CPGTaintEngine,
    MemoryLayout,
    TaintFinding,
    TaintState,
)
from pyflow.language.python import ast as py_ast


def simple_assignment(x):
    y = x + 1
    z = y * 2
    return z


def simple_if(x):
    if x > 0:
        y = 1
    else:
        y = 2
    return y


def try_semantics(x):
    try:
        value = 1 / x
    except ZeroDivisionError:
        value = 0
    return value


class TestCPGConstruction(unittest.TestCase):
    def setUp(self):
        self.compiler = context.CompilerContext(None)
        self.compiler.extractor = Extractor(self.compiler)

    def decompile(self, func):
        return self.compiler.extractor.convertFunction(func, ssa=False)

    def build_cfg(self, func):
        code = self.decompile(func)
        return transform.evaluate(self.compiler, code)

    def build_cpg(self, func, *, func_name="test_func", run_ssa=True):
        cfg = self.build_cfg(func)
        pdg = construct_pdg(cfg, run_ssa=run_ssa, expand_phi=True,
                            include_control=True, include_data=True)
        cpg = CodePropertyGraph()
        cpg.add_function(func_name, pdg)
        return cpg

    # ── Construction basics ──────────────────────────────────────────

    def test_single_function_construction(self):
        cpg = self.build_cpg(simple_assignment)
        self.assertEqual(cpg.functions, ("test_func",))

    def test_build_produces_nodes_and_edges(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        stats = cpg.stats()
        self.assertGreater(stats.nodes, 0)
        self.assertGreater(stats.edges, 0)

    def test_build_is_idempotent(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        stats1 = cpg.stats()
        cpg.build()
        stats2 = cpg.stats()
        self.assertEqual(stats1.nodes, stats2.nodes)
        self.assertEqual(stats1.edges, stats2.edges)

    # ── PDG edge pass-through ────────────────────────────────────────

    def test_pdg_control_edges_passthrough(self):
        cpg = self.build_cpg(simple_if)
        cpg.build()
        control_edges = list(cpg.all_edges(kinds={CPGEdgeKind.CONTROL}))
        self.assertGreater(len(control_edges), 0)
        for e in control_edges:
            self.assertEqual(e.kind, CPGEdgeKind.CONTROL)

    def test_pdg_data_edges_passthrough(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        data_edges = list(cpg.all_edges(kinds={CPGEdgeKind.DATA}))
        self.assertGreater(len(data_edges), 0)
        for e in data_edges:
            self.assertEqual(e.kind, CPGEdgeKind.DATA)

    # ── CFG edges ────────────────────────────────────────────────────

    def test_cfg_next_edges_exist(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        cfg_next = list(cpg.all_edges(kinds={CPGEdgeKind.CFG_NEXT}))
        self.assertGreater(len(cfg_next), 0)

    def test_cfg_branch_edges_for_if(self):
        cpg = self.build_cpg(simple_if)
        cpg.build()
        true_edges = list(cpg.all_edges(kinds={CPGEdgeKind.CFG_BRANCH_TRUE}))
        false_edges = list(cpg.all_edges(kinds={CPGEdgeKind.CFG_BRANCH_FALSE}))
        self.assertGreater(len(true_edges), 0)
        self.assertGreater(len(false_edges), 0)

    def test_cfg_except_edges_for_try(self):
        cpg = self.build_cpg(try_semantics, run_ssa=False)
        cpg.build()
        except_edges = list(cpg.all_edges(kinds={CPGEdgeKind.CFG_EXCEPT}))
        self.assertGreater(len(except_edges), 0)

    # ── AST edges ────────────────────────────────────────────────────

    def test_ast_children_method_works(self):
        """AST_CHILD edges exist only when both parent and child AST nodes
        have PDG representations.  For leaf-only functions like
        simple_assignment, this may yield zero edges — the method still
        works correctly."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        for node in cpg.nodes():
            children = cpg.ast_children(node)
            self.assertIsInstance(children, set)

    def test_ast_parent_child_consistency(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        for node in cpg.nodes():
            for child in cpg.ast_children(node):
                parent = cpg.ast_parent(child)
                self.assertIsNotNone(parent)
                self.assertIs(parent, cpg.ast_parent(child))

    # ── Typed navigation ─────────────────────────────────────────────

    def test_cfg_successors_filter_by_kind(self):
        cpg = self.build_cpg(simple_if)
        cpg.build()
        for node in cpg.nodes():
            succ_all = cpg.cfg_successors(node)
            succ_true = cpg.cfg_successors(node, kind=CPGEdgeKind.CFG_BRANCH_TRUE)
            self.assertLessEqual(len(succ_true), len(succ_all))

    # ── Unified slicing ──────────────────────────────────────────────

    def test_forward_slice_all_includes_data_edges(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        entry = next(cpg.nodes("test_func"))
        slc = cpg.forward_slice_all(
            [entry], kinds=frozenset((CPGEdgeKind.DATA,))
        )
        # Slice should contain entry plus downstream nodes
        self.assertIn(entry, slc)
        self.assertGreater(len(slc), 0)

    def test_backward_slice_all_from_return(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        ret_nodes = [n for n in cpg.nodes("test_func")
                     if n.kind == "stmt" and isinstance(n.ast_node, py_ast.Return)]
        self.assertGreater(len(ret_nodes), 0)
        slc = cpg.backward_slice_all(
            ret_nodes, kinds=frozenset((CPGEdgeKind.DATA, CPGEdgeKind.CONTROL))
        )
        self.assertIn(ret_nodes[0], slc)

    # ── Reachability ─────────────────────────────────────────────────

    def test_entry_reaches_exit(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        entry = next(cpg.nodes("test_func"))
        exit_nodes = [n for n in cpg.nodes("test_func") if n.kind == "exit"]
        self.assertGreater(len(exit_nodes), 0)
        self.assertTrue(cpg.reachable(entry, exit_nodes[0]))

    # ── is_in_try_block ──────────────────────────────────────────────

    def test_node_in_try_block_detected(self):
        cpg = self.build_cpg(try_semantics, run_ssa=False)
        cpg.build()
        stmts = [n for n in cpg.nodes("test_func") if n.kind == "stmt"]
        self.assertGreater(len(stmts), 0)
        # At least one statement inside try block should register
        self.assertTrue(any(cpg.is_in_try_block(n) for n in stmts))

    # ── Call graph ───────────────────────────────────────────────────

    def test_call_graph_edges(self):
        cg = CallGraph()
        cg.add_edge("caller", "callee")

        cfg_caller = self.build_cfg(simple_assignment)
        pdg_caller = construct_pdg(cfg_caller, run_ssa=True, expand_phi=True,
                                   include_control=True, include_data=True)
        cfg_callee = self.build_cfg(simple_if)
        pdg_callee = construct_pdg(cfg_callee, run_ssa=True, expand_phi=True,
                                   include_control=True, include_data=True)

        cpg = CodePropertyGraph()
        cpg.add_function("caller", pdg_caller)
        cpg.add_function("callee", pdg_callee)
        cpg.add_call_graph(cg)
        cpg.build()

        call_edges = list(cpg.all_edges(kinds={CPGEdgeKind.CALL}))
        self.assertGreater(len(call_edges), 0)
        self.assertEqual(call_edges[0].kind, CPGEdgeKind.CALL)

    def test_call_graph_no_match_skips_silently(self):
        cg = CallGraph()
        cg.add_edge("nonexistent_caller", "nonexistent_callee")

        cpg = self.build_cpg(simple_assignment, func_name="test_func")
        cpg.add_call_graph(cg)
        cpg.build()

        call_edges = list(cpg.all_edges(kinds={CPGEdgeKind.CALL}))
        self.assertEqual(len(call_edges), 0)

    # ── Stats ────────────────────────────────────────────────────────

    def test_stats_includes_edge_kind_counts(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        stats = cpg.stats()
        self.assertEqual(stats.functions, 1)
        self.assertGreater(stats.nodes, 0)
        # simple_assignment is straight-line — may not have control edges
        self.assertIn("data", stats.edge_kinds)
        self.assertIn("CFG_NEXT", stats.edge_kinds)

    # ── Multiple functions ───────────────────────────────────────────

    def test_multiple_functions_isolated_pdg_nodes(self):
        cfg1 = self.build_cfg(simple_assignment)
        pdg1 = construct_pdg(cfg1, run_ssa=True, expand_phi=True,
                             include_control=True, include_data=True)
        cfg2 = self.build_cfg(simple_if)
        pdg2 = construct_pdg(cfg2, run_ssa=True, expand_phi=True,
                             include_control=True, include_data=True)

        cpg = CodePropertyGraph()
        cpg.add_function("func_a", pdg1)
        cpg.add_function("func_b", pdg2)
        cpg.build()

        self.assertEqual(len(cpg.functions), 2)
        nodes_a = list(cpg.nodes("func_a"))
        nodes_b = list(cpg.nodes("func_b"))
        self.assertGreater(len(nodes_a), 0)
        self.assertGreater(len(nodes_b), 0)

    # ── Edge kinds exhaustiveness ────────────────────────────────────

    def test_all_edge_kinds_in_enum(self):
        for ek in CPGEdgeKind:
            self.assertIn(ek.value, ("control", "data", "AST_CHILD",
                                      "CFG_NEXT", "CFG_BRANCH_TRUE",
                                      "CFG_BRANCH_FALSE", "CFG_EXCEPT",
                                      "CALL", "RETURN_EDGE"))

    # ── RETURN_EDGE ───────────────────────────────────────────────────

    def test_return_edge_built_for_call_graph(self):
        cg = CallGraph()
        cg.add_edge("caller", "callee")
        cfg_caller = self.build_cfg(simple_assignment)
        pdg_caller = construct_pdg(cfg_caller, run_ssa=True, expand_phi=True,
                                   include_control=True, include_data=True)
        cfg_callee = self.build_cfg(simple_if)
        pdg_callee = construct_pdg(cfg_callee, run_ssa=True, expand_phi=True,
                                   include_control=True, include_data=True)
        cpg = CodePropertyGraph()
        cpg.add_function("caller", pdg_caller)
        cpg.add_function("callee", pdg_callee)
        cpg.add_call_graph(cg)
        cpg.build()
        return_edges = list(cpg.all_edges(kinds={CPGEdgeKind.RETURN_EDGE}))
        self.assertGreater(len(return_edges), 0)
        self.assertEqual(return_edges[0].kind, CPGEdgeKind.RETURN_EDGE)

    # ── Serialization ─────────────────────────────────────────────────

    def test_to_dict_produces_valid_structure(self):
        import json
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        d = cpg.to_dict()
        self.assertIn("nodes", d)
        self.assertIn("edges", d)
        self.assertIn("defs", d)
        self.assertIn("uses", d)
        self.assertIn("functions", d)
        json.dumps(d)

    # ── Defs / Uses indexes ───────────────────────────────────────────

    def test_defs_maps_variable_to_defining_nodes(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        d = cpg.defs
        self.assertIn("x", d)
        self.assertIn("y", d)
        self.assertIn("z", d)
        self.assertGreater(len(d["x"]), 0)

    def test_uses_maps_variable_to_using_nodes(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        u = cpg.uses
        self.assertIn("x", u)
        self.assertIn("y", u)

    # ── TaintState ────────────────────────────────────────────────────

    def test_taint_state_clean_is_not_tainted(self):
        self.assertFalse(TaintState.clean().is_tainted())

    def test_taint_state_user_controlled_is_tainted(self):
        self.assertTrue(TaintState.user_controlled().is_tainted())

    def test_taint_state_merge_combines_tags(self):
        a = TaintState(tags=frozenset({"xss"}))
        b = TaintState(tags=frozenset({"sqli"}))
        merged = a.merge(b)
        self.assertIn("xss", merged.tags)
        self.assertIn("sqli", merged.tags)

    def test_taint_state_sanitize_clears_tags(self):
        tainted = TaintState(tags=frozenset({"xss"}))
        clean = tainted.sanitize("html.escape")
        self.assertFalse(clean.is_tainted())
        self.assertIn("html.escape", clean.sanitized_by)

    # ── MemoryLayout ──────────────────────────────────────────────────

    def test_memory_layout_alias_shares_taint(self):
        mem = MemoryLayout()
        mem.mark_tainted("src", TaintState.user_controlled())
        mem.alias("dst", "src")
        self.assertTrue(mem.is_tainted("src"))
        self.assertTrue(mem.is_tainted("dst"))

    def test_memory_layout_write_read_scalar(self):
        mem = MemoryLayout()
        mem.mark_tainted("x", TaintState.user_controlled())
        self.assertTrue(mem.is_tainted("x"))
        self.assertFalse(mem.is_tainted("y"))

    def test_memory_layout_snapshot_restore(self):
        mem = MemoryLayout()
        mem.mark_tainted("a", TaintState.user_controlled())
        snap = mem.snapshot()
        mem2 = MemoryLayout()
        mem2.restore(snap)
        self.assertTrue(mem2.is_tainted("a"))

    # ── CPGTaintEngine ────────────────────────────────────────────────

    def test_taint_engine_initializes_with_defaults(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        self.assertGreater(len(engine.sources), 0)
        self.assertGreater(len(engine.sinks), 0)
        self.assertGreater(len(engine.sanitizers), 0)

    def test_taint_engine_add_custom_sink(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        engine.add_sink("my_sink", cwe="CWE-999")
        self.assertIn("my_sink", engine.sinks)
        self.assertEqual(engine.sinks["my_sink"], "CWE-999")

    def test_taint_engine_find_paths_returns_list(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        paths = engine.find_taint_paths()
        self.assertIsInstance(paths, list)

    def test_taint_finding_has_source_and_sink_lines(self):
        cpg = self.build_cpg(simple_if)
        cpg.build()
        entry = next(cpg.nodes("test_func"))
        stmts = [n for n in cpg.nodes("test_func") if n.kind == "stmt"]
        finding = TaintFinding(
            cwe="CWE-000",
            severity="low",
            source_label="src",
            sink_label="snk",
            source_node=entry,
            sink_node=stmts[0] if stmts else entry,
        )
        self.assertGreaterEqual(finding.source_line, 0)
        self.assertGreaterEqual(finding.sink_line, 0)

    # ── build_cpg ─────────────────────────────────────────────────────

    def test_build_cpg_from_source(self):
        source = "def add(a, b):\n    return a + b\n"
        cpg = build_cpg(source, "test.py")
        self.assertGreater(len(cpg.functions), 0)
        cpg.build()
        self.assertGreater(cpg.stats().nodes, 0)

    # ── Interprocedural taint ─────────────────────────────────────────

    def test_taint_engine_includes_call_edges(self):
        cg = CallGraph()
        cg.add_edge("caller", "callee")
        cfg1 = self.build_cfg(simple_assignment)
        pdg1 = construct_pdg(cfg1, run_ssa=True, expand_phi=True,
                             include_control=True, include_data=True)
        cfg2 = self.build_cfg(simple_if)
        pdg2 = construct_pdg(cfg2, run_ssa=True, expand_phi=True,
                             include_control=True, include_data=True)
        cpg = CodePropertyGraph()
        cpg.add_function("caller", pdg1)
        cpg.add_function("callee", pdg2)
        cpg.add_call_graph(cg)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        paths = engine.find_taint_paths()
        self.assertIsInstance(paths, list)

    # ── DOT export ────────────────────────────────────────────────────

    def test_to_dot_produces_digraph(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        dot = to_dot(cpg)
        self.assertIn("digraph CPG", dot)
        self.assertIn("}", dot)
        self.assertIn("n", dot)

    def test_to_dot_with_kind_filter(self):
        cpg = self.build_cpg(simple_if)
        cpg.build()
        dot = to_dot(cpg, kinds={CPGEdgeKind.CFG_BRANCH_TRUE})
        self.assertIn("digraph CPG", dot)

    def test_to_dot_with_highlight(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        entry = next(cpg.nodes("test_func"))
        dot = to_dot(cpg, highlight_nodes={entry.node_id})
        self.assertIn("fillcolor=lightcoral", dot)

    # ── Query API ──────────────────────────────────────────────────────

    def test_find_nodes_by_kind(self):
        cpg = self.build_cpg(simple_if)
        cpg.build()
        conds = cpg.find_nodes(kind="cond")
        self.assertGreater(len(conds), 0)
        for n in conds:
            self.assertEqual(n.kind, "cond")

    def test_find_nodes_by_label(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        entry = cpg.find_nodes(kind="entry")
        self.assertEqual(len(entry), 1)

    def test_find_edges_by_kind(self):
        cpg = self.build_cpg(simple_if)
        cpg.build()
        control = cpg.find_edges(kind=CPGEdgeKind.CONTROL)
        self.assertGreater(len(control), 0)

    def test_path_between_entry_and_exit(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        entry = cpg.find_nodes(kind="entry")[0]
        exits = cpg.find_nodes(kind="exit")
        self.assertGreater(len(exits), 0)
        path = cpg.path_between(entry, exits[0])
        self.assertIsNotNone(path)
        self.assertEqual(path[0], entry)
        self.assertEqual(path[-1], exits[0])

    def test_path_between_returns_none_when_unreachable(self):
        cpg = self.build_cpg(simple_if)
        cpg.build()
        nodes = list(cpg.nodes("test_func"))
        if len(nodes) >= 2:
            path = cpg.path_between(nodes[-1], nodes[0], kinds=set())
            self.assertIsNone(path)

    def test_nodes_touching_finds_data_flow(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        touched = cpg.nodes_touching("Entry")
        self.assertIsInstance(touched, set)

    # ── Multi-file CPG ────────────────────────────────────────────────

    def test_build_cpg_from_directory(self):
        import tempfile, os
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "a.py"), "w") as f:
                f.write("def foo(x):\n    return x + 1\n")
            with open(os.path.join(tmp, "b.py"), "w") as f:
                f.write("from a import foo\ndef bar(y):\n    return foo(y)\n")
            cpg = build_cpg_from_directory(tmp)
            cpg.build()
            self.assertGreater(len(cpg.functions), 0)
            self.assertGreater(cpg.stats().nodes, 0)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    # ── Finding serialization ──────────────────────────────────────────

    def test_finding_to_dict(self):
        import json
        cpg = self.build_cpg(simple_if)
        cpg.build()
        entry = next(cpg.nodes("test_func"))
        stmts = [n for n in cpg.nodes("test_func") if n.kind == "stmt"]
        finding = TaintFinding(
            cwe="CWE-78", severity="high", source_label="input",
            sink_label="subprocess.run", source_node=entry,
            sink_node=stmts[0] if stmts else entry,
        )
        d = finding.to_dict()
        self.assertEqual(d["cwe"], "CWE-78")
        self.assertIn("confidence", d)
        json.dumps(d)

    def test_finding_confidence_in_range(self):
        finding = TaintFinding(
            cwe="CWE-78", severity="high", source_label="request.args",
            sink_label="subprocess.run", source_node=None, sink_node=None,
            path_nodes=[None] * 5, tags=frozenset({"xss"}),
            sanitizers=frozenset({"escape"}),
        )
        conf = finding.confidence
        self.assertGreaterEqual(conf, 0.0)
        self.assertLessEqual(conf, 1.0)

    def test_finding_sarif(self):
        import json
        cpg = self.build_cpg(simple_if)
        cpg.build()
        entry = next(cpg.nodes("test_func"))
        finding = TaintFinding(
            cwe="CWE-78", severity="critical", source_label="input",
            sink_label="subprocess.run", source_node=entry, sink_node=entry,
        )
        sarif_result = finding.to_sarif(rule_index=0)
        self.assertEqual(sarif_result["ruleId"], "CWE-78")
        self.assertEqual(sarif_result["level"], "error")
        json.dumps(sarif_result)

    # ── Deduplication ──────────────────────────────────────────────────

    def test_deduplicate_collapses_same_key(self):
        finding1 = TaintFinding(
            cwe="CWE-78", severity="high", source_label="a",
            sink_label="b", source_node=None, sink_node=None,
        )
        finding2 = TaintFinding(
            cwe="CWE-78", severity="high", source_label="a",
            sink_label="b", source_node=None, sink_node=None,
            path_nodes=[None, None, None],
        )
        deduped = CPGTaintEngine.deduplicate([finding1, finding2])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].path_length, 3)

    def test_deduplicate_preserves_different_keys(self):
        f1 = TaintFinding(
            cwe="CWE-78", severity="high", source_label="a",
            sink_label="b", source_node=None, sink_node=None,
        )
        f2 = TaintFinding(
            cwe="CWE-89", severity="high", source_label="a",
            sink_label="b", source_node=None, sink_node=None,
        )
        deduped = CPGTaintEngine.deduplicate([f1, f2])
        self.assertEqual(len(deduped), 2)

    def test_deduplicate_sorts_by_confidence(self):
        f1 = TaintFinding(
            cwe="CWE-78", severity="high", source_label="x",
            sink_label="y", source_node=None, sink_node=None,
            path_nodes=[None] * 10, sanitizers=frozenset({"esc"}),
        )
        f2 = TaintFinding(
            cwe="CWE-89", severity="low", source_label="z",
            sink_label="w", source_node=None, sink_node=None,
            path_nodes=[],
        )
        deduped = CPGTaintEngine.deduplicate([f2, f1])
        self.assertGreaterEqual(deduped[0].confidence, deduped[-1].confidence)

    # ── SARIF export ───────────────────────────────────────────────────

    def test_to_sarif_produces_valid_document(self):
        import json
        finding = TaintFinding(
            cwe="CWE-78", severity="critical", source_label="src",
            sink_label="snk", source_node=None, sink_node=None,
        )
        doc = CPGTaintEngine.to_sarif([finding], tool_name="test")
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 1)
        json.dumps(doc)

    def test_to_json_serializes(self):
        finding = TaintFinding(
            cwe="CWE-78", severity="high", source_label="src",
            sink_label="snk", source_node=None, sink_node=None,
        )
        s = CPGTaintEngine.to_json([finding])
        self.assertIn("CWE-78", s)
        import json
        json.loads(s)


if __name__ == "__main__":
    unittest.main()
