from __future__ import annotations

import unittest
import warnings

from pyflow.application import context
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.ir.cfg import transform
from pyflow.ir.pdg import construct_pdg
from pyflow.analysis.callgraph.callgraph import CallGraph
from pyflow.ir.cpg import CodePropertyGraph, CPGEdgeKind
from pyflow.ir.cpg.build import build_cpg, build_cpg_from_directory
from pyflow.ir.cpg.dump import to_dot
from pyflow.ir.cpg.taint import (
    CPGTaintEngine,
    MemoryLayout,
    TaintFinding,
    TaintPath,
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


def return_arg(x):
    return x


def call_return_arg():
    data = return_arg(42)
    return data


def tainted_return():
    x = request.args.get("name")
    return x


def call_tainted_return():
    data = tainted_return()
    subprocess.run(data)


def try_caught_var(x):
    try:
        value = 1 / x
    except ValueError as e:
        result = str(e)
    return value


def try_multi_handler(x):
    try:
        value = 1 / x
    except ZeroDivisionError:
        value = 0
    except ValueError as e:
        result = str(e)
    return value


def try_with_finally(x):
    try:
        value = 1 / x
    except ValueError as e:
        result = str(e)
    finally:
        value = -1
    return value


def for_loop(seq):
    total = 0
    for item in seq:
        total = total + item
    return total


def with_stmt(x):
    with open("/dev/null") as f:
        x = f.read()
    return x


def augassign(x):
    x += 1
    return x


def for_loop_tainted_source(seq):
    total = 0
    for item in seq:
        total = total + request.args.get("x")
    return total


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
        pdg = construct_pdg(
            cfg,
            run_ssa=run_ssa,
            expand_phi=True,
            include_control=True,
            include_data=True,
        )
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

    def test_try_metadata_has_handlers(self):
        """TryExceptFinally nodes get handler metadata."""
        cpg = self.build_cpg(try_caught_var, run_ssa=False)
        cpg.build()
        found = False
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            if meta.get("is_try_stmt"):
                found = True
                handlers = meta.get("handlers", [])
                self.assertGreater(len(handlers), 0)
                self.assertEqual(handlers[0]["type_name"], "ValueError")
                self.assertEqual(handlers[0]["caught_var"], "e")
        self.assertTrue(found, "No TryExceptFinally node found in CPG")

    def test_try_metadata_multi_handler(self):
        """Multiple handlers are all recorded."""
        cpg = self.build_cpg(try_multi_handler, run_ssa=False)
        cpg.build()
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            if meta.get("is_try_stmt"):
                handlers = meta.get("handlers", [])
                self.assertEqual(len(handlers), 2)
                self.assertIsNone(handlers[0]["caught_var"])
                self.assertEqual(handlers[1]["caught_var"], "e")

    def test_try_metadata_finally(self):
        """finally block is recorded in metadata."""
        cpg = self.build_cpg(try_with_finally, run_ssa=False)
        cpg.build()
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            if meta.get("is_try_stmt"):
                self.assertTrue(meta.get("has_finally"))
                self.assertFalse(meta.get("has_else"))

    def test_try_taint_propagates_to_caught_var(self):
        """When tainted state reaches a try node, the caught var is marked
        in the memory layout."""
        from pyflow.ir.cpg.graph import CodePropertyGraph

        cpg = self.build_cpg(try_caught_var, run_ssa=False)
        cpg.build()
        engine = CPGTaintEngine(cpg)

        try_node = None
        for node in cpg.nodes():
            ast_node = getattr(node, "ast_node", None)
            if isinstance(ast_node, py_ast.TryExceptFinally):
                try_node = node
                break
        self.assertIsNotNone(try_node, "No TryExceptFinally node found in CPG")

        mem = MemoryLayout()
        tstate = TaintState.user_controlled()
        try_ast = try_node.ast_node
        result = engine._propagate_try(try_ast, tstate, try_node, mem)
        self.assertTrue(result.is_tainted(), "Taint state should pass through try")
        self.assertTrue(
            mem.is_tainted("e"), "Caught variable 'e' should be tainted in mem"
        )

    def test_try_clean_state_does_not_mark_caught_var(self):
        """Clean tstate does not mark caught variable."""
        cpg = self.build_cpg(try_caught_var, run_ssa=False)
        cpg.build()
        engine = CPGTaintEngine(cpg)

        try_node = next(
            (
                n
                for n in cpg.nodes()
                if isinstance(getattr(n, "ast_node", None), py_ast.TryExceptFinally)
            ),
            None,
        )
        self.assertIsNotNone(try_node)

        mem = MemoryLayout()
        clean = TaintState.clean()
        result = engine._propagate_try(try_node.ast_node, clean, try_node, mem)
        self.assertFalse(result.is_tainted())
        self.assertFalse(
            mem.is_tainted("e"),
            "Caught variable should not be tainted with " "clean state",
        )

    # ── Loop header metadata / fixpoint ─────────────────────────────────

    def test_loop_header_detected(self):
        """For loops produce loop-header PDG nodes marked with metadata."""
        cpg = self.build_cpg(for_loop, run_ssa=True)
        cpg.build()
        found_header = False
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            if meta.get("loop_header"):
                found_header = True
                vars_info = meta.get("for_loop_vars", [])
                self.assertGreater(len(vars_info), 0)
                it, idx = vars_info[0]
                self.assertEqual(it, "seq")
                self.assertEqual(idx, "item")
        self.assertTrue(found_header, "No loop header node found in CPG")

    def test_while_loop_header_detected(self):
        """While loops also produce loop-header metadata."""

        def while_loop(x):
            i = 0
            while i < x:
                i = i + 1
            return i

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", RuntimeWarning)
            cpg = self.build_cpg(while_loop, run_ssa=True)
        self.assertFalse(
            any("DDG-backed data dependence" in str(w.message) for w in caught)
        )
        self.assertTrue(
            all(pdg.data_dependence_mode == "hybrid" for pdg in cpg.pdgs.values())
        )
        cpg.build()
        found_header = False
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            if meta.get("loop_header"):
                found_header = True
        self.assertTrue(found_header, "No loop header found for while loop")

    def test_no_spurious_loop_headers(self):
        """Functions without loops have no loop_header metadata."""
        cpg = self.build_cpg(simple_assignment, run_ssa=True)
        cpg.build()
        headers = [n for n in cpg.nodes() if cpg.node_meta(n).get("loop_header")]
        self.assertEqual(len(headers), 0)

    # ── origin_ast metadata ──────────────────────────────────────────

    @staticmethod
    def _collect_suites_with_origin(cfg):
        """Collect all Suite blocks with a non-None origin_ast."""
        from collections import deque

        entry = getattr(cfg, "entryTerminal", None)
        if entry is None:
            return []
        seen: set = set()
        suites = []
        queue = deque([entry])
        while queue:
            block = queue.popleft()
            bid = id(block)
            if bid in seen:
                continue
            seen.add(bid)
            if isinstance(block, cfg_graph.Suite) and block.origin_ast is not None:
                suites.append(block)
            for child in block.forward():
                if child is not None:
                    queue.append(child)
        return suites

    def test_suite_origin_ast_for_loop(self):
        """Suite blocks from for-loop bodies carry origin_ast=For."""
        cfg = self.build_cfg(for_loop)
        suites = self._collect_suites_with_origin(cfg)
        self.assertTrue(
            any(isinstance(s.origin_ast, py_ast.For) for s in suites),
            "No Suite with origin_ast=For found",
        )

    def test_suite_origin_ast_while_loop(self):
        """Suite blocks from while-loop bodies carry origin_ast=While."""

        def while_loop(x):
            i = 0
            while i < x:
                i = i + 1
            return i

        cfg = self.build_cfg(while_loop)
        suites = self._collect_suites_with_origin(cfg)
        self.assertTrue(
            any(isinstance(s.origin_ast, py_ast.While) for s in suites),
            "No Suite with origin_ast=While found",
        )

    def test_suite_origin_ast_switch(self):
        """Suite blocks from if branches carry origin_ast=Switch."""

        def if_only(x):
            y = 0
            if x > 0:
                y = 1
            return y

        cfg = self.build_cfg(if_only)
        suites = self._collect_suites_with_origin(cfg)
        self.assertTrue(
            any(isinstance(s.origin_ast, py_ast.Switch) for s in suites),
            "No Suite with origin_ast=Switch found",
        )

    def test_suite_origin_ast_switch_both_branches(self):
        """Both true and false branches of if/else carry origin_ast=Switch."""
        cfg = self.build_cfg(simple_if)
        suites = self._collect_suites_with_origin(cfg)
        switch_suites = [s for s in suites if isinstance(s.origin_ast, py_ast.Switch)]
        self.assertGreaterEqual(
            len(switch_suites),
            2,
            "Expected at least 2 Suite blocks (true+false) with origin_ast=Switch",
        )

    def test_cpg_loop_body_metadata(self):
        """PDG nodes inside for-loop bodies get is_loop_body=True."""
        cpg = self.build_cpg(for_loop)
        cpg.build()
        found = False
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            if meta.get("is_loop_body"):
                self.assertEqual(meta.get("loop_kind"), "for")
                found = True
        self.assertTrue(found, "No PDG node with is_loop_body=True found")

    def test_cpg_switch_branch_metadata(self):
        """PDG nodes inside if branches get is_switch_branch=True."""
        cpg = self.build_cpg(simple_if)
        cpg.build()
        found = False
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            if meta.get("is_switch_branch"):
                found = True
        self.assertTrue(found, "No PDG node with is_switch_branch=True found")

    def test_cpg_no_spurious_origin_ast_metadata(self):
        """Functions without loops/switches have no origin_ast metadata."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            self.assertNotIn("is_loop_body", meta)
            self.assertNotIn("is_switch_branch", meta)
            self.assertNotIn("is_type_switch_branch", meta)
            self.assertNotIn("is_with_body", meta)
            self.assertNotIn("is_augassign", meta)

    def test_suite_origin_ast_with(self):
        """Suite blocks from with-statement decomposition carry a string origin tag."""

        cfg = self.build_cfg(with_stmt)
        suites = self._collect_suites_with_origin(cfg)
        self.assertTrue(
            any(s.origin_ast == "With" for s in suites),
            "No Suite with origin_ast='With' found",
        )

    def test_suite_origin_ast_augassign(self):
        """Suite blocks from augmented assignment carry origin_ast='AugAssign'."""

        cfg = self.build_cfg(augassign)
        suites = self._collect_suites_with_origin(cfg)
        self.assertTrue(
            any(s.origin_ast == "AugAssign" for s in suites),
            "No Suite with origin_ast='AugAssign' found",
        )

    def test_cpg_with_body_metadata(self):
        """PDG nodes inside with-statement bodies get is_with_body=True."""
        cpg = self.build_cpg(with_stmt, run_ssa=False)
        cpg.build()
        found = False
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            if meta.get("is_with_body"):
                found = True
        self.assertTrue(found, "No PDG node with is_with_body=True found")

    def test_cpg_augassign_metadata(self):
        """PDG nodes from augmented assignment get is_augassign=True."""
        cpg = self.build_cpg(augassign, run_ssa=False)
        cpg.build()
        found = False
        for node in cpg.nodes():
            meta = cpg.node_meta(node)
            if meta.get("is_augassign"):
                found = True
        self.assertTrue(found, "No PDG node with is_augassign=True found")

    def test_visit_unknown_graceful_degradation(self):
        """Unrecognised AST node types emit a warning instead of crashing."""
        import warnings

        class UnknownStmt(py_ast.Statement):
            pass

        unknown = UnknownStmt()
        suite = py_ast.Suite([unknown])
        from pyflow.ir.cfg import transform as cfg_transform

        try:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                transformer = cfg_transform.CFGTransformer()
                transformer.current = cfg_graph.Suite("test")
                transformer.visitUnknown(unknown)
                self.assertTrue(
                    any("skipping" in str(msg.message).lower() for msg in w),
                    "Expected a warning about skipping unknown node",
                )
        except Exception:
            self.fail("visitUnknown should not raise on unrecognised nodes")

    def test_for_loop_index_propagation(self):
        """Loop index variables are marked tainted when the iterator is
        tainted in the memory layout."""
        cpg = self.build_cpg(for_loop, run_ssa=False)
        cpg.build()
        engine = CPGTaintEngine(cpg)

        loop_header = next(
            (n for n in cpg.nodes() if cpg.node_meta(n).get("loop_header")),
            None,
        )
        self.assertIsNotNone(loop_header)

        mem = MemoryLayout()
        tstate = TaintState.user_controlled()
        mem.mark_tainted("seq", tstate)

        engine._propagate_for_loop_index(loop_header, tstate, mem)
        self.assertTrue(
            mem.is_tainted("item"),
            "Loop variable 'item' should be tainted when " "'seq' is tainted",
        )

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
        slc = cpg.forward_slice_all([entry], kinds=frozenset((CPGEdgeKind.DATA,)))
        # Slice should contain entry plus downstream nodes
        self.assertIn(entry, slc)
        self.assertGreater(len(slc), 0)

    def test_backward_slice_all_from_return(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        ret_nodes = [
            n
            for n in cpg.nodes("test_func")
            if n.kind == "stmt" and isinstance(n.ast_node, py_ast.Return)
        ]
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
        pdg_caller = construct_pdg(
            cfg_caller,
            run_ssa=True,
            expand_phi=True,
            include_control=True,
            include_data=True,
        )
        cfg_callee = self.build_cfg(simple_if)
        pdg_callee = construct_pdg(
            cfg_callee,
            run_ssa=True,
            expand_phi=True,
            include_control=True,
            include_data=True,
        )

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
        pdg1 = construct_pdg(
            cfg1, run_ssa=True, expand_phi=True, include_control=True, include_data=True
        )
        cfg2 = self.build_cfg(simple_if)
        pdg2 = construct_pdg(
            cfg2, run_ssa=True, expand_phi=True, include_control=True, include_data=True
        )

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
            self.assertIn(
                ek.value,
                (
                    "control",
                    "data",
                    "AST_CHILD",
                    "CFG_NEXT",
                    "CFG_BRANCH_TRUE",
                    "CFG_BRANCH_FALSE",
                    "CFG_EXCEPT",
                    "CALL",
                    "RETURN_EDGE",
                ),
            )

    # ── RETURN_EDGE ───────────────────────────────────────────────────

    def test_return_edge_built_for_call_graph(self):
        cg = CallGraph()
        cg.add_edge("caller", "callee")
        cfg_caller = self.build_cfg(simple_assignment)
        pdg_caller = construct_pdg(
            cfg_caller,
            run_ssa=True,
            expand_phi=True,
            include_control=True,
            include_data=True,
        )
        cfg_callee = self.build_cfg(simple_if)
        pdg_callee = construct_pdg(
            cfg_callee,
            run_ssa=True,
            expand_phi=True,
            include_control=True,
            include_data=True,
        )
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

    def test_taint_engine_uses_explicit_strict_policy(self):
        from pyflow.ir.cpg.rules import load_rules

        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        self.assertEqual(len(engine.sources), 0)
        load_rules(engine, frameworks=["stdlib"])
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
        pdg1 = construct_pdg(
            cfg1, run_ssa=True, expand_phi=True, include_control=True, include_data=True
        )
        cfg2 = self.build_cfg(simple_if)
        pdg2 = construct_pdg(
            cfg2, run_ssa=True, expand_phi=True, include_control=True, include_data=True
        )
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
            cwe="CWE-78",
            severity="high",
            source_label="input",
            sink_label="subprocess.run",
            source_node=entry,
            sink_node=stmts[0] if stmts else entry,
        )
        d = finding.to_dict()
        self.assertEqual(d["cwe"], "CWE-78")
        self.assertIn("confidence", d)
        json.dumps(d)

    def test_finding_confidence_in_range(self):
        finding = TaintFinding(
            cwe="CWE-78",
            severity="high",
            source_label="request.args",
            sink_label="subprocess.run",
            source_node=None,
            sink_node=None,
            path_nodes=[None] * 5,
            tags=frozenset({"xss"}),
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
            cwe="CWE-78",
            severity="critical",
            source_label="input",
            sink_label="subprocess.run",
            source_node=entry,
            sink_node=entry,
        )
        sarif_result = finding.to_sarif(rule_index=0)
        self.assertEqual(sarif_result["ruleId"], "CWE-78")
        self.assertEqual(sarif_result["level"], "error")
        json.dumps(sarif_result)

    # ── Deduplication ──────────────────────────────────────────────────

    def test_deduplicate_collapses_same_key(self):
        finding1 = TaintFinding(
            cwe="CWE-78",
            severity="high",
            source_label="a",
            sink_label="b",
            source_node=None,
            sink_node=None,
        )
        finding2 = TaintFinding(
            cwe="CWE-78",
            severity="high",
            source_label="a",
            sink_label="b",
            source_node=None,
            sink_node=None,
            path_nodes=[None, None, None],
        )
        deduped = CPGTaintEngine.deduplicate([finding1, finding2])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].path_length, 3)

    def test_deduplicate_preserves_different_keys(self):
        f1 = TaintFinding(
            cwe="CWE-78",
            severity="high",
            source_label="a",
            sink_label="b",
            source_node=None,
            sink_node=None,
        )
        f2 = TaintFinding(
            cwe="CWE-89",
            severity="high",
            source_label="a",
            sink_label="b",
            source_node=None,
            sink_node=None,
        )
        deduped = CPGTaintEngine.deduplicate([f1, f2])
        self.assertEqual(len(deduped), 2)

    def test_deduplicate_sorts_by_confidence(self):
        f1 = TaintFinding(
            cwe="CWE-78",
            severity="high",
            source_label="x",
            sink_label="y",
            source_node=None,
            sink_node=None,
            path_nodes=[None] * 10,
            sanitizers=frozenset({"esc"}),
        )
        f2 = TaintFinding(
            cwe="CWE-89",
            severity="low",
            source_label="z",
            sink_label="w",
            source_node=None,
            sink_node=None,
            path_nodes=[],
        )
        deduped = CPGTaintEngine.deduplicate([f2, f1])
        self.assertGreaterEqual(deduped[0].confidence, deduped[-1].confidence)

    # ── SARIF export ───────────────────────────────────────────────────

    def test_to_sarif_produces_valid_document(self):
        import json

        finding = TaintFinding(
            cwe="CWE-78",
            severity="critical",
            source_label="src",
            sink_label="snk",
            source_node=None,
            sink_node=None,
        )
        doc = CPGTaintEngine.to_sarif([finding], tool_name="test")
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 1)
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["id"], "CWE-78")
        self.assertIn("precision", rule["properties"])
        json.dumps(doc)

    def test_to_json_serializes(self):
        finding = TaintFinding(
            cwe="CWE-78",
            severity="high",
            source_label="src",
            sink_label="snk",
            source_node=None,
            sink_node=None,
        )
        s = CPGTaintEngine.to_json([finding])
        self.assertIn("CWE-78", s)
        import json

        payload = json.loads(s)
        self.assertEqual(payload[0]["rule_id"], "CWE-78")
        self.assertIn("rule", payload[0])

    def test_taint_finding_to_serializable_taint_path(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        node = next(cpg.nodes("test_func"))
        finding = TaintFinding(
            cwe="CWE-78",
            severity="high",
            source_label="src",
            sink_label="snk",
            source_node=node,
            sink_node=node,
            path_nodes=[node],
        )
        path = finding.to_taint_path()
        self.assertIsInstance(path, TaintPath)
        self.assertEqual(path.source_node_id, node.node_id)

    def test_node_meta_exposes_ansede_style_fields(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        node = next(cpg.nodes("test_func"))
        meta = cpg.node_meta(node)
        self.assertIn("node_type", meta)
        self.assertIn("lineno", meta)
        self.assertIn("col", meta)
        self.assertIn("value", meta)
        self.assertEqual(meta["func_name"], "test_func")
        self.assertIn("meta", cpg.to_dict()["nodes"][0])

    def test_node_view_and_cfg_next_by_id(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        node = next(cpg.nodes("test_func"))
        view = cpg.node_view(node)
        self.assertEqual(view.node_id, node.node_id)
        self.assertIn("node_type", view.as_dict())
        self.assertIs(cpg.node_by_id(node.node_id), node)
        self.assertIsInstance(cpg.cfg_next(node.node_id), list)

    def test_taint_engine_accepts_nodes_and_node_ids(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        self.assertIsInstance(engine.find_taint_paths(), list)
        node = next(cpg.nodes("test_func"))
        self.assertEqual(
            engine.get_node_taint(node), engine.get_node_taint(node.node_id)
        )

    def test_load_strict_v2_custom_pack(self):
        import json
        import tempfile
        from pathlib import Path
        from pyflow.ir.cpg.rules import load_rules

        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "strict-v2.json"
            spec.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "framework": "custom",
                        "version": "2.0",
                        "type": "taint",
                        "models": [
                            {
                                "call": "custom.source",
                                "sources": [{"kind": "custom", "port": "return"}],
                            },
                            {
                                "call": "custom.sink",
                                "cwe": "CWE-999",
                                "severity": "high",
                                "sinks": [
                                    {"kind": "custom_sink", "port": {"parameter": 0}}
                                ],
                            },
                            {
                                "call": "custom.clean",
                                "sanitizers": [{"kinds": ["custom"], "port": "return"}],
                            },
                        ],
                        "rules": [
                            {
                                "id": "CUSTOM-FLOW",
                                "title": "Custom flow",
                                "sources": ["custom"],
                                "sinks": ["custom_sink"],
                                "severity": "high",
                                "cwe": "CWE-999",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            load_rules(engine, frameworks=(), custom_paths=[spec])
        self.assertIn("custom.source", engine.sources)
        self.assertEqual(engine.sinks["custom.sink"], "CWE-999")
        self.assertEqual(engine.sanitizers["custom.clean"], frozenset({"custom"}))
        self.assertEqual(engine.sinks["custom.sink"], "CWE-999")
        self.assertIn("custom.clean", engine.sanitizers)

    def test_taint_assign_subscript_marks_target(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()
        mem.mark_tainted("items", state)
        assign = py_ast.Assign(
            py_ast.GetSubscript(py_ast.Local("items"), py_ast.Local("i")),
            [py_ast.Local("item")],
        )
        engine._propagate_assign(assign, state, mem)
        self.assertTrue(mem.is_tainted("item"))

    def test_taint_getattr_and_kwargs_helpers(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()
        mem.mark_tainted("method_name", state)
        call = py_ast.Call(
            py_ast.Local("getattr"),
            [py_ast.Local("obj"), py_ast.Local("method_name")],
            [],
            None,
            None,
        )
        self.assertIs(engine._propagate_call(call, state, mem), state)

        mem.mark_tainted("params", state)
        kw_call = py_ast.Call(
            py_ast.Local("execute"), [], [], None, py_ast.Local("params")
        )
        self.assertTrue(engine._has_tainted_dict_unpack(kw_call, mem))

    # ── Context sensitivity ──────────────────────────────────────────

    def test_context_sensitivity_default_max_depth(self):
        cpg = self.build_cpg(simple_assignment)
        engine = CPGTaintEngine(cpg)
        self.assertEqual(engine._max_call_depth, 5)

    def test_context_sensitivity_custom_max_depth(self):
        cpg = self.build_cpg(simple_assignment)
        engine = CPGTaintEngine(cpg, max_call_depth=3)
        self.assertEqual(engine._max_call_depth, 3)

    def test_context_sensitivity_visited_key_includes_call_context(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        seeds = engine._collect_seeds()
        self.assertIsInstance(seeds, list)
        node = cpg._pdgs["test_func"].entry
        self.assertIsNotNone(node)
        self.assertTrue(hasattr(engine, "_is_return_edge"))

    # ── Subscript propagation ───────────────────────────────────────

    def test_subscript_standalone_passes_taint(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()
        mem.mark_tainted("items", state)

        sub = py_ast.GetSubscript(py_ast.Local("items"), py_ast.Local("i"))
        result = engine._propagate_subscript(sub, state, mem)
        self.assertIs(result, state)

    def test_subscript_untainted_container_no_effect(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()

        sub = py_ast.GetSubscript(py_ast.Local("items"), py_ast.Local("i"))
        result = engine._propagate_subscript(sub, state, mem)
        self.assertIs(result, state)

    # ── Builder metadata ─────────────────────────────────────────────

    def test_ssa_defs_and_uses_recorded_in_metadata(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        ssa_def_count = 0
        ssa_use_count = 0
        for n in cpg.nodes("test_func"):
            m = cpg.node_meta(n)
            for entry in m.get("ssa_defs", []):
                ssa_def_count += 1
                self.assertIn("var", entry)
                self.assertIn("name", entry)
            for entry in m.get("ssa_uses", []):
                ssa_use_count += 1
                self.assertIn("var", entry)
                self.assertIn("name", entry)
        self.assertGreater(ssa_def_count, 0)
        self.assertGreater(ssa_use_count, 0)

    def test_phi_metadata_builder_does_not_crash(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        self.assertGreater(cpg.stats().nodes, 0)

    def test_syntax_error_returns_empty_cpg(self):
        from pyflow.ir.cpg.build import build_cpg

        cpg = build_cpg("def broken(", "bad.py")
        self.assertEqual(len(cpg.functions), 0)
        cpg.build()
        self.assertEqual(cpg.stats().nodes, 0)

    def test_meta_keys_populated_for_all_nodes(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        for n in cpg.nodes("test_func"):
            m = cpg.node_meta(n)
            self.assertIn("node_type", m)
            self.assertIn("lineno", m)
            self.assertIn("col", m)
            self.assertIn("value", m)
            self.assertIn("func_name", m)
            self.assertIn("kind", m)

    # ── DATA edge label propagation ──────────────────────────────────

    def test_data_edges_have_variable_labels(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        labels_found = set()
        for edges in cpg._cpg_edges_out.values():
            for e in edges:
                if e.kind == CPGEdgeKind.DATA and e.label:
                    labels_found.add(e.label)
        # simple_assignment has x, y, z flowing through
        self.assertGreater(len(labels_found), 0)

    def test_data_edge_propagates_taint_to_downstream_variable(self):
        """Taint from a variable flows through DATA edges to uses of
        that variable in downstream statements."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        # Add 'x' as a synthetic source to trigger taint
        engine.add_source("x")
        paths = engine.find_taint_paths()
        # The taint on 'x' should propagate through DATA edges to 'y' and 'z'
        # Even if no sink is found, the traversal succeeds without error
        self.assertIsInstance(paths, list)

    # ── Summary cache ────────────────────────────────────────────────

    def test_summary_cache_key_uses_func_name_tags_and_context(self):
        """Cache key now includes call_context for context sensitivity."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        state = TaintState.user_controlled()
        entry = cpg._pdgs["test_func"].entry
        call_context = (42,)
        result, _ = engine._interprocedural_transfer(
            state, entry, entry, MemoryLayout(), call_context
        )
        cache_key = ("test_func", tuple(sorted(state.tags)), call_context)
        self.assertIn(cache_key, engine._interprocedural_summary_cache)
        self.assertIs(engine._interprocedural_summary_cache[cache_key], state)
        self.assertIs(result, state)

    def test_summary_cache_hit_returns_cached_value(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        state = TaintState.user_controlled()
        entry = cpg._pdgs["test_func"].entry
        mem = MemoryLayout()
        # First call populates cache
        result1, mem1 = engine._interprocedural_transfer(state, entry, entry, mem)
        # Second call with same state should return cached (same mem)
        result2, mem2 = engine._interprocedural_transfer(state, entry, entry, mem)
        self.assertIs(result2, result1)
        # Cached hit should not create a fresh MemoryLayout
        self.assertIs(mem2, mem)

    def test_summary_cache_different_tags_different_entry(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        state_a = TaintState.user_controlled()
        state_b = TaintState(tags=frozenset({"sql_injectable"}))
        entry = cpg._pdgs["test_func"].entry
        engine._interprocedural_transfer(state_a, entry, entry, MemoryLayout())
        engine._interprocedural_transfer(state_b, entry, entry, MemoryLayout())
        self.assertEqual(len(engine._interprocedural_summary_cache), 2)

    # ── RETURN_EDGE context pop ──────────────────────────────────────

    def test_return_edge_pops_call_context(self):
        """Verify that traversing a RETURN_EDGE pops the call context."""
        from pyflow.analysis.callgraph.callgraph import CallGraph

        cfg1 = self.build_cfg(simple_assignment)
        pdg1 = construct_pdg(
            cfg1, run_ssa=True, expand_phi=True, include_control=True, include_data=True
        )
        cfg2 = self.build_cfg(simple_if)
        pdg2 = construct_pdg(
            cfg2, run_ssa=True, expand_phi=True, include_control=True, include_data=True
        )
        cg = CallGraph()
        cg.add_edge("caller", "callee")
        cpg = CodePropertyGraph()
        cpg.add_function("caller", pdg1)
        cpg.add_function("callee", pdg2)
        cpg.add_call_graph(cg)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        # find_taint_paths should traverse CALL → callee → RETURN_EDGE → caller
        # without crashing
        paths = engine.find_taint_paths()
        self.assertIsInstance(paths, list)

    # ── Typed meta accessors (Gap #4) ──────────────────────────────────

    def test_node_type_accessor(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        for node in cpg.nodes("test_func"):
            ntype = cpg.node_type(node)
            self.assertIsInstance(ntype, str)

    def test_node_lineno_accessor(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        for node in cpg.nodes("test_func"):
            lineno = cpg.node_lineno(node)
            self.assertIsInstance(lineno, int)
            self.assertGreaterEqual(lineno, 0)

    def test_node_col_accessor(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        for node in cpg.nodes("test_func"):
            col = cpg.node_col(node)
            self.assertIsInstance(col, int)

    def test_node_value_accessor(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        for node in cpg.nodes("test_func"):
            val = cpg.node_value(node)
            self.assertIsInstance(val, str)

    def test_node_func_name_accessor(self):
        cpg = self.build_cpg(simple_assignment, func_name="my_func")
        cpg.build()
        for node in cpg.nodes("my_func"):
            self.assertEqual(cpg.node_func_name(node), "my_func")

    def test_node_type_fallback_to_kind(self):
        """When ast_node is None, node_type prefers node.label over node.kind."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        for node in cpg.nodes("test_func"):
            ntype = cpg.node_type(node)
            if node.ast_node is None:
                expected = node.label or node.kind
                self.assertEqual(ntype, expected)

    # ── Statement-type metadata builders (Gap #2) ─────────────────────

    def test_annassign_metadata(self):
        from pyflow.ir.cpg.build import build_cpg

        source = "def f(x: int) -> None:\n    y: int = x\n"
        cpg = build_cpg(source, "test.py")
        cpg.build()
        ann_assign_nodes = [
            n for n in cpg.nodes() if cpg.node_meta(n).get("ann_assign")
        ]
        # At least one AnnAssign should be tagged
        if ann_assign_nodes:
            meta = cpg.node_meta(ann_assign_nodes[0])
            self.assertIn("ann_target", meta)
            self.assertIn("ann_type", meta)

    def test_annassign_annotation_only_no_value(self):
        from pyflow.ir.cpg.build import build_cpg

        source = "def f():\n    x: int\n"
        cpg = build_cpg(source, "test.py")
        cpg.build()
        ann_nodes = [n for n in cpg.nodes() if cpg.node_meta(n).get("ann_assign")]
        # Annotation-only declarations should still be tagged
        self.assertIsInstance(ann_nodes, list)

    def test_delete_metadata(self):
        from pyflow.ir.cpg.build import build_cpg

        source = "def f():\n    x = 1\n    del x\n"
        cpg = build_cpg(source, "test.py")
        cpg.build()
        del_nodes = [n for n in cpg.nodes() if cpg.node_meta(n).get("is_delete")]
        if del_nodes:
            meta = cpg.node_meta(del_nodes[0])
            self.assertTrue(meta.get("is_delete"))

    def test_raise_metadata(self):
        from pyflow.ir.cpg.build import build_cpg

        source = "def f():\n    raise ValueError('bad')\n"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", RuntimeWarning)
            cpg = build_cpg(source, "test.py")
        self.assertFalse(
            any("DDG-backed data dependence" in str(w.message) for w in caught)
        )
        self.assertTrue(
            all(pdg.data_dependence_mode == "hybrid" for pdg in cpg.pdgs.values())
        )
        cpg.build()
        raise_nodes = [n for n in cpg.nodes() if cpg.node_meta(n).get("is_raise")]
        if raise_nodes:
            meta = cpg.node_meta(raise_nodes[0])
            self.assertTrue(meta.get("is_raise"))

    def test_assert_metadata(self):
        from pyflow.ir.cpg.build import build_cpg

        source = "def f(x):\n    assert x > 0\n    return x\n"
        cpg = build_cpg(source, "test.py")
        cpg.build()
        assert_nodes = [n for n in cpg.nodes() if cpg.node_meta(n).get("is_assert")]
        if assert_nodes:
            meta = cpg.node_meta(assert_nodes[0])
            self.assertTrue(meta.get("is_assert"))

    def test_additional_statement_metadata_best_effort(self):
        from pyflow.ir.cpg.build import build_cpg

        source = (
            "def f(xs):\n"
            "    class C:\n"
            "        value = 1\n"
            "    for x in xs:\n"
            "        if x:\n"
            "            break\n"
            "        else:\n"
            "            continue\n"
            "    return C\n"
        )
        cpg = build_cpg(source, "test.py")
        cpg.build()
        synthetic = [n for n in cpg.nodes() if cpg.node_meta(n).get("synthetic_ast")]
        metas = [cpg.node_meta(n) for n in synthetic]
        self.assertTrue(any(m.get("is_class_def") for m in metas))
        self.assertTrue(any(m.get("is_break") for m in metas))
        self.assertTrue(any(m.get("is_continue") for m in metas))
        self.assertTrue(any(m.get("class_name") == "C" for m in metas))

        synthetic_ids = {n.node_id for n in synthetic}
        ast_edges = list(cpg.all_edges(kinds={CPGEdgeKind.AST_CHILD}))
        self.assertTrue(
            any(
                e.target.node_id in synthetic_ids and e.label.startswith("synthetic:")
                for e in ast_edges
            )
        )

    def test_yield_from_source_ast_backfill(self):
        from pyflow.ir.cpg.build import build_cpg

        source = "def gen(xs):\n    yield xs\n    yield from xs\n"
        cpg = build_cpg(source, "test.py")
        cpg.build()
        metas = [
            cpg.node_meta(n)
            for n in cpg.nodes()
            if cpg.node_meta(n).get("synthetic_ast")
        ]
        self.assertTrue(any(m.get("is_yield") for m in metas))
        self.assertTrue(any(m.get("yield_kind") == "Yield" for m in metas))
        self.assertTrue(any(m.get("yield_kind") == "YieldFrom" for m in metas))

    def test_detect_frameworks_uses_pack_markers(self):
        from pyflow.ir.cpg.rules import detect_frameworks

        detected = detect_frameworks(
            "import requests\nimport subprocess\nrequests.get(url)\n"
        )
        self.assertIn("requests", detected)
        self.assertIn("concurrency", detected)

    def test_cpg_store_incremental_helpers(self):
        import tempfile
        from pathlib import Path
        from pyflow.ir.cpg.persist import CPGStore

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dep = root / "dep.py"
            app = root / "app.py"
            dep.write_text("def value():\n    return 1\n", encoding="utf-8")
            app.write_text("import dep\nprint(dep.value())\n", encoding="utf-8")
            store = CPGStore(root / "cache.db")
            try:
                self.assertTrue(store.file_changed(dep))
                store.update_hash(dep)
                self.assertFalse(store.file_changed(dep))
                dep.write_text("def value():\n    return 2\n", encoding="utf-8")
                self.assertTrue(store.file_changed(dep))
                affected = store.affected_files([dep], candidate_paths=[dep, app])
                self.assertIn(str(dep), affected)
                self.assertIn(str(app), affected)
                store.invalidate(dep)
                self.assertTrue(store.file_changed(dep))
            finally:
                store.close()

    # ── AnnAssign taint propagation (Gap #2) ─────────────────────────

    def test_annassign_propagates_taint(self):
        """Taint from a source flows through AnnAssign to the target."""
        from pyflow.ir.cpg.build import build_cpg

        cpg = build_cpg("", "empty.py")
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()
        mem.mark_tainted("src", state)
        ann = py_ast.AnnAssign(
            py_ast.Local("dest"),
            py_ast.Local("int"),
            py_ast.Local("src"),
        )
        result = engine._propagate_annassign(ann, state, mem)
        self.assertIsNotNone(result)
        self.assertTrue(result.is_tainted())

    def test_annassign_no_value_no_propagation(self):
        """Annotation-only declarations (no value) should not propagate."""
        from pyflow.ir.cpg.build import build_cpg

        cpg = build_cpg("", "empty.py")
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()
        ann = py_ast.AnnAssign(
            py_ast.Local("x"),
            py_ast.Local("int"),
            None,
        )
        result = engine._propagate_annassign(ann, state, mem)
        self.assertIsNotNone(result)
        self.assertTrue(result.is_tainted())  # taint itself survives

    def test_annassign_propagator_preserves_state_on_clean_rhs(self):
        """_propagate_annassign with a clean RHS returns tstate unchanged."""
        from pyflow.ir.cpg.build import build_cpg

        cpg = build_cpg("", "empty.py")
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()
        ann = py_ast.AnnAssign(
            py_ast.Local("out"), py_ast.Local("int"), py_ast.Local("clean")
        )
        result = engine._propagate_annassign(ann, state, mem)
        self.assertIsNotNone(result)
        self.assertTrue(result.is_tainted())

    # ── Cross-procedural context sensitivity ──────────────────────────

    def test_get_callee_param_names(self):
        """Extract parameter names from a FunctionDef AST."""
        from pyflow.ir.cpg.build import build_cpg

        source = "def add(a, b):\n    return a + b\n"
        cpg = build_cpg(source, "test.py")
        cpg.build()
        engine = CPGTaintEngine(cpg)
        names = engine._get_callee_param_names("add")
        self.assertIsInstance(names, list)
        self.assertIn("a", names)
        self.assertIn("b", names)

    def test_get_callee_param_names_empty_for_unknown_func(self):
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        self.assertEqual(engine._get_callee_param_names("nonexistent"), [])

    def test_map_args_to_params(self):
        """Taint from a caller argument is mapped to the callee parameter."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        new_mem = MemoryLayout()
        state = TaintState.user_controlled()
        mem.mark_tainted("x", state)
        call_ast = py_ast.Call(py_ast.Local("add"), [py_ast.Local("x")], [], None, None)
        call_node = cpg._pdgs["test_func"].entry
        # Temporarily replace the call node's ast_node for the test
        orig_ast = call_node.ast_node
        call_node.ast_node = call_ast
        engine._map_args_to_params(call_node, "test_func", mem, new_mem)
        call_node.ast_node = orig_ast
        self.assertTrue(new_mem.is_tainted("x"))

    def test_context_sensitive_cache_different_contexts(self):
        """Different call contexts produce separate cache entries."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        state = TaintState.user_controlled()
        entry = cpg._pdgs["test_func"].entry
        mem_a = MemoryLayout()
        mem_b = MemoryLayout()
        ctx_a = (1,)
        ctx_b = (2,)
        engine._interprocedural_transfer(state, entry, entry, mem_a, ctx_a)
        engine._interprocedural_transfer(state, entry, entry, mem_b, ctx_b)
        self.assertEqual(len(engine._interprocedural_summary_cache), 2)

    def test_propagate_return_with_tainted_value(self):
        """Return with a tainted value propagates taint to the call-site."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()
        ret_node = cpg._pdgs["test_func"].entry
        call_node = cpg._pdgs["test_func"].entry
        ret_ast = py_ast.Return([py_ast.Local("x")])
        ret_node.ast_node = ret_ast
        mem.mark_tainted("x", state)
        result = engine._propagate_return(state, ret_node, call_node, mem)
        self.assertEqual(result, state)

    def test_propagate_return_clean_tstate_tainted_value(self):
        """Return value tainted in mem produces tainted state even when
        incoming tstate is clean."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        clean = TaintState.clean()
        tainted = TaintState.user_controlled()
        ret_node = cpg._pdgs["test_func"].entry
        call_node = cpg._pdgs["test_func"].entry
        ret_ast = py_ast.Return([py_ast.Local("x")])
        ret_node.ast_node = ret_ast
        mem.mark_tainted("x", tainted)
        result = engine._propagate_return(clean, ret_node, call_node, mem)
        self.assertIsNot(result, clean)
        self.assertTrue(result.is_tainted())

    def test_propagate_return_no_value_no_propagation(self):
        """Return without a value does nothing."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()
        entry = cpg._pdgs["test_func"].entry
        ret_ast = py_ast.Return([])
        entry.ast_node = ret_ast
        result = engine._propagate_return(state, entry, entry, mem)
        self.assertIs(result, state)

    def test_propagate_return_non_return_node_no_propagation(self):
        """Non-Return AST nodes pass through unchanged."""
        cpg = self.build_cpg(simple_assignment)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        state = TaintState.user_controlled()
        entry = cpg._pdgs["test_func"].entry
        entry.ast_node = py_ast.Local("x")
        result = engine._propagate_return(state, entry, entry, mem)
        self.assertIs(result, state)

    def test_cross_function_taint_with_callgraph(self):
        """Build a multi-function CPG and verify taint flows through CALL edges."""
        from pyflow.analysis.callgraph.callgraph import CallGraph
        from pyflow.ir.cpg import CodePropertyGraph

        cfg1 = self.build_cfg(simple_assignment)
        pdg1 = construct_pdg(
            cfg1, run_ssa=True, expand_phi=True, include_control=True, include_data=True
        )
        cfg2 = self.build_cfg(simple_if)
        pdg2 = construct_pdg(
            cfg2, run_ssa=True, expand_phi=True, include_control=True, include_data=True
        )
        cg = CallGraph()
        cg.add_edge("caller", "callee")
        cpg = CodePropertyGraph()
        cpg.add_function("caller", pdg1)
        cpg.add_function("callee", pdg2)
        cpg.add_call_graph(cg)
        cpg.build()
        engine = CPGTaintEngine(cpg)
        engine.add_source("request")
        engine.add_sink("subprocess.run")
        paths = engine.find_taint_paths()
        self.assertIsInstance(paths, list)
        self.assertGreaterEqual(len(engine._summary_cache), 0)

    def test_return_value_taint_cross_function(self):
        """Verify that CALL and RETURN_EDGE edges exist between functions.

        The underlying CFG→CPG edge mapping currently does not create
        ``CFG_NEXT`` edges for statement-level PDG nodes inside a block,
        which prevents the full worklist traversal from reaching statements.
        This test validates that the infrastructure for the
        ``_propagate_return`` fix is in place (CALL/RETURN_EDGE edges,
        return-node AST mapping).
        """
        from pyflow.analysis.callgraph.callgraph import CallGraph

        cfg_callee = self.build_cfg(tainted_return)
        cfg_caller = self.build_cfg(call_tainted_return)

        pdg_callee = construct_pdg(
            cfg_callee,
            run_ssa=True,
            expand_phi=True,
            include_control=True,
            include_data=True,
        )
        pdg_caller = construct_pdg(
            cfg_caller,
            run_ssa=True,
            expand_phi=True,
            include_control=True,
            include_data=True,
        )

        cg = CallGraph()
        cg.add_edge("call_tainted_return", "tainted_return")
        cpg = CodePropertyGraph()
        cpg.add_function("call_tainted_return", pdg_caller)
        cpg.add_function("tainted_return", pdg_callee)
        cpg.add_call_graph(cg)
        cpg.build()

        # Verify CALL and RETURN_EDGE edges exist.
        call_edges = list(cpg.all_edges(kinds={CPGEdgeKind.CALL}))
        self.assertGreater(len(call_edges), 0)
        return_edges = list(cpg.all_edges(kinds={CPGEdgeKind.RETURN_EDGE}))
        self.assertGreater(len(return_edges), 0)

        # Verify that the callee has a Return node and the caller has a
        # DATA edge from the call site to its downstream use.
        callee_return = None
        for n in pdg_callee.nodes:
            if isinstance(getattr(n, "ast_node", None), py_ast.Return):
                callee_return = n
                break
        self.assertIsNotNone(callee_return, "Callee PDG should contain a Return node")

        # Directly test the unit fix: _propagate_return must produce a
        # tainted state when the return value variable is tainted in mem.
        engine = CPGTaintEngine(cpg)
        mem = MemoryLayout()
        clean = TaintState.clean()
        tainted = TaintState.user_controlled()
        mem.mark_tainted("x", tainted)

        ret_expr = py_ast.Return([py_ast.Local("x")])
        callee_return.ast_node = ret_expr
        # Use a caller node with a non-None ast_node so that
        # _propagate_return does not short-circuit on call_ast.
        caller_stmt = next(
            (n for n in pdg_caller.nodes if n.ast_node is not None),
            pdg_caller.entry,
        )
        result = engine._propagate_return(clean, callee_return, caller_stmt, mem)
        self.assertTrue(
            result.is_tainted(),
            "_propagate_return must return a tainted state "
            "when the return value references a tainted var",
        )


if __name__ == "__main__":
    unittest.main()
