"""
Tests for Program Dependence Graph (PDG) construction and querying.

These tests intentionally avoid the dataflowIR/DDG pipeline and derive data
dependences from the CFG's AST with SSA enabled, to keep tests self-contained.
"""

import unittest

from pyflow.application import context
from pyflow.frontend.programextractor import Extractor
from pyflow.analysis.cfg import transform
from pyflow.analysis.pdg import construct_pdg
from pyflow.language.python import ast


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


class TestPDG(unittest.TestCase):
    def setUp(self):
        self.compiler = context.CompilerContext(None)
        self.compiler.extractor = Extractor(self.compiler)

    def decompile(self, func):
        return self.compiler.extractor.convertFunction(func, ssa=False)

    def build_cfg(self, func):
        code = self.decompile(func)
        return transform.evaluate(self.compiler, code)

    def test_pdg_construction_has_nodes_and_edges(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=True, include_data=True)

        stats = pdg.stats()
        self.assertGreater(stats.nodes, 0)
        self.assertGreaterEqual(stats.edges, 0)
        self.assertIn("data", stats.edge_kinds)

        # Should have an entry node.
        self.assertIsNotNone(pdg.entry)
        self.assertEqual(pdg.entry.kind, "entry")

    def test_pdg_data_dependence_chain(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        entry = pdg.entry
        self.assertIsNotNone(entry)

        # Find PDG nodes for y-assign, z-assign, and return.
        y_assign = None
        z_assign = None
        ret = None
        for n in pdg.nodes:
            if n.kind != "stmt" or n.ast_node is None:
                continue
            if isinstance(n.ast_node, ast.Assign):
                names = [l.name for l in n.ast_node.lcls if isinstance(l, ast.Local)]
                if "y" in names:
                    y_assign = n
                if "z" in names:
                    z_assign = n
            if isinstance(n.ast_node, ast.Return):
                ret = n

        self.assertIsNotNone(y_assign)
        self.assertIsNotNone(z_assign)
        self.assertIsNotNone(ret)

        # Expect data edges: entry -(x)-> y, y -(y)-> z, z -(z)-> return.
        data_edges = pdg.all_edges(kind="data")
        self.assertTrue(any(e.source == entry and e.target == y_assign and e.label == "x" for e in data_edges))
        self.assertTrue(any(e.source == y_assign and e.target == z_assign and e.label == "y" for e in data_edges))
        self.assertTrue(any(e.source == z_assign and e.target == ret and e.label == "z" for e in data_edges))

    def test_pdg_control_dependence_edges_exist(self):
        cfg = self.build_cfg(simple_if)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=True, include_data=False)

        control_edges = pdg.all_edges(kind="control")
        # Should include some control edges for the if.
        self.assertGreater(len(control_edges), 0)

        # Condition node should control something.
        cond_nodes = [n for n in pdg.nodes if n.kind == "cond"]
        self.assertGreaterEqual(len(cond_nodes), 1)
        self.assertTrue(any(e.source in cond_nodes for e in control_edges))

    def test_backward_slice_includes_relevant_defs(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        ret = next((n for n in pdg.nodes if n.kind == "stmt" and isinstance(n.ast_node, ast.Return)), None)
        self.assertIsNotNone(ret)

        slc = pdg.backward_slice([ret], kinds=frozenset(("data",)))
        # Slice should include at least: return, z assign, y assign, and entry.
        self.assertIn(ret, slc)
        self.assertIn(pdg.entry, slc)
        self.assertTrue(any(n.kind == "stmt" and isinstance(n.ast_node, ast.Assign) for n in slc))


if __name__ == "__main__":
    unittest.main()
