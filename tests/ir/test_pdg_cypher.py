import unittest

from pyflow.application import context
from pyflow.frontend.programextractor import Extractor
from pyflow.analysis.cfg import transform
from pyflow.analysis.pdg import construct_pdg


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


class TestPDGCypher(unittest.TestCase):
    def setUp(self):
        self.compiler = context.CompilerContext(None)
        self.compiler.extractor = Extractor(self.compiler)

    def decompile(self, func):
        return self.compiler.extractor.convertFunction(func, ssa=False)

    def build_cfg(self, func):
        code = self.decompile(func)
        return transform.evaluate(self.compiler, code)

    def test_match_nodes_return_properties(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        rows = pdg.cypher('MATCH (n:stmt) RETURN n.kind AS k, n.node_id AS id ORDER BY id ASC LIMIT 10')
        self.assertGreaterEqual(len(rows), 1)
        self.assertTrue(all(r["k"] == "stmt" for r in rows))
        self.assertTrue(all(isinstance(r["id"], int) for r in rows))

    def test_match_data_edges_with_where_and_params(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        rows = pdg.cypher(
            'MATCH (a:stmt)-[e:data]->(b:stmt) WHERE e.label = $lbl RETURN a.node_id AS src, b.node_id AS dst LIMIT 20',
            params={"lbl": "y"},
        )
        self.assertGreaterEqual(len(rows), 1)
        for r in rows:
            self.assertIsInstance(r["src"], int)
            self.assertIsInstance(r["dst"], int)

    def test_match_control_edges(self):
        cfg = self.build_cfg(simple_if)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=True, include_data=False)

        rows = pdg.cypher("MATCH (c:cond)-[:control]->(n) RETURN c.node_id AS cid, n.kind AS nk LIMIT 50")
        self.assertGreaterEqual(len(rows), 1)
        self.assertTrue(all(isinstance(r["cid"], int) for r in rows))

    def test_return_star_includes_bound_variables(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        rows = pdg.cypher("MATCH (a:stmt)-[e:data]->(b) RETURN * LIMIT 5")
        self.assertGreaterEqual(len(rows), 1)
        for r in rows:
            self.assertIn("a", r)
            self.assertIn("e", r)
            self.assertIn("b", r)

    def test_skip_and_limit(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        rows = pdg.cypher("MATCH (n:stmt) RETURN n.node_id AS id ORDER BY id ASC SKIP 1 LIMIT 1")
        self.assertEqual(len(rows), 1)
        self.assertIsInstance(rows[0]["id"], int)

    def test_variable_length_relationship(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        # Two-hop data path should exist: y-assign -> z-assign -> return
        rows = pdg.cypher("MATCH (a:stmt)-[:data*2]->(b:stmt) RETURN a.node_id AS a, b.node_id AS b LIMIT 50")
        self.assertGreaterEqual(len(rows), 1)

    def test_variable_length_relationship_binds_edge_sequence(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        rows = pdg.cypher("MATCH (a:stmt)-[p:data*2]->(b:stmt) RETURN p LIMIT 5")
        self.assertGreaterEqual(len(rows), 1)
        p = rows[0]["p"]
        self.assertTrue(isinstance(p, tuple))
        self.assertEqual(len(p), 2)

    def test_undirected_relationship_matches(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        rows = pdg.cypher("MATCH (a:stmt)-[:data]-(b:stmt) RETURN a.node_id AS a, b.node_id AS b LIMIT 50")
        self.assertGreaterEqual(len(rows), 1)

    def test_node_pattern_property_map(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        rows = pdg.cypher('MATCH (n {kind: "stmt"}) RETURN count(n) AS c')
        self.assertEqual(rows[0]["c"], 3)

    def test_aggregations_count_and_collect(self):
        cfg = self.build_cfg(simple_assignment)
        pdg = construct_pdg(cfg, run_ssa=True, expand_phi=True, include_control=False, include_data=True)

        rows = pdg.cypher("MATCH (n:stmt) RETURN count(*) AS c, collect(n.kind) AS kinds")
        self.assertEqual(rows[0]["c"], 3)
        self.assertEqual(len(rows[0]["kinds"]), 3)


if __name__ == "__main__":
    unittest.main()
