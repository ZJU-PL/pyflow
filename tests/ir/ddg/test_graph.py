"""Tests for ir/ddg/graph.py - Data Dependence Graph."""

import unittest

from pyflow.ir.ddg.graph import (
    DDGEdge,
    DDGNode,
    DataDependenceGraph,
)


class TestDDGEdge(unittest.TestCase):
    """Test cases for DDGEdge class."""

    def test_init(self):
        """Test DDGEdge initialization."""
        source = DDGNode(1, "op1", "op")
        target = DDGNode(2, "op2", "op")
        edge = DDGEdge(source, target, "def-use", "slot_x")
        
        self.assertIs(edge.source, source)
        self.assertIs(edge.target, target)
        self.assertEqual(edge.kind, "def-use")
        self.assertEqual(edge.label, "slot_x")

    def test_init_default_label(self):
        """Test DDGEdge with default empty label."""
        source = DDGNode(1, "op1", "op")
        target = DDGNode(2, "op2", "op")
        edge = DDGEdge(source, target, "memory")
        
        self.assertEqual(edge.label, "")

    def test_repr(self):
        """Test DDGEdge string representation."""
        source = DDGNode(1, "op1", "op")
        target = DDGNode(2, "op2", "op")
        edge = DDGEdge(source, target, "def-use")
        
        repr_str = repr(edge)
        self.assertIn("DDGEdge", repr_str)
        self.assertIn("def-use", repr_str)


class TestDDGNode(unittest.TestCase):
    """Test cases for DDGNode class."""

    def test_init(self):
        """Test DDGNode initialization."""
        node = DDGNode(1, "ir_node", "op")
        
        self.assertEqual(node.node_id, 1)
        self.assertEqual(node.ir_node, "ir_node")
        self.assertEqual(node.category, "op")
        self.assertEqual(node.edges_in, set())
        self.assertEqual(node.edges_out, set())

    def test_init_slot_category(self):
        """Test DDGNode with slot category."""
        node = DDGNode(1, "slot", "slot")
        self.assertEqual(node.category, "slot")

    def test_init_phi_category(self):
        """Test DDGNode with phi category."""
        node = DDGNode(1, "phi", "phi")
        self.assertEqual(node.category, "phi")

    def test_add_edge_to(self):
        """Test adding edge to another node."""
        source = DDGNode(1, "op1", "op")
        target = DDGNode(2, "op2", "op")
        
        edge = source.add_edge_to(target, "def-use", "x")
        
        self.assertIn(edge, source.edges_out)
        self.assertIn(edge, target.edges_in)
        self.assertEqual(edge.kind, "def-use")
        self.assertEqual(edge.label, "x")

    def test_add_multiple_edges(self):
        """Test adding multiple edges to same node."""
        source = DDGNode(1, "op1", "op")
        target1 = DDGNode(2, "op2", "op")
        target2 = DDGNode(3, "op3", "op")
        
        source.add_edge_to(target1, "def-use", "x")
        source.add_edge_to(target2, "memory", "RAW")
        
        self.assertEqual(len(source.edges_out), 2)

    def test_repr(self):
        """Test DDGNode string representation."""
        node = DDGNode(1, "ir_node", "op")
        repr_str = repr(node)
        self.assertIn("DDGNode", repr_str)
        self.assertIn("1", repr_str)
        self.assertIn("op", repr_str)

    def test_hash(self):
        """Node IDs are display-local and do not define graph identity."""
        node1 = DDGNode(1, "ir_node", "op")
        node2 = DDGNode(1, "different_ir", "op")

        self.assertNotEqual(hash(node1), hash(node2))

    def test_equality(self):
        """Test DDGNode equality."""
        node1 = DDGNode(1, "ir_node", "op")
        node2 = DDGNode(1, "different_ir", "op")
        node3 = DDGNode(2, "ir_node", "op")
        
        self.assertNotEqual(node1, node2)
        self.assertNotEqual(node1, node3)

    def test_memory_edges_keep_distinct_locations(self):
        source = DDGNode(1, "write", "op")
        target = DDGNode(2, "read", "op")

        first = source.add_edge_to(target, "memory", "RAW", location="a.x")
        second = source.add_edge_to(target, "memory", "RAW", location="b.x")

        self.assertNotEqual(first, second)
        self.assertEqual(len(source.edges_out), 2)

    def test_equality_with_different_type(self):
        """Test DDGNode equality with different types."""
        node = DDGNode(1, "ir_node", "op")
        self.assertNotEqual(node, "not a node")
        self.assertNotEqual(node, None)


class TestDataDependenceGraph(unittest.TestCase):
    """Test cases for DataDependenceGraph class."""

    def test_init(self):
        """Test DataDependenceGraph initialization."""
        ddg = DataDependenceGraph()
        
        self.assertEqual(ddg.nodes, [])
        self.assertEqual(ddg._id, 0)
        self.assertEqual(ddg.op_node_map, {})
        self.assertEqual(ddg.slot_node_map, {})

    def test_new_id(self):
        """Test ID generation."""
        ddg = DataDependenceGraph()
        
        id1 = ddg._new_id()
        id2 = ddg._new_id()
        id3 = ddg._new_id()
        
        self.assertEqual(id1, 0)
        self.assertEqual(id2, 1)
        self.assertEqual(id3, 2)
        self.assertEqual(ddg._id, 3)

    def test_get_or_create_op_node_new(self):
        """Test creating a new operation node."""
        ddg = DataDependenceGraph()
        
        node = ddg.get_or_create_op_node("op1")
        
        self.assertIsInstance(node, DDGNode)
        self.assertEqual(node.node_id, 0)
        self.assertEqual(node.category, "op")
        self.assertEqual(len(ddg.nodes), 1)
        self.assertIn("op1", ddg.op_node_map)

    def test_get_or_create_op_node_existing(self):
        """Test getting existing operation node."""
        ddg = DataDependenceGraph()
        
        node1 = ddg.get_or_create_op_node("op1")
        node2 = ddg.get_or_create_op_node("op1")
        
        self.assertIs(node1, node2)
        self.assertEqual(len(ddg.nodes), 1)

    def test_get_or_create_slot_node_new(self):
        """Test creating a new slot node."""
        ddg = DataDependenceGraph()
        
        node = ddg.get_or_create_slot_node("slot1")
        
        self.assertIsInstance(node, DDGNode)
        self.assertEqual(node.category, "slot")
        self.assertIn("slot1", ddg.slot_node_map)

    def test_get_or_create_slot_node_existing(self):
        """Test getting existing slot node."""
        ddg = DataDependenceGraph()
        
        node1 = ddg.get_or_create_slot_node("slot1")
        node2 = ddg.get_or_create_slot_node("slot1")
        
        self.assertIs(node1, node2)
        self.assertEqual(len(ddg.nodes), 1)

    def test_add_def_use(self):
        """Test adding def-use edge."""
        ddg = DataDependenceGraph()
        
        def_node = ddg.get_or_create_op_node("def_op")
        use_node = ddg.get_or_create_op_node("use_op")
        
        edge = ddg.add_def_use(def_node, use_node, "x")
        
        self.assertEqual(edge.kind, "def-use")
        self.assertEqual(edge.label, "x")
        self.assertIn(edge, def_node.edges_out)
        self.assertIn(edge, use_node.edges_in)

    def test_add_mem_dep(self):
        """Test adding memory dependence edge."""
        ddg = DataDependenceGraph()
        
        node1 = ddg.get_or_create_op_node("op1")
        node2 = ddg.get_or_create_op_node("op2")
        
        edge = ddg.add_mem_dep(node1, node2, "RAW")
        
        self.assertEqual(edge.kind, "memory")
        self.assertEqual(edge.label, "RAW")

    def test_all_edges(self):
        """Test getting all edges."""
        ddg = DataDependenceGraph()
        
        node1 = ddg.get_or_create_op_node("op1")
        node2 = ddg.get_or_create_op_node("op2")
        node3 = ddg.get_or_create_op_node("op3")
        
        ddg.add_def_use(node1, node2, "x")
        ddg.add_def_use(node1, node3, "y")
        
        edges = ddg.all_edges()
        
        self.assertEqual(len(edges), 2)

    def test_stats_empty(self):
        """Test stats on empty graph."""
        ddg = DataDependenceGraph()
        
        stats = ddg.stats()
        
        self.assertEqual(stats["nodes"], 0)
        self.assertEqual(stats["edges"], 0)
        self.assertEqual(stats["ops"], 0)
        self.assertEqual(stats["slots"], 0)

    def test_stats_with_nodes(self):
        """Test stats with nodes and edges."""
        ddg = DataDependenceGraph()
        
        op1 = ddg.get_or_create_op_node("op1")
        op2 = ddg.get_or_create_op_node("op2")
        slot = ddg.get_or_create_slot_node("slot1")
        
        ddg.add_def_use(op1, op2, "x")
        ddg.add_mem_dep(slot, op1, "RAW")
        
        stats = ddg.stats()
        
        self.assertEqual(stats["nodes"], 3)
        self.assertEqual(stats["edges"], 2)
        self.assertEqual(stats["ops"], 2)
        self.assertEqual(stats["slots"], 1)

    def test_mixed_op_and_slot_nodes(self):
        """Test that op and slot nodes are tracked separately."""
        ddg = DataDependenceGraph()
        
        op = ddg.get_or_create_op_node("op1")
        slot = ddg.get_or_create_slot_node("slot1")
        
        self.assertIs(op, ddg.op_node_map["op1"])
        self.assertIs(slot, ddg.slot_node_map["slot1"])

    def test_node_id_uniqueness(self):
        """Test that each node gets a unique ID."""
        ddg = DataDependenceGraph()
        
        nodes = []
        for i in range(5):
            node = ddg.get_or_create_op_node(f"op{i}")
            nodes.append(node)
        
        ids = [n.node_id for n in nodes]
        self.assertEqual(ids, [0, 1, 2, 3, 4])


class TestDDGIntegration(unittest.TestCase):
    """Integration tests for DDG construction."""

    def test_simple_def_use_chain(self):
        """Test building a simple def-use chain."""
        ddg = DataDependenceGraph()
        
        # Create nodes
        assign = ddg.get_or_create_op_node("assign_op")
        use = ddg.get_or_create_op_node("use_op")
        slot = ddg.get_or_create_slot_node("x")
        
        # Build def-use chain: assign -> slot -> use
        ddg.add_def_use(assign, slot, "x")
        ddg.add_def_use(slot, use, "x")
        
        # Verify structure
        self.assertEqual(len(ddg.nodes), 3)
        self.assertEqual(len(ddg.all_edges()), 2)
        
        # Check edges
        assign_edges = list(assign.edges_out)
        self.assertEqual(len(assign_edges), 1)
        self.assertEqual(assign_edges[0].target, slot)
        
        slot_edges_out = list(slot.edges_out)
        self.assertEqual(len(slot_edges_out), 1)
        self.assertEqual(slot_edges_out[0].target, use)

    def test_multiple_uses(self):
        """Test node with multiple outgoing edges."""
        ddg = DataDependenceGraph()
        
        def_node = ddg.get_or_create_op_node("def")
        use1 = ddg.get_or_create_op_node("use1")
        use2 = ddg.get_or_create_op_node("use2")
        
        ddg.add_def_use(def_node, use1, "x")
        ddg.add_def_use(def_node, use2, "x")
        
        self.assertEqual(len(def_node.edges_out), 2)
        self.assertEqual(len(ddg.all_edges()), 2)


if __name__ == "__main__":
    unittest.main()
