"""
Tests for Control Dependence Graph (CDG) construction and analysis.

This module tests the CDG construction from CFG, including:
- Basic CDG construction
- Control dependence relationships
- Dominance frontier computation
- Post-dominator computation
- CDG graph structure and statistics
"""

import unittest

from pyflow.application import context
from pyflow.frontend.programextractor import Extractor
from pyflow.analysis.cfg import transform
from pyflow.analysis.cdg import construct_cdg, analyze_control_dependencies
from pyflow.analysis.cdg.graph import ControlDependenceGraph, CDGNode, CDGEdge


def simple_if(x):
    """Simple if statement."""
    if x > 0:
        y = 1
    else:
        y = -1
    return y


def nested_if(x, y):
    """Nested if statements."""
    if x > 0:
        if y > 0:
            z = 1
        else:
            z = -1
    else:
        z = 0
    return z


def if_with_loop(x):
    """If statement followed by a loop."""
    if x > 0:
        result = 0
        while x > 0:
            result += x
            x -= 1
    else:
        result = -1
    return result


def sequential_ifs(x, y):
    """Sequential if statements."""
    if x > 0:
        a = 1
    if y > 0:
        b = 1
    return a + b


def loop_with_break(x):
    """Loop with break statement."""
    result = 0
    while x > 0:
        if x == 5:
            break
        result += x
        x -= 1
    return result


class TestCDG(unittest.TestCase):
    """Test cases for Control Dependence Graph construction."""

    def setUp(self):
        """Set up test fixtures."""
        self.compiler = context.CompilerContext(None)
        self.compiler.extractor = Extractor(self.compiler)

    def decompile(self, func):
        """Decompile a function to CFG IR."""
        return self.compiler.extractor.convertFunction(func, ssa=False)

    def build_cfg(self, func):
        """Build CFG from a function."""
        code = self.decompile(func)
        return transform.evaluate(self.compiler, code)

    def build_cdg(self, func):
        """Build CDG from a function."""
        cfg = self.build_cfg(func)
        return construct_cdg(cfg)

    def test_simple_if_cdg_construction(self):
        """Test CDG construction for a simple if statement."""
        cdg = self.build_cdg(simple_if)
        
        # CDG should have nodes
        self.assertIsInstance(cdg, ControlDependenceGraph)
        self.assertGreater(len(cdg.nodes), 0)
        
        # Should have a root node (entry terminal)
        self.assertIsNotNone(cdg.root_node)
        self.assertEqual(cdg.root_node.cfg_node, cdg.cfg.entryTerminal)
        
        # Check statistics
        stats = cdg.get_statistics()
        self.assertIn('total_nodes', stats)
        self.assertIn('total_edges', stats)
        self.assertGreater(stats['total_nodes'], 0)

    def test_cdg_node_creation(self):
        """Test CDG node creation and retrieval."""
        cdg = self.build_cdg(simple_if)
        
        # Test getting nodes
        entry_node = cdg.get_node(cdg.cfg.entryTerminal)
        self.assertIsNotNone(entry_node)
        self.assertIsInstance(entry_node, CDGNode)
        
        # Test adding node (should return existing if already present)
        node1 = cdg.add_node(cdg.cfg.entryTerminal)
        node2 = cdg.add_node(cdg.cfg.entryTerminal)
        self.assertEqual(node1, node2)

    def test_control_dependence_edges(self):
        """Test control dependence edge creation."""
        cdg = self.build_cdg(simple_if)
        
        # Get all edges
        edges = cdg.get_all_edges()
        self.assertIsInstance(edges, list)
        
        # Check edge structure
        for edge in edges:
            self.assertIsInstance(edge, CDGEdge)
            self.assertIsInstance(edge.source, CDGNode)
            self.assertIsInstance(edge.target, CDGNode)
            self.assertIsInstance(edge.label, str)

    def test_control_dependents(self):
        """Test getting control dependents."""
        cdg = self.build_cdg(simple_if)
        
        # Get entry node
        entry_node = cdg.get_node(cdg.cfg.entryTerminal)
        if entry_node:
            # Entry should have some dependents (or none, depending on structure)
            dependents = cdg.get_control_dependents(cdg.cfg.entryTerminal)
            self.assertIsInstance(dependents, set)

    def test_control_dependencies(self):
        """Test getting control dependencies."""
        cdg = self.build_cdg(simple_if)
        
        # Get all nodes
        all_nodes = cdg.get_all_nodes()
        self.assertGreater(len(all_nodes), 0)
        
        # Check dependencies for each node
        for node in all_nodes:
            dependencies = cdg.get_control_dependencies(node.cfg_node)
            self.assertIsInstance(dependencies, set)

    def test_nested_if_cdg(self):
        """Test CDG construction for nested if statements."""
        cdg = self.build_cdg(nested_if)
        
        stats = cdg.get_statistics()
        # Nested ifs should create more control dependencies
        self.assertGreater(stats['total_nodes'], 0)
        self.assertGreaterEqual(stats['total_edges'], 0)

    def test_loop_cdg(self):
        """Test CDG construction for loops."""
        cdg = self.build_cdg(if_with_loop)
        
        stats = cdg.get_statistics()
        # Loops should create control dependencies
        self.assertGreater(stats['total_nodes'], 0)

    def test_cdg_statistics(self):
        """Test CDG statistics generation."""
        cdg = self.build_cdg(simple_if)
        stats = cdg.get_statistics()
        
        # Check required statistics fields
        required_fields = ['total_nodes', 'total_edges', 'node_types', 
                          'edge_labels', 'has_root']
        for field in required_fields:
            self.assertIn(field, stats)
        
        # Check types
        self.assertIsInstance(stats['total_nodes'], int)
        self.assertIsInstance(stats['total_edges'], int)
        self.assertIsInstance(stats['node_types'], dict)
        self.assertIsInstance(stats['edge_labels'], dict)
        self.assertIsInstance(stats['has_root'], bool)

    def test_analyze_control_dependencies(self):
        """Test control dependency analysis function."""
        cfg = self.build_cfg(simple_if)
        analysis = analyze_control_dependencies(cfg)
        
        # Should return a dictionary with statistics
        self.assertIsInstance(analysis, dict)
        self.assertIn('total_nodes', analysis)
        self.assertIn('dominance_frontiers', analysis)
        self.assertIn('post_dominators', analysis)

    def test_cdg_node_relationships(self):
        """Test CDG node relationship methods."""
        cdg = self.build_cdg(simple_if)
        
        nodes = cdg.get_all_nodes()
        if len(nodes) > 1:
            node1, node2 = nodes[0], nodes[1]
            
            # Test is_control_dependent_on
            result = node1.is_control_dependent_on(node2)
            self.assertIsInstance(result, bool)
            
            # Test controls
            result = node1.controls(node2)
            self.assertIsInstance(result, bool)

    def test_cdg_edge_labels(self):
        """Test CDG edge label handling."""
        cdg = self.build_cdg(simple_if)
        
        edges = cdg.get_all_edges()
        for edge in edges:
            # Edge should have a label (may be empty string)
            self.assertIsNotNone(edge.label)
            self.assertIsInstance(edge.label, str)

    def test_sequential_ifs_cdg(self):
        """Test CDG for sequential if statements."""
        cdg = self.build_cdg(sequential_ifs)
        
        stats = cdg.get_statistics()
        self.assertGreater(stats['total_nodes'], 0)

    def test_loop_with_break_cdg(self):
        """Test CDG for loop with break statement."""
        cdg = self.build_cdg(loop_with_break)
        
        stats = cdg.get_statistics()
        self.assertGreater(stats['total_nodes'], 0)

    def test_cdg_control_conditions(self):
        """Test getting control conditions for nodes."""
        cdg = self.build_cdg(simple_if)
        
        all_nodes = cdg.get_all_nodes()
        for node in all_nodes:
            conditions = cdg.get_control_conditions(node.cfg_node)
            self.assertIsInstance(conditions, dict)

    def test_cdg_is_control_dependent(self):
        """Test checking if one node is control dependent on another."""
        cdg = self.build_cdg(simple_if)
        
        all_cfg_nodes = list(cdg.nodes.keys())
        if len(all_cfg_nodes) > 1:
            node1, node2 = all_cfg_nodes[0], all_cfg_nodes[1]
            result = cdg.is_control_dependent(node1, node2)
            self.assertIsInstance(result, bool)

    def test_cdg_repr(self):
        """Test CDG string representation."""
        cdg = self.build_cdg(simple_if)
        repr_str = repr(cdg)
        self.assertIsInstance(repr_str, str)
        self.assertIn('ControlDependenceGraph', repr_str)


if __name__ == "__main__":
    unittest.main()
