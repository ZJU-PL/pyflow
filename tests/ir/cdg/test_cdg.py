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
import importlib.util
import os
import sys
import tempfile
import textwrap
from pathlib import Path

from pyflow.application import context
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import transform
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.ir.cdg import (
    CDGConstructor,
    construct_cdg,
    analyze_control_dependencies,
    dump_cdg,
)
from pyflow.ir.cdg.graph import ControlDependenceGraph, CDGNode, CDGEdge


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

    def build_constructor(self, func):
        """Build a constructor for direct post-dominator inspection."""
        cfg = self.build_cfg(func)
        constructor = CDGConstructor(cfg)
        constructor.construct()
        return constructor

    def load_function_from_source(self, module_name, source, func_name):
        """Load a function from temporary source so inspect-based extraction works."""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
            tmp.write(textwrap.dedent(source))
            tmp_path = tmp.name

        spec = importlib.util.spec_from_file_location(module_name, tmp_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        self.addCleanup(sys.modules.pop, module_name, None)
        self.addCleanup(os.unlink, tmp_path)
        spec.loader.exec_module(module)
        return getattr(module, func_name)

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

    def test_analyze_control_dependencies_uses_unique_node_keys(self):
        """Serialized analysis maps should keep one entry per CFG node."""
        cfg = self.build_cfg(simple_if)
        analysis = analyze_control_dependencies(cfg)

        self.assertEqual(len(analysis["dominance_frontiers"]), analysis["total_nodes"])
        self.assertEqual(len(analysis["post_dominators"]), analysis["total_nodes"])

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

    def test_simple_if_has_switch_to_branch_edges(self):
        """Simple if should create exactly the true/false branch dependences."""
        cdg = self.build_cdg(simple_if)

        edges = sorted(
            (
                type(edge.source.cfg_node).__name__,
                type(edge.target.cfg_node).__name__,
                edge.label,
            )
            for edge in cdg.get_all_edges()
        )

        self.assertEqual(
            edges,
            [
                ("Switch", "Suite", "false"),
                ("Switch", "Suite", "true"),
            ],
        )

    def test_control_dependence_sources_are_branching_nodes(self):
        """Controllers in the CDG should be CFG nodes with multiple normal successors."""
        cdg = self.build_cdg(if_with_loop)

        for edge in cdg.get_all_edges():
            self.assertGreater(len(edge.source.cfg_node.normalForward()), 1)

    def test_loop_self_edges_are_limited_to_loop_switches(self):
        """Any loop self-dependence should stay on the loop condition itself."""
        cdg = self.build_cdg(if_with_loop)

        self.assertTrue(cdg.get_all_edges())
        for edge in cdg.get_all_edges():
            if edge.source.cfg_node is edge.target.cfg_node:
                self.assertIsInstance(edge.source.cfg_node, cfg_graph.Switch)
                self.assertEqual(edge.label, "true")

    def test_nested_if_preserves_indirect_branch_labels(self):
        """Indirectly controlled nodes should retain the originating branch label."""
        cdg = self.build_cdg(nested_if)

        labeled_merge_edges = {
            (
                type(edge.source.cfg_node).__name__,
                type(edge.target.cfg_node).__name__,
                edge.label,
            )
            for edge in cdg.get_all_edges()
        }

        self.assertIn(("Switch", "Merge", "true"), labeled_merge_edges)

    def test_post_dominators_for_simple_if_are_sane(self):
        """Post-dominator relationships should match the if/else join structure."""
        constructor = self.build_constructor(simple_if)
        cfg_nodes = constructor._get_all_cfg_nodes()

        switch = next(node for node in cfg_nodes if isinstance(node, cfg_graph.Switch))
        join = next(
            node
            for node in cfg_nodes
            if isinstance(node, cfg_graph.Merge)
            and len(node.reverse()) == 2
            and all(isinstance(pred, cfg_graph.Suite) for pred in node.reverse())
        )

        self.assertIn(join, constructor.get_post_dominators(switch))
        self.assertNotIn(constructor.cfg.entryTerminal, constructor.get_post_dominators(join))
        self.assertNotIn(switch, constructor.get_post_dominators(join))

    def test_dump_text_header_includes_function_name(self):
        """Text dump headers should interpolate the function name."""
        cdg = self.build_cdg(simple_if)

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "simple_if_cdg.txt"
            dump_cdg(cdg, str(output), "text", "simple_if")
            content = output.read_text()

        self.assertIn("Control Dependence Graph for function: simple_if", content)

    def test_exceptional_only_nested_if_keeps_transitive_control_dependence(self):
        """Exceptional-only branches should still keep a full postdom chain."""
        func = self.load_function_from_source(
            "tmp_cdg_exceptional_only",
            """
            def only_raise_nested(x, y):
                if x > 0:
                    if y > 0:
                        raise ValueError("a")
                    else:
                        raise ValueError("b")
                else:
                    raise ValueError("c")
            """,
            "only_raise_nested",
        )
        cdg = self.build_cdg(func)

        switch_to_switch_edges = [
            edge for edge in cdg.get_all_edges() if isinstance(edge.source.cfg_node, cfg_graph.Switch)
            and isinstance(edge.target.cfg_node, cfg_graph.Switch)
        ]
        true_merge_edges = [
            edge for edge in cdg.get_all_edges()
            if isinstance(edge.source.cfg_node, cfg_graph.Switch)
            and isinstance(edge.target.cfg_node, cfg_graph.Merge)
            and edge.label == "true"
        ]

        self.assertTrue(switch_to_switch_edges)
        self.assertTrue(true_merge_edges)


if __name__ == "__main__":
    unittest.main()
