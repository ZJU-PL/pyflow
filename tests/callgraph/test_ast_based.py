"""Tests for analysis/callgraph/ast_based.py - AST-based call graph extraction."""

import unittest
import ast

from pyflow.analysis.callgraph.ast_based import (
    extract_call_graph,
    _analyze_function_calls,
    _analyze_module_calls,
    _analyze_call_node,
)
from pyflow.analysis.callgraph.callgraph import CallGraph


class TestExtractCallGraph(unittest.TestCase):
    """Test cases for extract_call_graph function."""

    def test_empty_source(self):
        """Test with empty source code."""
        graph = extract_call_graph("")
        
        data = graph.get()
        self.assertIn("main", data)

    def test_single_function(self):
        """Test with a single function definition."""
        source = """
def foo():
    pass
"""
        graph = extract_call_graph(source)
        
        data = graph.get()
        # Should have main and main.foo (qualified names)
        self.assertIn("main", data)
        self.assertIn("main.foo", data)

    def test_function_with_call(self):
        """Test function that calls another function."""
        source = """
def foo():
    pass

def bar():
    foo()
"""
        graph = extract_call_graph(source)
        
        data = graph.get()
        # Both functions should be in the graph
        self.assertIn("main.foo", data)
        self.assertIn("main.bar", data)
        # main.bar calls main.foo (call happens inside bar, not at module level)
        self.assertIn("main.foo", data.get("main.bar", set()))

    def test_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        source = "def foo(:"
        
        # Should not raise
        graph = extract_call_graph(source)
        
        # Should return a valid graph (possibly empty)
        self.assertIsNotNone(graph.get())


class TestCallGraph(unittest.TestCase):
    """Test cases for CallGraph class."""

    def test_add_node(self):
        """Test adding nodes to the graph."""
        graph = CallGraph()
        graph.add_node("test")
        
        self.assertIn("test", graph.get())

    def test_add_edge(self):
        """Test adding edges to the graph."""
        graph = CallGraph()
        graph.add_node("caller")
        graph.add_node("callee")
        graph.add_edge("caller", "callee")
        
        callees = graph.get().get("caller", set())
        self.assertIn("callee", callees)

    def test_add_edge_creates_nodes(self):
        """Test that adding edge creates nodes if they don't exist."""
        graph = CallGraph()
        graph.add_edge("caller", "callee")
        
        self.assertIn("caller", graph.get())
        self.assertIn("callee", graph.get())

    def test_no_self_loop(self):
        """Test that self-loops are prevented."""
        graph = CallGraph()
        graph.add_edge("func", "func")
        
        callees = graph.get().get("func", set())
        self.assertNotIn("func", callees)


class TestAnalyzeFunctionCalls(unittest.TestCase):
    """Test cases for _analyze_function_calls function."""

    def test_analyze_function_calls(self):
        """Test that function calls are detected within functions."""
        source = """
def caller():
    callee()

def callee():
    pass
"""
        tree = ast.parse(source)
        graph = CallGraph()
        function_names = {"caller", "callee", "main"}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "caller":
                _analyze_function_calls(node, "caller", function_names, graph)
        
        # Uses qualified name since "caller" != "main"
        callees = graph.get().get("main.caller", set())
        self.assertIn("callee", callees)


class TestAnalyzeModuleCalls(unittest.TestCase):
    """Test cases for _analyze_module_calls function."""

    def test_analyze_module_calls(self):
        """Test that module-level calls are detected."""
        source = """
foo()
"""
        tree = ast.parse(source)
        graph = CallGraph()
        function_names = {"main", "foo"}
        
        # Set parent references
        for child in ast.walk(tree):
            child._parent = tree
        
        _analyze_module_calls(tree, "main", function_names, graph)
        
        callees = graph.get().get("main", set())
        self.assertIn("foo", callees)


class TestAnalyzeCallNode(unittest.TestCase):
    """Test cases for _analyze_call_node function."""

    def test_direct_call(self):
        """Test detection of direct function calls."""
        source = "func()"
        tree = ast.parse(source)
        graph = CallGraph()
        function_names = {"main", "func"}
        
        call_node = tree.body[0].value  # The Call node
        _analyze_call_node(call_node, "main", function_names, graph)
        
        callees = graph.get().get("main", set())
        self.assertIn("func", callees)

    def test_unknown_function(self):
        """Test that calls to unknown functions are handled."""
        source = "unknown_func()"
        tree = ast.parse(source)
        graph = CallGraph()
        function_names = {"main"}  # unknown_func not in here
        
        call_node = tree.body[0].value
        _analyze_call_node(call_node, "main", function_names, graph)
        
        # No edge should be added for unknown function
        callees = graph.get().get("main", set())
        self.assertEqual(callees, set())


if __name__ == "__main__":
    unittest.main()
