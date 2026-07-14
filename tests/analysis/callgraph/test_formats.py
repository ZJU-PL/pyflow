"""Tests for analysis/callgraph/formats.py - Call graph output formats."""

import unittest
import json

from pyflow.analysis.callgraph.formats import (
    generate_text_output,
    generate_dot_output,
    generate_json_output,
)


class MockCallGraph:
    """Mock call graph for testing."""

    def __init__(self, data=None, modules=None):
        self._data = data or {}
        self._modules = modules or {}

    def get(self):
        return self._data

    def get_modules(self):
        return self._modules


class TestGenerateTextOutput(unittest.TestCase):
    """Test cases for generate_text_output function."""

    def test_empty_graph(self):
        """Test with empty call graph."""
        graph = MockCallGraph()
        
        result = generate_text_output(graph, None)
        
        self.assertIn("Call Graph Analysis", result)
        self.assertIn("Functions (0)", result)

    def test_single_function_no_calls(self):
        """Test with single function that has no calls."""
        graph = MockCallGraph(
            data={"main": set()},
            modules={"main": ""}
        )
        
        result = generate_text_output(graph, None)
        
        self.assertIn("main", result)
        self.assertIn("(no calls)", result)

    def test_function_with_calls(self):
        """Test with function that calls another function."""
        graph = MockCallGraph(
            data={
                "main": {"func_a", "func_b"},
                "func_a": set(),
                "func_b": set()
            },
            modules={}
        )
        
        result = generate_text_output(graph, None)
        
        self.assertIn("main -> func_a, func_b", result)

    def test_function_with_module_info(self):
        """Test that module info is included."""
        graph = MockCallGraph(
            data={"main": set()},
            modules={"main": "example.py"}
        )
        
        result = generate_text_output(graph, None)
        
        self.assertIn("main (from example.py)", result)


class TestGenerateDotOutput(unittest.TestCase):
    """Test cases for generate_dot_output function."""

    def test_empty_graph(self):
        """Test with empty call graph."""
        graph = MockCallGraph()
        
        result = generate_dot_output(graph, None)
        
        self.assertIn("digraph CallGraph", result)
        self.assertIn("rankdir=TB", result)
        self.assertIn("}", result)

    def test_single_node(self):
        """Test with single function."""
        graph = MockCallGraph(data={"main": set()})
        
        result = generate_dot_output(graph, None)
        
        self.assertIn('"main"', result)

    def test_function_calls(self):
        """Test with function that calls another."""
        graph = MockCallGraph(data={"main": {"func_a"}})
        
        result = generate_dot_output(graph, None)
        
        self.assertIn('"main" -> "func_a"', result)

    def test_escapes_special_chars(self):
        """Test that special characters are escaped."""
        graph = MockCallGraph(data={"func_with_dash": set()})
        
        result = generate_dot_output(graph, None)
        
        self.assertIn('"func_with_dash"', result)


class TestGenerateJsonOutput(unittest.TestCase):
    """Test cases for generate_json_output function."""

    def test_empty_graph(self):
        """Test with empty call graph."""
        graph = MockCallGraph()
        
        result = generate_json_output(graph, None)
        
        # Should be valid JSON
        data = json.loads(result)
        self.assertIn("functions", data)

    def test_function_with_calls(self):
        """Test with function that calls another."""
        graph = MockCallGraph(
            data={"main": {"func_a"}},
            modules={"main": "example.py"}
        )
        
        result = generate_json_output(graph, None)
        
        data = json.loads(result)
        self.assertIn("main", data["functions"])
        self.assertIn("invocations", data)
        self.assertIn("main", data["invocations"])


if __name__ == "__main__":
    unittest.main()
