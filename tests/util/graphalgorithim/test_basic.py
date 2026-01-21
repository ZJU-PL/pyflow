"""Tests for pyflow.util.graphalgorithim.basic module."""

import unittest
from pyflow.util.graphalgorithim.basic import reverseDirectedGraph, findEntryPoints


class TestReverseDirectedGraph(unittest.TestCase):
    """Test cases for reverseDirectedGraph function."""

    def test_simple_graph(self):
        """Test reversing a simple directed graph."""
        G = {1: [2, 3], 2: [3], 3: []}
        result = reverseDirectedGraph(G)
        expected = {2: [1], 3: [1, 2]}
        self.assertEqual(result, expected)

    def test_empty_graph(self):
        """Test reversing an empty graph."""
        G = {}
        result = reverseDirectedGraph(G)
        expected = {}
        self.assertEqual(result, expected)

    def test_single_node_no_edges(self):
        """Test reversing a graph with a single node and no edges."""
        G = {1: []}
        result = reverseDirectedGraph(G)
        expected = {}
        self.assertEqual(result, expected)

    def test_single_node_self_loop(self):
        """Test reversing a graph with a self-loop."""
        G = {1: [1]}
        result = reverseDirectedGraph(G)
        expected = {1: [1]}
        self.assertEqual(result, expected)

    def test_chain_graph(self):
        """Test reversing a linear chain graph."""
        G = {1: [2], 2: [3], 3: [4], 4: []}
        result = reverseDirectedGraph(G)
        expected = {2: [1], 3: [2], 4: [3]}
        self.assertEqual(result, expected)

    def test_complete_graph(self):
        """Test reversing a complete directed graph."""
        G = {1: [2, 3], 2: [1, 3], 3: [1, 2]}
        result = reverseDirectedGraph(G)
        expected = {2: [1, 3], 3: [1, 2], 1: [2, 3]}
        self.assertEqual(result, expected)

    def test_multiple_edges_to_same_node(self):
        """Test graph where multiple nodes point to the same node."""
        G = {1: [4], 2: [4], 3: [4], 4: []}
        result = reverseDirectedGraph(G)
        expected = {4: [1, 2, 3]}
        self.assertEqual(result, expected)

    def test_diamond_graph(self):
        """Test reversing a diamond-shaped graph."""
        G = {1: [2, 3], 2: [4], 3: [4], 4: []}
        result = reverseDirectedGraph(G)
        expected = {2: [1], 3: [1], 4: [2, 3]}
        self.assertEqual(result, expected)


class TestFindEntryPoints(unittest.TestCase):
    """Test cases for findEntryPoints function."""

    def test_simple_graph(self):
        """Finding entry point in a simple graph."""
        G = {1: [2, 3], 2: [3], 3: []}
        result = findEntryPoints(G)
        self.assertEqual(result, [1])

    def test_empty_graph(self):
        """Finding entry points in an empty graph."""
        G = {}
        result = findEntryPoints(G)
        self.assertEqual(result, [])

    def test_single_node(self):
        """Finding entry point for a single node."""
        G = {1: []}
        result = findEntryPoints(G)
        self.assertEqual(result, [1])

    def test_cyclic_graph(self):
        """Finding entry points in a cyclic graph."""
        G = {1: [2], 2: [1]}
        result = findEntryPoints(G)
        # In a cycle where each node appears in the other's successor list,
        # there are no entry points (both nodes have predecessors)
        self.assertEqual(result, [])

    def test_multiple_entry_points(self):
        """Graph with multiple entry points."""
        G = {1: [3], 2: [3], 3: []}
        result = findEntryPoints(G)
        self.assertEqual(set(result), {1, 2})

    def test_chain_graph(self):
        """Finding entry point in a linear chain."""
        G = {1: [2], 2: [3], 3: [4], 4: []}
        result = findEntryPoints(G)
        self.assertEqual(result, [1])

    def test_complex_graph(self):
        """Finding entry points in a more complex graph."""
        G = {
            1: [2, 3],
            2: [4],
            3: [4, 5],
            4: [6],
            5: [6],
            6: []
        }
        result = findEntryPoints(G)
        self.assertEqual(result, [1])

    def test_no_connections(self):
        """Graph with completely disconnected nodes."""
        G = {1: [], 2: [], 3: []}
        result = findEntryPoints(G)
        self.assertEqual(set(result), {1, 2, 3})


if __name__ == "__main__":
    unittest.main()
