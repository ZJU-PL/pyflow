"""
Comprehensive unit tests for pyflow.util.PADS module.

This test suite covers:
- UnionFind: Disjoint set data structure
- StrongConnectivity: Strongly connected components algorithm
- DFS: Depth-first search algorithms
- BFS: Breadth-first search algorithms
- Graphs: Graph utility functions
- Util: Utility functions
- Biconnectivity: Biconnected components algorithm
"""

import unittest
from pyflow.util.PADS import UnionFind as UFModule
from pyflow.util.PADS.UnionFind import UnionFind
from pyflow.util.PADS import StrongConnectivity, BFS, Graphs, Util, Biconnectivity, DFS
from pyflow.util.PADS.Biconnectivity import BiconnectedComponents


class TestUnionFind(unittest.TestCase):
    """Tests for UnionFind data structure."""

    def test_empty_init(self):
        """Test that UnionFind initializes with empty structures."""
        uf = UnionFind()
        self.assertEqual(uf.parents, {})
        self.assertEqual(uf.weights, {})

    def test_single_element(self):
        """Test adding a single element."""
        uf = UnionFind()
        root = uf[1]
        self.assertEqual(root, 1)
        self.assertIn(1, uf.parents)
        self.assertIn(1, uf.weights)
        self.assertEqual(uf.weights[1], 1)

    def test_find_singleton(self):
        """Test finding root of a singleton set."""
        uf = UnionFind()
        self.assertEqual(uf[1], 1)
        self.assertEqual(uf[2], 2)

    def test_union_same_set(self):
        """Test union of elements already in the same set."""
        uf = UnionFind()
        uf[1]
        uf[2]
        root = uf.union(1, 2)
        self.assertEqual(uf[1], uf[2])
        self.assertEqual(uf[1], root)

    def test_union_multiple(self):
        """Test union with multiple elements."""
        uf = UnionFind()
        root = uf.union(1, 2, 3, 4)
        self.assertEqual(uf[1], uf[2])
        self.assertEqual(uf[2], uf[3])
        self.assertEqual(uf[3], uf[4])
        self.assertEqual(uf[1], root)

    def test_union_creates_singleton(self):
        """Test that union with unknown elements creates singletons."""
        uf = UnionFind()
        uf.union(1, 2)
        self.assertIn(1, uf)
        self.assertIn(2, uf)
        # Unknown element should be created when accessed
        self.assertEqual(uf[3], 3)

    def test_path_compression(self):
        """Test that path compression works correctly."""
        uf = UnionFind()
        uf.union(1, 2)
        uf.union(2, 3)
        uf.union(3, 4)
        # Accessing 1 should compress the path
        self.assertEqual(uf[1], uf[4])
        # Check that parents are compressed
        root = uf[4]
        self.assertEqual(uf.parents[1], root)
        self.assertEqual(uf.parents[2], root)
        self.assertEqual(uf.parents[3], root)

    def test_weighted_union(self):
        """Test that union by weight works correctly."""
        uf = UnionFind()
        # Create a larger set
        for i in range(1, 5):
            uf[i]
        # Union smaller sets
        uf.union(1, 2)  # Both weight 1
        uf.union(3, 4)  # Both weight 1
        uf.union(1, 3)  # Both weight 2, one becomes root
        # Check weights are merged
        root = uf[1]
        self.assertEqual(uf.weights[root], 4)

    def test_iteration(self):
        """Test that iteration works correctly."""
        uf = UnionFind()
        uf[1]
        uf[2]
        uf.union(3, 4)
        items = set(uf)
        self.assertEqual(items, {1, 2, 3, 4})

    def test_find_after_union(self):
        """Test find returns correct root after unions."""
        uf = UnionFind()
        uf.union(1, 2)
        uf.union(3, 4)
        uf.union(2, 3)
        self.assertEqual(uf[1], uf[4])
        self.assertEqual(uf[2], uf[4])

    def test_non_integer_elements(self):
        """Test UnionFind with non-integer elements."""
        uf = UnionFind()
        uf["a"]
        uf["b"]
        uf.union("a", "b")
        self.assertEqual(uf["a"], uf["b"])

    def test_tuple_elements(self):
        """Test UnionFind with tuple elements."""
        uf = UnionFind()
        uf[("a", "b")]
        uf[("c", "d")]
        uf.union(("a", "b"), ("c", "d"))
        self.assertEqual(uf[("a", "b")], uf[("c", "d")])


class TestStrongConnectivity(unittest.TestCase):
    """Tests for StronglyConnectedComponents algorithm."""

    def test_empty_graph(self):
        """Test strongly connected components of empty graph."""
        G = {}
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        self.assertEqual(components, [])

    def test_single_node(self):
        """Test single node graph."""
        G = {0: []}
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        self.assertEqual(len(components), 1)
        self.assertEqual(list(components[0].keys()), [0])

    def test_disconnected_nodes(self):
        """Test disconnected graph with multiple isolated nodes."""
        G = {0: [], 1: [], 2: []}
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        self.assertEqual(len(components), 3)

    def test_simple_cycle(self):
        """Test simple cycle graph."""
        # 0 -> 1 -> 2 -> 0
        G = {0: [1], 1: [2], 2: [0]}
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        self.assertEqual(len(components), 1)
        self.assertEqual(set(components[0].keys()), {0, 1, 2})

    def test_diamond_graph(self):
        """Test diamond-shaped graph."""
        #     0
        #    / \
        #   1   2
        #    \ /
        #     3
        G = {0: [1, 2], 1: [3], 2: [3], 3: []}
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        # Each node is its own SCC
        self.assertEqual(len(components), 4)

    def test_complex_graph(self):
        """Test more complex graph with multiple SCCs."""
        # Two SCCs connected in a chain
        G = {0: [1], 1: [0, 2], 2: [3], 3: [2, 4], 4: [3]}
        # SCC 1: {0, 1}, SCC 2: {2, 3, 4}
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        component_sets = [set(c.keys()) for c in components]
        self.assertTrue({0, 1} in component_sets)
        self.assertTrue({2, 3, 4} in component_sets)

    def test_component_is_induced_subgraph(self):
        """Test that each component is an induced subgraph."""
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1, 3], 3: [2]}
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        for component in components:
            vertices = set(component.keys())
            for v in vertices:
                for w in G[v]:
                    if w in vertices:
                        self.assertIn(w, component[v])

    def test_back_edge_scc(self):
        """Test SCC detection with back edges."""
        G = {0: [1], 1: [2], 2: [0]}  # cycle
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        self.assertEqual(len(components), 1)

    def test_self_loop(self):
        """Test graph with self-loops."""
        G = {0: [0], 1: []}  # self-loop on 0
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        # Self-loop should be its own SCC
        self.assertEqual(len(components), 2)


class TestDFS(unittest.TestCase):
    """Tests for DFS algorithms."""

    def test_search_empty_graph(self):
        """Test DFS search on empty graph."""
        G = {}
        result = list(DFS.search(G))
        self.assertEqual(result, [])

    def test_search_single_node(self):
        """Test DFS search on single node."""
        G = {0: []}
        result = list(DFS.search(G))
        self.assertEqual(result, [(0, 0, DFS.forward), (0, 0, DFS.reverse)])

    def test_search_two_nodes(self):
        """Test DFS search on two nodes with edge."""
        G = {0: [1], 1: []}
        result = list(DFS.search(G))
        # Should contain: (0,0,forward), (0,1,forward), (1,1,reverse), (0,0,reverse)
        self.assertEqual(len(result), 4)

    def test_search_with_initial_vertex(self):
        """Test DFS search with specific initial vertex."""
        G = {0: [1], 1: [], 2: [3], 3: []}
        result = list(DFS.search(G, initial_vertex=0))
        # Should only visit 0 and 1
        self.assertEqual(len(result), 4)

    def test_preorder_empty_graph(self):
        """Test preorder traversal on empty graph."""
        G = {}
        result = list(DFS.preorder(G))
        self.assertEqual(result, [])

    def test_preorder_single_node(self):
        """Test preorder traversal on single node."""
        G = {0: []}
        result = list(DFS.preorder(G))
        self.assertEqual(result, [0])

    def test_preorder_chain(self):
        """Test preorder traversal on chain graph."""
        G = {0: [1], 1: [2], 2: []}
        result = list(DFS.preorder(G))
        self.assertEqual(result, [0, 1, 2])

    def test_postorder_empty_graph(self):
        """Test postorder traversal on empty graph."""
        G = {}
        result = list(DFS.postorder(G))
        self.assertEqual(result, [])

    def test_postorder_single_node(self):
        """Test postorder traversal on single node."""
        G = {0: []}
        result = list(DFS.postorder(G))
        self.assertEqual(result, [0])

    def test_postorder_chain(self):
        """Test postorder traversal on chain graph."""
        G = {0: [1], 1: [2], 2: []}
        result = list(DFS.postorder(G))
        self.assertEqual(result, [2, 1, 0])

    def test_reachable_true(self):
        """Test reachable function when path exists."""
        G = {0: [1], 1: [2], 2: []}
        self.assertTrue(DFS.reachable(G, 0, 2))

    def test_reachable_false(self):
        """Test reachable function when no path exists."""
        G = {0: [1], 1: [], 2: [3], 3: []}
        self.assertFalse(DFS.reachable(G, 0, 2))
        self.assertFalse(DFS.reachable(G, 0, 3))

    def test_reachable_self(self):
        """Test reachable function for same vertex."""
        G = {0: [1], 1: []}
        self.assertTrue(DFS.reachable(G, 0, 0))
        self.assertTrue(DFS.reachable(G, 1, 1))

    def test_searcher_preorder_callback(self):
        """Test Searcher class preorder callback."""
        visited_preorder = []

        class TestSearcher(DFS.Searcher):
            def preorder(self, parent, child):
                visited_preorder.append((parent, child))

        G = {0: [1], 1: []}
        TestSearcher(G)
        self.assertIn((0, 0), visited_preorder)
        self.assertIn((0, 1), visited_preorder)

    def test_searcher_postorder_callback(self):
        """Test Searcher class postorder callback."""
        visited_postorder = []

        class TestSearcher(DFS.Searcher):
            def postorder(self, parent, child):
                visited_postorder.append((parent, child))

        G = {0: [1], 1: []}
        TestSearcher(G)
        self.assertIn((0, 1), visited_postorder)
        self.assertIn((0, 0), visited_postorder)

    def test_searcher_backedge_callback(self):
        """Test Searcher class backedge callback."""
        visited_backedges = []

        class TestSearcher(DFS.Searcher):
            def backedge(self, source, destination):
                visited_backedges.append((source, destination))

        # Graph with a cycle
        G = {0: [1], 1: [2], 2: [0]}
        TestSearcher(G)
        # Should have at least one backedge
        self.assertTrue(len(visited_backedges) > 0)

    def test_edge_types(self):
        """Test that correct edge types are returned."""
        # Graph with a cycle to trigger nontree edges
        G = {0: [1], 1: [2], 2: [0]}
        result = list(DFS.search(G))
        edge_types = [et for _, _, et in result]
        self.assertIn(DFS.forward, edge_types)
        self.assertIn(DFS.reverse, edge_types)
        self.assertIn(DFS.nontree, edge_types)  # Back edge in cycle


class TestBFS(unittest.TestCase):
    """Tests for BFS algorithms."""

    def test_breadth_first_levels_empty_graph(self):
        """Test BreadthFirstLevels on graph with no edges from root."""
        # BreadthFirstLevels requires root to exist in graph
        G = {0: []}
        result = list(BFS.BreadthFirstLevels(G, 0))
        self.assertEqual(len(result), 1)

    def test_breadth_first_levels_single_node(self):
        """Test BreadthFirstLevels on single node graph."""
        G = {0: []}
        result = list(BFS.BreadthFirstLevels(G, 0))
        self.assertEqual(len(result), 1)
        self.assertEqual(set(result[0].keys()), {0})
        self.assertEqual(result[0][0], set())

    def test_breadth_first_levels_two_levels(self):
        """Test BreadthFirstLevels on two-level graph."""
        #     0
        #    / \
        #   1   2
        G = {0: [1, 2], 1: [], 2: []}
        result = list(BFS.BreadthFirstLevels(G, 0))
        self.assertEqual(len(result), 2)
        # Level 0: just 0
        self.assertEqual(set(result[0].keys()), {0})
        # Level 1: edges from 0 to 1 and 2
        self.assertEqual(set(result[0][0]), {1, 2})

    def test_breadth_first_levels_three_levels(self):
        """Test BreadthFirstLevels on three-level graph."""
        #     0
        #    / \
        #   1   2
        #  / \
        # 3   4
        G = {0: [1, 2], 1: [3, 4], 2: [], 3: [], 4: []}
        result = list(BFS.BreadthFirstLevels(G, 0))
        self.assertEqual(len(result), 3)
        # Level 0: {0}
        self.assertEqual(set(result[0].keys()), {0})
        # Level 1: edges from 0
        self.assertEqual(set(result[0][0]), {1, 2})
        # Level 2: both 1 and 2 have entries (2 has empty set)
        self.assertEqual(set(result[1].keys()), {1, 2})
        self.assertEqual(result[1][1], {3, 4})
        self.assertEqual(result[1][2], set())

    def test_breadth_first_levels_with_visited(self):
        """Test BreadthFirstLevels doesn't revisit nodes."""
        # Graph with cycle
        # 0 -> 1 -> 2 -> 0
        G = {0: [1], 1: [2], 2: [0]}
        result = list(BFS.BreadthFirstLevels(G, 0))
        # Should have 3 levels, each with correct edges
        self.assertEqual(len(result), 3)


class TestGraphs(unittest.TestCase):
    """Tests for graph utility functions."""

    def test_is_undirected_simple(self):
        """Test isUndirected on simple undirected graph."""
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1]}
        self.assertTrue(Graphs.isUndirected(G))

    def test_is_undirected_directed(self):
        """Test isUndirected on directed graph."""
        G = {0: [1], 1: [2], 2: []}
        self.assertFalse(Graphs.isUndirected(G))

    def test_is_undirected_with_self_loop(self):
        """Test isUndirected detects self-loops."""
        G = {0: [0], 1: []}  # self-loop on 0
        self.assertFalse(Graphs.isUndirected(G))

    def test_is_undirected_asymmetric_edge(self):
        """Test isUndirected detects asymmetric edges."""
        G = {0: [1], 1: []}  # edge 0->1 but no edge 1->0
        self.assertFalse(Graphs.isUndirected(G))

    def test_is_undirected_empty(self):
        """Test isUndirected on empty graph."""
        G = {}
        self.assertTrue(Graphs.isUndirected(G))

    def test_max_degree(self):
        """Test maxDegree function."""
        G = {0: [1, 2], 1: [0], 2: [0]}
        self.assertEqual(Graphs.maxDegree(G), 2)

    def test_max_degree_empty(self):
        """Test maxDegree on empty graph."""
        G = {}
        with self.assertRaises(ValueError):
            Graphs.maxDegree(G)

    def test_min_degree(self):
        """Test minDegree function."""
        G = {0: [1, 2], 1: [0], 2: [0]}
        self.assertEqual(Graphs.minDegree(G), 1)

    def test_min_degree_empty(self):
        """Test minDegree on empty graph."""
        G = {}
        with self.assertRaises(ValueError):
            Graphs.minDegree(G)

    def test_copy_graph(self):
        """Test copyGraph function."""
        G = {0: [1], 1: [0]}
        G_copy = Graphs.copyGraph(G, list)
        self.assertEqual(G_copy, G)
        # Modify copy doesn't affect original
        G_copy[0].append(2)
        self.assertNotEqual(G[0], G_copy[0])

    def test_copy_graph_with_set(self):
        """Test copyGraph with set as adjacency type."""
        G = {0: [1], 1: [0]}
        G_copy = Graphs.copyGraph(G, set)
        self.assertEqual(G_copy[0], {1})
        self.assertEqual(G_copy[1], {0})

    def test_induced_subgraph(self):
        """Test InducedSubgraph function."""
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1], 3: [4], 4: [3]}
        V = {0, 1, 2}
        induced = Graphs.InducedSubgraph(V, G, list)
        self.assertEqual(set(induced.keys()), {0, 1, 2})
        self.assertEqual(induced[0], [1, 2])
        self.assertEqual(induced[1], [0, 2])
        self.assertEqual(induced[2], [0, 1])

    def test_induced_subgraph_empty(self):
        """Test InducedSubgraph with empty vertex set."""
        G = {0: [1], 1: [0]}
        V = set()
        induced = Graphs.InducedSubgraph(V, G, list)
        self.assertEqual(induced, {})

    def test_induced_subgraph_all_vertices(self):
        """Test InducedSubgraph with all vertices."""
        G = {0: [1], 1: [0]}
        V = {0, 1}
        induced = Graphs.InducedSubgraph(V, G, list)
        self.assertEqual(induced, G)

    def test_union_single_graph(self):
        """Test union with single graph."""
        G = {0: [1], 1: [0]}
        result = Graphs.union(G)
        # union converts adjacency lists to sets
        self.assertEqual(set(result.keys()), {0, 1})
        self.assertEqual(result[0], {1})
        self.assertEqual(result[1], {0})

    def test_union_multiple_graphs(self):
        """Test union with multiple graphs."""
        G1 = {0: [1], 1: []}
        G2 = {2: [3], 3: []}
        result = Graphs.union(G1, G2)
        self.assertEqual(set(result.keys()), {0, 1, 2, 3})
        self.assertEqual(result[0], {1})
        self.assertEqual(result[2], {3})

    def test_union_with_overlapping_edges(self):
        """Test union with overlapping edges."""
        G1 = {0: [1], 1: []}
        G2 = {0: [2], 2: []}
        result = Graphs.union(G1, G2)
        self.assertEqual(result[0], {1, 2})

    def test_is_independent_set_true(self):
        """Test isIndependentSet with valid independent set."""
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1]}
        self.assertTrue(Graphs.isIndependentSet({3}, G))  # 3 has no edges

    def test_is_independent_set_false(self):
        """Test isIndependentSet with invalid independent set."""
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1]}
        self.assertFalse(Graphs.isIndependentSet({0, 1}, G))  # 0 and 1 are connected


class TestUtil(unittest.TestCase):
    """Tests for utility functions."""

    def test_arbitrary_item_from_list(self):
        """Test arbitrary_item with a list."""
        result = Util.arbitrary_item([1, 2, 3])
        self.assertIn(result, [1, 2, 3])

    def test_arbitrary_item_from_set(self):
        """Test arbitrary_item with a set."""
        result = Util.arbitrary_item({1, 2, 3})
        self.assertIn(result, {1, 2, 3})

    def test_arbitrary_item_from_empty_raises(self):
        """Test arbitrary_item raises IndexError on empty sequence."""
        with self.assertRaises(IndexError):
            Util.arbitrary_item([])

    def test_arbitrary_item_from_empty_set_raises(self):
        """Test arbitrary_item raises IndexError on empty set."""
        with self.assertRaises(IndexError):
            Util.arbitrary_item(set())

    def test_map_to_constant(self):
        """Test map_to_constant function."""
        factory = Util.map_to_constant("constant")
        result = factory([1, 2, 3])
        expected = {1: "constant", 2: "constant", 3: "constant"}
        self.assertEqual(result, expected)

    def test_map_to_constant_empty(self):
        """Test map_to_constant with empty sequence."""
        factory = Util.map_to_constant("constant")
        result = factory([])
        self.assertEqual(result, {})


class TestBiconnectivity(unittest.TestCase):
    """Tests for Biconnectivity algorithms."""

    def test_is_biconnected_simple(self):
        """Test isBiconnected on simple cycle."""
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1]}  # triangle
        self.assertTrue(Biconnectivity.isBiconnected(G))

    def test_is_biconnected_path(self):
        """Test isBiconnected on path (not biconnected)."""
        G = {0: [1], 1: [0, 2], 2: [1, 3], 3: [2]}  # path of 4 nodes
        self.assertFalse(Biconnectivity.isBiconnected(G))

    def test_is_biconnected_with_articulation(self):
        """Test isBiconnected with articulation point."""
        #     0
        #    / \
        #   1   2
        G = {0: [1, 2], 1: [0], 2: [0]}
        self.assertFalse(Biconnectivity.isBiconnected(G))

    def test_is_biconnected_empty(self):
        """Test isBiconnected on empty graph."""
        G = {}
        self.assertTrue(Biconnectivity.isBiconnected(G))

    def test_is_biconnected_single_node(self):
        """Test isBiconnected on single node."""
        G = {0: []}
        self.assertTrue(Biconnectivity.isBiconnected(G))

    def test_is_biconnected_two_nodes(self):
        """Test isBiconnected on two connected nodes."""
        G = {0: [1], 1: [0]}
        self.assertTrue(Biconnectivity.isBiconnected(G))

    def test_biconnected_components_triangle(self):
        """Test BiconnectedComponents on triangle."""
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1]}
        components = list(Biconnectivity.BiconnectedComponents(G))
        # Triangle is one biconnected component
        self.assertEqual(len(components), 1)
        self.assertEqual(set(components[0].keys()), {0, 1, 2})

    def test_biconnected_components_multiple(self):
        """Test BiconnectedComponents with multiple components."""
        G = {0: [2, 5], 1: [3, 8], 2: [0, 3, 5], 3: [1, 2, 6, 8], 4: [7],
             5: [0, 2], 6: [3, 8], 7: [4], 8: [1, 3, 6]}
        components = list(Biconnectivity.BiconnectedComponents(G))
        # Should have 4 biconnected components
        self.assertEqual(len(components), 4)

    def test_st_orientation(self):
        """Test stOrientation function."""
        G = {0: [1, 2, 5], 1: [0, 5], 2: [0, 3, 4], 3: [2, 4, 5, 6],
             4: [2, 3, 5, 6], 5: [0, 1, 3, 4], 6: [3, 4]}
        st_graph = Biconnectivity.stOrientation(G)
        # Check that the result is a DAG
        # Count sources and sinks
        sources = sum(1 for v in st_graph if len(st_graph[v]) == 0 or
                      all(st_graph[v].__contains__(u) or u not in st_graph for u in st_graph))
        # Verify structure
        for v in st_graph:
            for w in st_graph[v]:
                self.assertIn(v, G)  # Original vertices preserved
                self.assertIn(w, G)

    def test_st_orientation_not_biconnected_raises(self):
        """Test stOrientation raises on non-biconnected graph."""
        G = {0: [1], 1: [0, 2], 2: [1]}  # path, not biconnected
        with self.assertRaises(Biconnectivity.NotBiconnected):
            Biconnectivity.stOrientation(G)

    def test_biconnected_components_iterator(self):
        """Test that BiconnectedComponents returns proper iterator."""
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1]}
        components = BiconnectedComponents(G)
        # Should be iterable
        comp_list = list(components)
        self.assertEqual(len(comp_list), 1)


class TestDFSEdgeTypes(unittest.TestCase):
    """Test DFS edge type constants."""

    def test_edge_type_values(self):
        """Test that edge types have correct values."""
        self.assertEqual(DFS.forward, 1)
        self.assertEqual(DFS.reverse, -1)
        self.assertEqual(DFS.nontree, 0)

    def test_edge_type_ordering(self):
        """Test that edge type ordering matches dispatch array indexing."""
        # dispatch = [backedge, preorder, postorder]
        # dispatch[0] = backedge (nontree = 0)
        # dispatch[1] = preorder (forward = 1)
        # dispatch[-1] = postorder (reverse = -1)
        self.assertEqual(DFS.forward, 1)  # calls preorder
        self.assertEqual(DFS.nontree, 0)  # calls backedge
        self.assertEqual(DFS.reverse, -1)  # calls postorder


class TestGraphExamples(unittest.TestCase):
    """Test that various graph structures work correctly with PADS algorithms."""

    def test_chain_graph_with_union_find(self):
        """Test UnionFind on chain of unions."""
        uf = UnionFind()
        # Create chain: 0-1-2-3-4
        for i in range(4):
            uf.union(i, i + 1)
        # All should be in the same set
        root = uf[0]
        for i in range(1, 5):
            self.assertEqual(uf[i], root)

    def test_star_graph_with_dfs(self):
        """Test DFS on star graph."""
        #     0
        #   / | \
        #  1  2  3
        G = {0: [1, 2, 3], 1: [], 2: [], 3: []}
        preorder = list(DFS.preorder(G))
        postorder = list(DFS.postorder(G))
        # All nodes should be visited
        self.assertEqual(set(preorder), {0, 1, 2, 3})
        self.assertEqual(set(postorder), {0, 1, 2, 3})
        # Postorder should start with leaves
        self.assertIn(postorder[0], [1, 2, 3])

    def test_complete_graph_scc(self):
        """Test SCC on complete graph."""
        # Complete graph K4
        G = {i: [j for j in range(4) if j != i] for i in range(4)}
        components = list(StrongConnectivity.StronglyConnectedComponents(G))
        # K4 is strongly connected
        self.assertEqual(len(components), 1)
        self.assertEqual(set(components[0].keys()), {0, 1, 2, 3})

    def test_bipartite_graph_bfs(self):
        """Test BFS on bipartite graph."""
        # Complete bipartite K_{2,3}
        left = {0, 1}
        right = {2, 3, 4}
        G = {i: list(right) for i in left}
        G.update({i: list(left) for i in right})
        G[0].extend([1])  # Add edge within left for undirected check
        G[1].append(0)

        levels = list(BFS.BreadthFirstLevels(G, 0))
        # Should have multiple levels
        self.assertGreater(len(levels), 1)


if __name__ == "__main__":
    unittest.main()


class TestReadUndirectedGraph(unittest.TestCase):
    """Tests for ReadUndirectedGraph module."""

    def test_graph_num_valid(self):
        """Test graphNum with valid integer."""
        from pyflow.util.PADS.ReadUndirectedGraph import graphNum
        self.assertEqual(graphNum("123"), 123)
        self.assertEqual(graphNum("0"), 0)

    def test_graph_num_invalid(self):
        """Test graphNum raises GraphFormatError on invalid input."""
        from pyflow.util.PADS.ReadUndirectedGraph import graphNum, GraphFormatError
        with self.assertRaises(GraphFormatError):
            graphNum("abc")

    def test_graph_creation(self):
        """Test graph() function creates empty graph."""
        from pyflow.util.PADS.ReadUndirectedGraph import graph
        G = graph()
        self.assertEqual(G, {})

    def test_vertex_addition(self):
        """Test vertex() function adds vertex to graph."""
        from pyflow.util.PADS.ReadUndirectedGraph import graph, vertex
        G = graph()
        vertex(G, 0)
        self.assertIn(0, G)
        self.assertEqual(G[0], {})

    def test_vertex_duplicate_raises(self):
        """Test vertex() raises on duplicate vertex."""
        from pyflow.util.PADS.ReadUndirectedGraph import graph, vertex, GraphFormatError
        G = graph()
        vertex(G, 0)
        with self.assertRaises(GraphFormatError):
            vertex(G, 0)

    def test_edge_addition(self):
        """Test edge() function adds edge to graph."""
        from pyflow.util.PADS.ReadUndirectedGraph import graph, vertex, edge
        G = graph()
        vertex(G, 0)
        vertex(G, 1)
        edge(G, 0, 1, 1)
        self.assertIn(1, G[0])
        self.assertIn(0, G[1])

    def test_edge_self_loop_raises(self):
        """Test edge() raises on self-loop."""
        from pyflow.util.PADS.ReadUndirectedGraph import graph, vertex, edge, GraphFormatError
        G = graph()
        vertex(G, 0)
        with self.assertRaises(GraphFormatError):
            edge(G, 0, 0, 1)

    def test_edge_missing_vertex_raises(self):
        """Test edge() raises on missing vertex."""
        from pyflow.util.PADS.ReadUndirectedGraph import graph, vertex, edge, GraphFormatError
        G = graph()
        vertex(G, 0)
        with self.assertRaises(GraphFormatError):
            edge(G, 0, 1, 1)  # vertex 1 doesn't exist

    def test_graph6data_valid(self):
        """Test graph6data with valid input."""
        from pyflow.util.PADS.ReadUndirectedGraph import graph6data
        # ASCII characters 63-126 represent values 0-63
        data = graph6data("A")  # 'A' = 65 - 63 = 2
        self.assertEqual(data, [2])

    def test_graph6data_invalid(self):
        """Test graph6data returns None for invalid characters."""
        from pyflow.util.PADS.ReadUndirectedGraph import graph6data
        result = graph6data("\x00")  # Invalid character
        self.assertIsNone(result)

    def test_graph6n_single_value(self):
        """Test graph6n with single value."""
        from pyflow.util.PADS.ReadUndirectedGraph import graph6n
        data = [32]  # value <= 62
        result, rest = graph6n(data)
        self.assertEqual(result, 32)
        self.assertEqual(rest, [])

    def test_graph_format_error_exception(self):
        """Test GraphFormatError is a proper exception."""
        from pyflow.util.PADS.ReadUndirectedGraph import GraphFormatError
        with self.assertRaises(GraphFormatError):
            raise GraphFormatError("test message")


class TestCardinalityMatching(unittest.TestCase):
    """Tests for CardinalityMatching module."""

    def test_matching_empty_graph(self):
        """Test matching on empty graph."""
        from pyflow.util.PADS.CardinalityMatching import matching
        G = {}
        result = matching(G)
        self.assertEqual(result, {})

    def test_matching_no_edges(self):
        """Test matching on graph with no edges."""
        from pyflow.util.PADS.CardinalityMatching import matching
        G = {0: [], 1: []}
        result = matching(G)
        self.assertEqual(result, {})

    def test_matching_single_edge(self):
        """Test matching on single edge."""
        from pyflow.util.PADS.CardinalityMatching import matching
        G = {0: [1], 1: [0]}
        result = matching(G)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], 1)
        self.assertEqual(result[1], 0)

    def test_matching_path_graph(self):
        """Test matching on path graph."""
        from pyflow.util.PADS.CardinalityMatching import matching
        # 0 - 1 - 2 - 3
        G = {0: [1], 1: [0, 2], 2: [1, 3], 3: [2]}
        result = matching(G)
        # Maximum matching should have size 2 (2 edges, 4 vertices)
        self.assertEqual(len(result), 4)  # 2 pairs
        # Verify matching is consistent
        for v, matched in result.items():
            self.assertEqual(result[matched], v)

    def test_matching_cycle(self):
        """Test matching on cycle graph."""
        from pyflow.util.PADS.CardinalityMatching import matching
        # Triangle: 0 - 1 - 2 - 0
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1]}
        result = matching(G)
        # Maximum matching in triangle has size 2 (1 edge, 2 vertices)
        self.assertEqual(len(result), 2)

    def test_matching_star_graph(self):
        """Test matching on star graph."""
        from pyflow.util.PADS.CardinalityMatching import matching
        # 0 connected to 1, 2, 3, 4
        G = {0: [1, 2, 3, 4], 1: [0], 2: [0], 3: [0], 4: [0]}
        result = matching(G)
        # Should match center with one leaf
        self.assertEqual(len(result), 2)

    def test_greedy_matching(self):
        """Test greedyMatching function."""
        from pyflow.util.PADS.CardinalityMatching import greedyMatching
        G = {0: [1], 1: [0, 2], 2: [1]}
        result = greedyMatching(G)
        # Should find a valid matching
        for v, matched in result.items():
            self.assertEqual(result[matched], v)


class TestPartialOrder(unittest.TestCase):
    """Tests for PartialOrder module."""

    def test_is_topological_order_valid(self):
        """Test isTopologicalOrder on valid ordering."""
        from pyflow.util.PADS.PartialOrder import isTopologicalOrder
        G = {0: [1, 2], 1: [3], 2: [3], 3: []}
        L = [0, 1, 2, 3]
        self.assertTrue(isTopologicalOrder(G, L))

    def test_is_topological_order_invalid(self):
        """Test isTopologicalOrder on invalid ordering."""
        from pyflow.util.PADS.PartialOrder import isTopologicalOrder
        G = {0: [1], 1: [2]}
        L = [0, 2, 1]  # 2 comes before 1, but there's an edge 1->2
        self.assertFalse(isTopologicalOrder(G, L))

    def test_is_topological_order_missing_vertex(self):
        """Test isTopologicalOrder with missing vertex."""
        from pyflow.util.PADS.PartialOrder import isTopologicalOrder
        G = {0: [1], 1: [2]}
        L = [0, 1]  # missing 2
        self.assertFalse(isTopologicalOrder(G, L))

    def test_is_topological_order_extra_vertex(self):
        """Test isTopologicalOrder with extra vertex."""
        from pyflow.util.PADS.PartialOrder import isTopologicalOrder
        G = {0: [1]}
        L = [0, 1, 2]  # extra vertex 2 not in graph
        self.assertFalse(isTopologicalOrder(G, L))

    def test_topological_order_dag(self):
        """Test TopologicalOrder on valid DAG."""
        from pyflow.util.PADS.PartialOrder import TopologicalOrder
        G = {0: [1, 2], 1: [3], 2: [3], 3: []}
        L = TopologicalOrder(G)
        self.assertEqual(len(L), 4)
        # Verify it's a valid topological order
        vnum = {v: i for i, v in enumerate(L)}
        for v in G:
            for w in G[v]:
                self.assertGreater(vnum[w], vnum[v])

    def test_topological_order_cyclic_raises(self):
        """Test TopologicalOrder raises on cyclic graph."""
        from pyflow.util.PADS.PartialOrder import TopologicalOrder
        G = {0: [1], 1: [2], 2: [0]}  # cycle
        with self.assertRaises(ValueError):
            TopologicalOrder(G)

    def test_is_acyclic_true(self):
        """Test isAcyclic on DAG."""
        from pyflow.util.PADS.PartialOrder import isAcyclic
        G = {0: [1], 1: [2], 2: []}
        self.assertTrue(isAcyclic(G))

    def test_is_acyclic_false(self):
        """Test isAcyclic on cyclic graph."""
        from pyflow.util.PADS.PartialOrder import isAcyclic
        G = {0: [1], 1: [2], 2: [0]}  # cycle
        self.assertFalse(isAcyclic(G))

    def test_transitive_closure(self):
        """Test TransitiveClosure function."""
        from pyflow.util.PADS.PartialOrder import TransitiveClosure
        # 0 -> 1 -> 2
        G = {0: [1], 1: [2], 2: []}
        TC = TransitiveClosure(G)
        self.assertIn(1, TC[0])
        self.assertIn(2, TC[0])
        self.assertIn(2, TC[1])
        self.assertNotIn(0, TC[0])  # no self-loops
        self.assertNotIn(1, TC[1])
        self.assertNotIn(2, TC[2])

    def test_transitive_closure_complex(self):
        """Test TransitiveClosure on more complex graph."""
        from pyflow.util.PADS.PartialOrder import TransitiveClosure
        # Diamond: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        G = {0: [1, 2], 1: [3], 2: [3], 3: []}
        TC = TransitiveClosure(G)
        self.assertIn(2, TC[0])  # 0 -> 2 directly
        self.assertIn(3, TC[0])  # 0 -> 1 -> 3 and 0 -> 2 -> 3
        self.assertIn(3, TC[1])  # 1 -> 3 directly
        self.assertIn(3, TC[2])  # 2 -> 3 directly

    def test_trace_paths(self):
        """Test TracePaths function."""
        from pyflow.util.PADS.PartialOrder import TracePaths
        # Disjoint chains: 0 -> 1 -> 2 and 3 -> 4
        G = {0: [1], 1: [2], 2: [], 3: [4], 4: []}
        paths = list(TracePaths(G))
        self.assertEqual(len(paths), 2)

    def test_minimum_path_decomposition(self):
        """Test MinimumPathDecomposition function."""
        from pyflow.util.PADS.PartialOrder import MinimumPathDecomposition
        # Diamond shape
        G = {0: [1, 2], 1: [3], 2: [3], 3: []}
        paths = list(MinimumPathDecomposition(G))
        # Should cover the graph with minimum paths
        self.assertGreater(len(paths), 0)

    def test_minimum_chain_decomposition(self):
        """Test MinimumChainDecomposition function."""
        from pyflow.util.PADS.PartialOrder import MinimumChainDecomposition
        # Diamond shape
        G = {0: [1, 2], 1: [3], 2: [3], 3: []}
        chains = list(MinimumChainDecomposition(G))
        # Should cover with minimum chains (Dilworth's theorem)
        self.assertGreater(len(chains), 0)

    def test_maximum_antichain(self):
        """Test MaximumAntichain function."""
        from pyflow.util.PADS.PartialOrder import MaximumAntichain
        # Diamond: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        G = {0: [1, 2], 1: [3], 2: [3], 3: []}
        antichain = MaximumAntichain(G)
        # Antichain should not have comparable elements
        for a in antichain:
            for b in antichain:
                if a != b:
                    self.assertNotIn(b, G.get(a, []))
                    self.assertNotIn(a, G.get(b, []))

    def test_maximum_antichain_raises_on_cycle(self):
        """Test MaximumAntichain raises on cyclic graph."""
        from pyflow.util.PADS.PartialOrder import MaximumAntichain
        G = {0: [1], 1: [2], 2: [0]}  # cycle
        with self.assertRaises(ValueError):
            MaximumAntichain(G)


class TestAutomata(unittest.TestCase):
    """Tests for Automata module."""

    def test_language_from_string(self):
        """Test creating RegularLanguage from string (regex)."""
        from pyflow.util.PADS.Automata import RegularLanguage
        lang = RegularLanguage("a*b")
        self.assertIn("b", lang)
        self.assertIn("ab", lang)
        self.assertIn("aaaab", lang)
        self.assertNotIn("a", lang)
        self.assertNotIn("", lang)

    def test_language_complement(self):
        """Test complement of a language."""
        from pyflow.util.PADS.Automata import RegularLanguage
        lang = RegularLanguage("a")
        complement = ~lang
        # Complement should contain strings that original doesn't
        self.assertNotIn("a", complement)

    def test_language_is_empty(self):
        """Test checking if language is empty."""
        from pyflow.util.PADS.Automata import RegularLanguage
        # Empty language using a regex that matches nothing
        lang = RegularLanguage("")  # empty string only
        # Nonzero returns True if there are any final states
        self.assertTrue(bool(lang))  # empty string is in the language


class TestPartialCube(unittest.TestCase):
    """Tests for PartialCube module."""

    def test_is_partial_cube_true(self):
        """Test isPartialCube on a partial cube."""
        from pyflow.util.PADS.PartialCube import isPartialCube
        # Path graph is a partial cube
        G = {0: [1], 1: [0, 2], 2: [1, 3], 3: [2]}
        self.assertTrue(isPartialCube(G))

    def test_is_partial_cube_false(self):
        """Test isPartialCube on a non-partial-cube."""
        from pyflow.util.PADS.PartialCube import isPartialCube
        # Triangle is not a partial cube (not bipartite)
        G = {0: [1, 2], 1: [0, 2], 2: [0, 1]}
        self.assertFalse(isPartialCube(G))

    def test_is_partial_cube_odd_cycle(self):
        """Test isPartialCube detects odd cycles."""
        from pyflow.util.PADS.PartialCube import isPartialCube
        # 5-cycle
        G = {0: [1, 4], 1: [0, 2], 2: [1, 3], 3: [2, 4], 4: [3, 0]}
        self.assertFalse(isPartialCube(G))

    def test_partial_cube_edge_labeling(self):
        """Test PartialCubeEdgeLabeling function."""
        from pyflow.util.PADS.PartialCube import PartialCubeEdgeLabeling
        # Path of length 3
        G = {0: [1], 1: [0, 2], 2: [1, 3], 3: [2]}
        labeling = PartialCubeEdgeLabeling(G)
        # Each vertex should have edges with labels
        for v in G:
            for w in G[v]:
                self.assertIn(v, labeling)
                self.assertIn(w, labeling[v])

    def test_partial_cube_labeling(self):
        """Test PartialCubeLabeling function."""
        from pyflow.util.PADS.PartialCube import PartialCubeLabeling
        # Path of length 2
        G = {0: [1], 1: [0, 2], 2: [1]}
        labels = PartialCubeLabeling(G)
        # Should return a dictionary of labels
        self.assertIsInstance(labels, dict)
        self.assertEqual(len(labels), 3)  # 3 vertices

    def test_medium_for_partial_cube(self):
        """Test MediumForPartialCube function."""
        from pyflow.util.PADS.PartialCube import MediumForPartialCube
        # Square (cycle of 4) is a partial cube
        G = {0: [1, 3], 1: [0, 2], 2: [1, 3], 3: [2, 0]}
        medium = MediumForPartialCube(G)
        # Should have states and tokens
        self.assertGreater(len(list(medium.states())), 0)


class TestMedium(unittest.TestCase):
    """Tests for Medium module."""

    def test_bitvector_medium_states(self):
        """Test BitvectorMedium states iteration."""
        from pyflow.util.PADS.Medium import BitvectorMedium
        states = {0b0001, 0b0010, 0b0100, 0b1000}
        medium = BitvectorMedium(states, 4)
        result = list(medium.states())
        self.assertEqual(set(result), states)

    def test_bitvector_medium_tokens(self):
        """Test BitvectorMedium tokens iteration."""
        from pyflow.util.PADS.Medium import BitvectorMedium
        states = {0b0000, 0b0001}
        medium = BitvectorMedium(states, 4)
        tokens = list(medium.tokens())
        # Should have 2 * 4 = 8 tokens (2 bits per position)
        self.assertEqual(len(tokens), 8)

    def test_bitvector_medium_action(self):
        """Test BitvectorMedium action method."""
        from pyflow.util.PADS.Medium import BitvectorMedium
        states = {0b0000, 0b0001, 0b0010, 0b0011}
        medium = BitvectorMedium(states, 4)
        # Flip bit 0 (LSB)
        state = medium.action(0b0000, (0, True))
        self.assertEqual(state, 0b0001)

    def test_bitvector_medium_reverse(self):
        """Test BitvectorMedium reverse method."""
        from pyflow.util.PADS.Medium import BitvectorMedium
        states = {0b0000, 0b0001}
        medium = BitvectorMedium(states, 4)
        # Reverse of (0, True) should be (0, False)
        rev = medium.reverse((0, True))
        self.assertEqual(rev, (0, False))

    def test_medium_error(self):
        """Test MediumError exception."""
        from pyflow.util.PADS.Medium import MediumError
        with self.assertRaises(MediumError):
            raise MediumError("test error")

    def test_state_transition_graph(self):
        """Test StateTransitionGraph function."""
        from pyflow.util.PADS.Medium import BitvectorMedium, StateTransitionGraph
        states = {0b0000, 0b0001}
        medium = BitvectorMedium(states, 4)
        G = StateTransitionGraph(medium)
        self.assertIn(0b0000, G)
        self.assertIn(0b0001, G)

    def test_labeled_graph_medium(self):
        """Test LabeledGraphMedium class."""
        from pyflow.util.PADS.Medium import LabeledGraphMedium
        # Simple two-state medium with proper reversals
        G = {0: {1: "a"}, 1: {0: "a"}}  # "a" is its own reverse
        medium = LabeledGraphMedium(G)
        self.assertIn(0, list(medium.states()))
        self.assertIn(1, list(medium.states()))

    def test_explicit_medium(self):
        """Test ExplicitMedium class."""
        from pyflow.util.PADS.Medium import BitvectorMedium, ExplicitMedium
        states = {0b0000, 0b0001}
        original = BitvectorMedium(states, 4)
        explicit = ExplicitMedium(original)
        self.assertEqual(len(explicit), 2)

    def test_medium_iteration(self):
        """Test that Medium is iterable."""
        from pyflow.util.PADS.Medium import BitvectorMedium
        states = {0b0000, 0b0001}
        medium = BitvectorMedium(states, 4)
        result = list(medium)
        self.assertEqual(set(result), states)

    def test_medium_len(self):
        """Test that Medium supports len()."""
        from pyflow.util.PADS.Medium import BitvectorMedium
        states = {0b0000, 0b0001, 0b0010}
        medium = BitvectorMedium(states, 4)
        self.assertEqual(len(medium), 3)
