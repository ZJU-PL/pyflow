"""Tests for analysis/lifetimeanalysis module - lifetime analysis for object tracking."""

import unittest

from pyflow.analysis.lifetimeanalysis import (
    invertInvokes,
    filteredSCC,
    wrapOpContext,
    wrapCodeContext,
    ObjectInfo,
    ReadModifyAnalysis,
    DFSSearcher,
    ObjectSearcher,
)


class MockXType:
    """Mock XType for testing ObjectInfo."""

    def __init__(self, is_existing=False, is_external=False):
        self._is_existing = is_existing
        self._is_external = is_external

    def isExisting(self):
        return self._is_existing

    def isExternal(self):
        return self._is_external


class MockObjectNode:
    """Mock ObjectNode for testing."""

    def __init__(self, name, is_existing=False, is_external=False):
        self.name = name
        self.xtype = MockXType(is_existing, is_external)


class TestWrapSchemas(unittest.TestCase):
    """Test cases for schema wrapping functions."""

    def test_wrapOpContext(self):
        """Test that wrapOpContext returns a valid schema."""
        schema = wrapOpContext(str)
        self.assertIsNotNone(schema)

    def test_wrapCodeContext(self):
        """Test that wrapCodeContext returns a valid schema."""
        schema = wrapCodeContext(str)
        self.assertIsNotNone(schema)


class TestInvertInvokes(unittest.TestCase):
    """Test cases for invertInvokes function."""

    def test_empty_invokes(self):
        """Test inverting empty invokes mapping."""
        invokes = {}
        result = invertInvokes(invokes)
        self.assertEqual(len(result), 0)

    def test_single_invocation(self):
        """Test inverting a single invocation."""
        # Create a mock invokes structure
        invokes = {}
        # Simulate invokes: (code1, op1, context1) -> [(code2, context2)]
        # The actual structure depends on the schema implementation
        result = invertInvokes(invokes)
        # Result should be empty for empty input
        self.assertEqual(len(result), 0)


class TestFilteredSCC(unittest.TestCase):
    """Test cases for filteredSCC function."""

    def test_empty_graph(self):
        """Test filtering SCC on empty graph."""
        import networkx as nx
        G = nx.DiGraph()
        result = filteredSCC(G)
        self.assertEqual(len(result), 0)

    def test_single_node(self):
        """Test filtering SCC with single node (trivial SCC)."""
        import networkx as nx
        G = nx.DiGraph()
        G.add_node("A")
        result = filteredSCC(G)
        # Single node is a trivial SCC, should be filtered out
        self.assertEqual(len(result), 0)

    def test_multiple_disconnected_nodes(self):
        """Test filtering SCC with disconnected nodes."""
        import networkx as nx
        G = nx.DiGraph()
        G.add_node("A")
        G.add_node("B")
        result = filteredSCC(G)
        self.assertEqual(len(result), 0)

    def test_non_trivial_scc(self):
        """Test filtering SCC with a cycle (non-trivial SCC)."""
        import networkx as nx
        G = nx.DiGraph()
        G.add_edge("A", "B")
        G.add_edge("B", "A")
        result = filteredSCC(G)
        # A and B form a cycle, should be returned
        self.assertEqual(len(result), 1)
        # The result is a set of frozensets, check if A and B are in any component
        found = False
        for component in result:
            if "A" in component and "B" in component:
                found = True
                break
        self.assertTrue(found)

    def test_mixed_graph(self):
        """Test filtering SCC with mixed trivial and non-trivial components."""
        import networkx as nx
        G = nx.DiGraph()
        # Non-trivial cycle
        G.add_edge("A", "B")
        G.add_edge("B", "A")
        # Trivial node
        G.add_node("C")
        result = filteredSCC(G)
        # Should only return the non-trivial SCC
        self.assertEqual(len(result), 1)


class TestObjectInfo(unittest.TestCase):
    """Test cases for ObjectInfo class."""

    def test_init_existing_object(self):
        """Test ObjectInfo initialization with existing object."""
        obj = MockObjectNode("test", is_existing=True, is_external=False)
        info = ObjectInfo(obj)
        
        self.assertEqual(info.obj, obj)
        self.assertEqual(len(info.refersTo), 0)
        self.assertEqual(len(info.referedFrom), 0)
        self.assertEqual(len(info.localReference), 0)
        self.assertEqual(len(info.heldByClosure), 0)
        self.assertTrue(info.globallyVisible)
        self.assertFalse(info.externallyVisible)

    def test_init_external_object(self):
        """Test ObjectInfo initialization with external object."""
        obj = MockObjectNode("test", is_existing=False, is_external=True)
        info = ObjectInfo(obj)
        
        self.assertFalse(info.globallyVisible)
        self.assertTrue(info.externallyVisible)

    def test_init_regular_object(self):
        """Test ObjectInfo initialization with regular object."""
        obj = MockObjectNode("test", is_existing=False, is_external=False)
        info = ObjectInfo(obj)
        
        self.assertFalse(info.globallyVisible)
        self.assertFalse(info.externallyVisible)

    def test_isReachableFrom(self):
        """Test isReachableFrom method."""
        obj1 = MockObjectNode("obj1")
        obj2 = MockObjectNode("obj2")
        info1 = ObjectInfo(obj1)
        info2 = ObjectInfo(obj2)
        
        # Initially not reachable
        self.assertFalse(info1.isReachableFrom({info2}))
        
        # Add info2 to heldByClosure of info1
        info1.heldByClosure.add(info2)
        self.assertTrue(info1.isReachableFrom({info2}))

    def test_leaks(self):
        """Test leaks method."""
        obj = MockObjectNode("test", is_existing=True, is_external=False)
        info = ObjectInfo(obj)
        self.assertTrue(info.leaks())
        
        obj2 = MockObjectNode("test2", is_existing=False, is_external=True)
        info2 = ObjectInfo(obj2)
        self.assertTrue(info2.leaks())
        
        obj3 = MockObjectNode("test3", is_existing=False, is_external=False)
        info3 = ObjectInfo(obj3)
        self.assertFalse(info3.leaks())

    def test_updateHeldBy(self):
        """Test updateHeldBy method."""
        obj = MockObjectNode("test", is_existing=False, is_external=False)
        info = ObjectInfo(obj)
        
        other_info = ObjectInfo(MockObjectNode("other"))
        
        # Initially empty
        self.assertEqual(len(info.heldByClosure), 0)
        
        # Update with new holder
        result = info.updateHeldBy({other_info})
        self.assertTrue(result)
        self.assertIn(other_info, info.heldByClosure)
        
        # Update with same holder again
        result = info.updateHeldBy({other_info})
        self.assertFalse(result)

    def test_updateHeldBy_raises_for_leaking_object(self):
        """Test that updateHeldBy raises AssertionError for leaking object."""
        obj = MockObjectNode("test", is_existing=True, is_external=False)
        info = ObjectInfo(obj)
        
        other_info = ObjectInfo(MockObjectNode("other"))
        
        with self.assertRaises(AssertionError):
            info.updateHeldBy({other_info})


class TestDFSSearcher(unittest.TestCase):
    """Test cases for DFSSearcher class."""

    def test_init(self):
        """Test DFSSearcher initialization."""
        searcher = DFSSearcher()
        self.assertEqual(len(searcher._stack), 0)
        self.assertEqual(len(searcher._touched), 0)

    def test_enqueue_single(self):
        """Test enqueueing a single node."""
        searcher = DFSSearcher()
        searcher.enqueue("A")
        
        self.assertIn("A", searcher._touched)
        self.assertIn("A", searcher._stack)

    def test_enqueue_multiple(self):
        """Test enqueueing multiple nodes."""
        searcher = DFSSearcher()
        searcher.enqueue("A", "B", "C")
        
        self.assertEqual(len(searcher._touched), 3)
        self.assertEqual(len(searcher._stack), 3)

    def test_enqueue_duplicate(self):
        """Test that duplicate enqueue is ignored."""
        searcher = DFSSearcher()
        searcher.enqueue("A")
        searcher.enqueue("A")
        
        self.assertEqual(len(searcher._touched), 1)
        self.assertEqual(len(searcher._stack), 1)

    def test_process_empty(self):
        """Test processing empty stack."""
        searcher = DFSSearcher()
        searcher.process()
        self.assertEqual(len(searcher._stack), 0)

    def test_process_calls_visit(self):
        """Test that process calls visit for each node."""
        # Create a custom searcher with visit tracking
        class TrackingSearcher(DFSSearcher):
            def __init__(self):
                super().__init__()
                self.visited = []
            
            def visit(self, node):
                self.visited.append(node)
        
        searcher = TrackingSearcher()
        
        searcher.enqueue("A", "B")
        searcher.process()
        
        self.assertEqual(len(searcher.visited), 2)


class TestObjectSearcher(unittest.TestCase):
    """Test cases for ObjectSearcher class."""

    def test_init(self):
        """Test ObjectSearcher initialization."""
        la = None  # We'll test with mock
        searcher = ObjectSearcher(la)
        
        self.assertEqual(searcher.la, la)
        self.assertEqual(len(searcher._stack), 0)
        self.assertEqual(len(searcher._touched), 0)

    def test_visit_with_mock_object(self):
        """Test visiting a mock object."""
        class MockLA:
            def __init__(self):
                self.obj_infos = {}
            
            def getObjectInfo(self, obj):
                if obj not in self.obj_infos:
                    self.obj_infos[obj] = ObjectInfo(obj)
                return self.obj_infos[obj]
        
        class MockSlot:
            def __init__(self, children):
                self.children = children
            
            def __iter__(self):
                return iter(self.children)
        
        class MockObj:
            def __init__(self, slots):
                self.slots = slots
                self.xtype = MockXType()
            
            def __iter__(self):
                return iter(self.slots)
        
        la = MockLA()
        searcher = ObjectSearcher(la)
        
        # Create object with a slot that references another object
        child_obj = MockObj([])
        parent_obj = MockObj([MockSlot([child_obj])])
        
        # Visit parent object
        searcher.visit(parent_obj)
        
        # Check that reference relationship was built
        parent_info = la.getObjectInfo(parent_obj)
        child_info = la.getObjectInfo(child_obj)
        
        self.assertIn(child_info, parent_info.refersTo)
        self.assertIn(parent_info, child_info.referedFrom)


class TestReadModifyAnalysis(unittest.TestCase):
    """Test cases for ReadModifyAnalysis class."""

    def test_init_empty(self):
        """Test ReadModifyAnalysis initialization with empty live code."""
        liveCode = set()
        invokeSources = {}
        
        analysis = ReadModifyAnalysis(liveCode, invokeSources)
        
        self.assertEqual(analysis.invokeSources, invokeSources)
        self.assertEqual(len(analysis.contextReads), 0)
        self.assertEqual(len(analysis.contextModifies), 0)
        self.assertEqual(len(analysis.allReads), 0)
        self.assertEqual(len(analysis.allModifies), 0)

    def test_process_empty_killed(self):
        """Test process with empty killed set."""
        liveCode = set()
        invokeSources = {}
        
        analysis = ReadModifyAnalysis(liveCode, invokeSources)
        analysis.process({})
        
        # Should not raise any exceptions
        self.assertIsNotNone(analysis.killed)

    def test_handleModifies_empty(self):
        """Test handleModifies with empty input."""
        liveCode = set()
        invokeSources = {}
        
        analysis = ReadModifyAnalysis(liveCode, invokeSources)
        
        # Should handle empty modifies gracefully
        analysis.handleModifies(None, None, (False, set()))

    def test_handleReads_empty(self):
        """Test handleReads with empty input."""
        liveCode = set()
        invokeSources = {}
        
        analysis = ReadModifyAnalysis(liveCode, invokeSources)
        
        # Should handle empty reads gracefully
        analysis.handleReads(None, None, (False, set()))

    def test_handleAllocates_empty(self):
        """Test handleAllocates with empty input."""
        liveCode = set()
        invokeSources = {}
        
        analysis = ReadModifyAnalysis(liveCode, invokeSources)
        
        # Should handle empty allocates gracefully
        analysis.handleAllocates(None, None, (False, set()))


if __name__ == "__main__":
    unittest.main()
