"""Tests for optimization/dce.py - Dead Code Elimination optimization."""

import unittest

from pyflow.optimization.dce import (
    liveMeet,
    MarkLocals,
    MarkLive,
    nodesWithNoSideEffects,
)
from pyflow.language.python import ast
from pyflow.optimization.dataflow.base import top, undefined


class MockFlow:
    """Mock flow dict for testing."""

    def __init__(self):
        self._current = None
        self._values = {}

    def define(self, node, value):
        self._values[id(node)] = value

    def lookup(self, node):
        return self._values.get(id(node), None)

    def undefine(self, node):
        if id(node) in self._values:
            del self._values[id(node)]


class MockAnnotation:
    """Mock annotation for testing."""

    def __init__(self, descriptive=False):
        self.descriptive = descriptive


class MockCode:
    """Mock code object for testing."""

    def __init__(self, descriptive=False):
        self.annotation = MockAnnotation(descriptive)


class TestLiveMeet(unittest.TestCase):
    """Test cases for liveMeet function."""

    def test_with_values(self):
        """Test with non-empty set of values."""
        values = {"a", "b", "c"}
        result = liveMeet(values)
        self.assertEqual(result, top)

    def test_empty_values(self):
        """Test with empty set of values."""
        values = set()
        result = liveMeet(values)
        self.assertEqual(result, undefined)


class TestNodesWithNoSideEffects(unittest.TestCase):
    """Test cases for nodesWithNoSideEffects tuple."""

    def test_contains_expected_types(self):
        """Test that expected node types are in the tuple."""
        self.assertIn(ast.GetGlobal, nodesWithNoSideEffects)
        self.assertIn(ast.Existing, nodesWithNoSideEffects)
        self.assertIn(ast.Local, nodesWithNoSideEffects)
        self.assertIn(ast.Is, nodesWithNoSideEffects)
        self.assertIn(ast.Load, nodesWithNoSideEffects)
        self.assertIn(ast.Allocate, nodesWithNoSideEffects)
        self.assertIn(ast.BuildTuple, nodesWithNoSideEffects)
        self.assertIn(ast.BuildList, nodesWithNoSideEffects)
        self.assertIn(ast.BuildMap, nodesWithNoSideEffects)

    def test_does_not_contain_call(self):
        """Test that Call is not in the tuple."""
        self.assertNotIn(ast.Call, nodesWithNoSideEffects)

    def test_does_not_contain_assign(self):
        """Test that Assign is not in the tuple."""
        self.assertNotIn(ast.Assign, nodesWithNoSideEffects)


class TestMarkLocals(unittest.TestCase):
    """Test cases for MarkLocals class."""

    def test_visitLeaf(self):
        """Test visitLeaf does nothing."""
        marker = MarkLocals()
        marker.flow = MockFlow()
        
        # Should not raise
        marker.visitLeaf(ast.Local("x"))
        marker.visitLeaf(None)

    def test_visitLocal_with_flow(self):
        """Test visitLocal marks variable as live."""
        marker = MarkLocals()
        flow = MockFlow()
        flow._current = "current"
        marker.flow = flow
        
        local = ast.Local("x")
        marker.visitLocal(local)
        
        # Flow should have defined the local
        self.assertIsNotNone(flow.lookup(local))

    def test_visitLocal_without_flow(self):
        """Test visitLocal does nothing without flow context."""
        marker = MarkLocals()
        flow = MockFlow()
        flow._current = None
        marker.flow = flow
        
        local = ast.Local("x")
        marker.visitLocal(local)
        
        # Flow should not have defined the local
        self.assertIsNone(flow.lookup(local))

    def test_visit_container_marks_keyword_value_live(self):
        """Test keyword tuple containers are traversed without crashing."""
        marker = MarkLocals()
        flow = MockFlow()
        flow._current = "current"
        marker.flow = flow

        kw_local = ast.Local("kw")

        marker.visitContainer([("name", kw_local)])

        self.assertIsNotNone(flow.lookup(kw_local))


class TestMarkLive(unittest.TestCase):
    """Test cases for MarkLive class."""

    def test_init(self):
        """Test MarkLive initialization."""
        code = MockCode()
        marker = MarkLive(code)
        
        self.assertEqual(marker.code, code)
        self.assertIsNotNone(marker.marker)

    def test_descriptive(self):
        """Test descriptive() method."""
        code1 = MockCode(descriptive=True)
        marker1 = MarkLive(code1)
        self.assertTrue(marker1.descriptive())
        
        code2 = MockCode(descriptive=False)
        marker2 = MarkLive(code2)
        self.assertFalse(marker2.descriptive())

    def test_visitDelete(self):
        """Test visitDelete undefines the local and preserves the node."""
        code = MockCode()
        marker = MarkLive(code)
        marker.flow = MockFlow()
        
        local = ast.Local("x")
        marker.flow.define(local, "value")
        
        node = ast.Delete(local)
        result = marker.visitDelete(node)

        # Local should be undefined
        self.assertIsNone(marker.flow.lookup(local))
        self.assertIs(result, node)


if __name__ == "__main__":
    unittest.main()
