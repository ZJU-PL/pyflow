"""Tests for analysis/cfg/graph.py - Control Flow Graph representation."""

import unittest

from pyflow.analysis.cfg.graph import (
    CFGBlock,
    NoNormalFlow,
)


class MockRegion:
    """Mock region for testing."""

    def __init__(self, name="mock"):
        self.name = name


class TestCFGBlock(unittest.TestCase):
    """Test cases for CFGBlock class."""

    def test_init(self):
        """Test CFGBlock initialization."""
        region = MockRegion()
        block = CFGBlock(region)
        
        self.assertEqual(block.region, region)
        self.assertEqual(block.next, {})
        self.assertEqual(block.exitNames, ())

    def test_validExitName_empty(self):
        """Test validExitName with empty exitNames."""
        block = CFGBlock(MockRegion())
        
        self.assertFalse(block.validExitName("normal"))
        self.assertFalse(block.validExitName(""))

    def test_validExitName_with_exitnames(self):
        """Test validExitName with defined exitNames."""
        class TestBlock(CFGBlock):
            exitNames = ("normal", "error")
        
        block = TestBlock(MockRegion())
        
        self.assertTrue(block.validExitName("normal"))
        self.assertTrue(block.validExitName("error"))
        self.assertFalse(block.validExitName("fail"))

    def test_setExit_to_none(self):
        """Test setting exit to None."""
        class TestBlock(CFGBlock):
            exitNames = ("normal",)
        
        block = TestBlock(MockRegion())
        block.setExit("normal", None)
        
        self.assertNotIn("normal", block.next)

    def test_setExit_invalid_name(self):
        """Test that invalid exit name raises assertion."""
        block = CFGBlock(MockRegion())
        
        with self.assertRaises(AssertionError):
            block.setExit("invalid", None)

    def test_getExit_empty(self):
        """Test getting exit from block with no exits."""
        class TestBlock(CFGBlock):
            exitNames = ("normal",)
        
        block = TestBlock(MockRegion())
        result = block.getExit("normal")
        
        self.assertIsNone(result)

    def test_forward(self):
        """Test forward returns all successors."""
        class TestBlock(CFGBlock):
            exitNames = ("normal", "error")
        
        block = TestBlock(MockRegion())
        successors = list(block.forward())
        
        self.assertEqual(successors, [])

    def test_normalForward(self):
        """Test normalForward filters exceptional exits."""
        class TestBlock(CFGBlock):
            exitNames = ("normal", "error", "fail", "yield")
        
        block = TestBlock(MockRegion())
        normal = block.normalForward()
        
        self.assertEqual(normal, [])

    def test_findExit_empty(self):
        """Test findExit with no exits."""
        block = CFGBlock(MockRegion())
        result = block.findExit(None)
        
        self.assertIsNone(result)

    def test_repr(self):
        """Test string representation."""
        region = MockRegion("test")
        block = CFGBlock(region)
        
        repr_str = repr(block)
        self.assertIn("CFGBlock", repr_str)
        self.assertIn("test", repr_str)


class TestNoNormalFlow(unittest.TestCase):
    """Test cases for NoNormalFlow exception."""

    def test_raise_exception(self):
        """Test that exception can be raised."""
        with self.assertRaises(NoNormalFlow):
            raise NoNormalFlow()

    def test_raise_with_message(self):
        """Test that exception can be raised with message."""
        msg = "test message"
        with self.assertRaises(NoNormalFlow) as ctx:
            raise NoNormalFlow(msg)
        
        self.assertEqual(str(ctx.exception), msg)


if __name__ == "__main__":
    unittest.main()
