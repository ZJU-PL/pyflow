"""Tests for analysis/cfgIR/cfg.py - CFG Intermediate Representation."""

import unittest

from pyflow.analysis.cfgIR.cfg import (
    CFGNode,
    CFGBlock,
    CFGBranch,
    CFGMerge,
    CFGEntry,
    CFGExit,
    CFGCompoundNode,
    CFGSuite,
    CFGTypeSwitch,
)


class TestCFGNode(unittest.TestCase):
    """Test cases for CFGNode base class."""

    def test_init(self):
        """Test CFGNode initialization."""
        node = CFGNode()
        self.assertIsNone(node.parent)
        self.assertIsNone(node.prev)
        self.assertIsNone(node.next)

    def test_numIn(self):
        """Test numIn returns 0 when no predecessor."""
        node = CFGNode()
        self.assertEqual(node.numIn(), 0)

    def test_numOut(self):
        """Test numOut returns 0 when no successor."""
        node = CFGNode()
        self.assertEqual(node.numOut(), 0)

    def test_isCompound(self):
        """Test isCompound returns False for base node."""
        node = CFGNode()
        self.assertFalse(node.isCompound())

    def test_isLinear(self):
        """Test isLinear returns True for base node."""
        node = CFGNode()
        self.assertTrue(node.isLinear())

    def test_isSuite(self):
        """Test isSuite returns False for base node."""
        node = CFGNode()
        self.assertFalse(node.isSuite())


class TestCFGBlock(unittest.TestCase):
    """Test cases for CFGBlock class."""

    def test_init(self):
        """Test CFGBlock initialization."""
        block = CFGBlock("hyperblock", ["predicate1"])
        self.assertEqual(block.hyperblock, "hyperblock")
        self.assertEqual(block.predicates, ["predicate1"])
        self.assertEqual(block.ops, [])
        self.assertIsNone(block.prev)
        self.assertIsNone(block.next)


class TestCFGBranch(unittest.TestCase):
    """Test cases for CFGBranch class."""

    def test_init(self):
        """Test CFGBranch initialization."""
        branch = CFGBranch("op")
        self.assertEqual(branch.op, "op")
        self.assertEqual(branch.next, [])
        self.assertIsNone(branch.prev)

    def test_numOut(self):
        """Test numOut returns number of successors."""
        branch = CFGBranch("op")
        self.assertEqual(branch.numOut(), 0)

    def test_isLinear(self):
        """Test isLinear returns False for branch."""
        branch = CFGBranch("op")
        self.assertFalse(branch.isLinear())


class TestCFGMerge(unittest.TestCase):
    """Test cases for CFGMerge class."""

    def test_init(self):
        """Test CFGMerge initialization."""
        merge = CFGMerge()
        self.assertEqual(merge.prev, [])
        self.assertIsNone(merge.next)

    def test_iterprev(self):
        """Test iterprev returns empty list initially."""
        merge = CFGMerge()
        self.assertEqual(list(merge.iterprev()), [])

    def test_isLinear(self):
        """Test isLinear returns False for merge."""
        merge = CFGMerge()
        self.assertFalse(merge.isLinear())


class TestCFGEntry(unittest.TestCase):
    """Test cases for CFGEntry class."""

    def test_init(self):
        """Test CFGEntry initialization."""
        entry = CFGEntry()
        self.assertIsNone(entry.prev)
        self.assertIsNone(entry.next)

    def test_addPrev_raises(self):
        """Test that addPrev raises NotImplementedError."""
        entry = CFGEntry()
        with self.assertRaises(NotImplementedError):
            entry._addPrev(CFGNode())


class TestCFGExit(unittest.TestCase):
    """Test cases for CFGExit class."""

    def test_init(self):
        """Test CFGExit initialization."""
        exit_node = CFGExit()
        self.assertIsNone(exit_node.prev)
        self.assertIsNone(exit_node.next)

    def test_addNext_raises(self):
        """Test that addNext raises NotImplementedError."""
        exit_node = CFGExit()
        with self.assertRaises(NotImplementedError):
            exit_node.addNext(CFGNode())


class TestCFGSuite(unittest.TestCase):
    """Test cases for CFGSuite class."""

    def test_init(self):
        """Test CFGSuite initialization with linear node."""
        block = CFGBlock(None, [])
        suite = CFGSuite(block)
        self.assertTrue(suite.isCompound())
        self.assertTrue(suite.isSuite())
        self.assertEqual(suite.nodes, [block])


class TestCFGTypeSwitch(unittest.TestCase):
    """Test cases for CFGTypeSwitch class."""

    def test_init(self):
        """Test CFGTypeSwitch initialization."""
        switch = CFGBlock(None, [])
        cases = [CFGBlock(None, []), CFGBlock(None, [])]
        merge = CFGMerge()
        type_switch = CFGTypeSwitch(switch, cases, merge)
        self.assertTrue(type_switch.isCompound())
        self.assertEqual(type_switch.switch, switch)
        self.assertEqual(type_switch.cases, cases)
        self.assertEqual(type_switch.merge, merge)


class TestCFGTypeSwitch(unittest.TestCase):
    """Test cases for CFGTypeSwitch class."""

    def test_init(self):
        """Test CFGTypeSwitch initialization."""
        switch = CFGBlock(None, [])
        cases = [CFGBlock(None, []), CFGBlock(None, [])]
        merge = CFGMerge()
        type_switch = CFGTypeSwitch(switch, cases, merge)
        self.assertTrue(type_switch.isCompound())
        self.assertEqual(type_switch.switch, switch)
        self.assertEqual(type_switch.cases, cases)
        self.assertEqual(type_switch.merge, merge)


class TestCFGEdgeBuilding(unittest.TestCase):
    """Test cases for CFG edge building operations."""

    def test_addNext_basic(self):
        """Test basic edge creation with addNext."""
        node1 = CFGNode()
        node2 = CFGNode()
        node1.addNext(node2)
        self.assertIs(node1.next, node2)
        self.assertIs(node2.prev, node1)

    def test_removeNext(self):
        """Test edge removal with removeNext."""
        node1 = CFGNode()
        node2 = CFGNode()
        node1.addNext(node2)
        node1.removeNext(node2)
        self.assertIsNone(node1.next)
        self.assertIsNone(node2.prev)

    def test_replaceNext(self):
        """Test edge replacement with replaceNext."""
        node1 = CFGNode()
        node2 = CFGNode()
        node3 = CFGNode()
        node1.addNext(node2)
        node1.replaceNext(node2, node3)
        self.assertIs(node1.next, node3)
        self.assertIs(node3.prev, node1)

    def test_iternext(self):
        """Test iteration over successors."""
        node = CFGNode()
        self.assertEqual(list(node.iternext()), [])


if __name__ == "__main__":
    unittest.main()
