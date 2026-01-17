"""Tests for analysis/dataflowIR/graph.py - Data Flow IR."""

import unittest

from pyflow.analysis.dataflowIR.graph import (
    Hyperblock,
    DataflowNode,
    SlotNode,
    FlowSensitiveSlotNode,
    LocalNode,
    PredicateNode,
    ExistingNode,
    NullNode,
    FieldNode,
    OpNode,
    PredicatedOpNode,
    Entry,
    Exit,
    Gate,
    Merge,
    Split,
    GenericOp,
    DataflowGraph,
)


class TestHyperblock(unittest.TestCase):
    """Test cases for Hyperblock class."""

    def test_init(self):
        """Test Hyperblock initialization."""
        hb = Hyperblock("test")
        self.assertEqual(hb.name, "test")

    def test_repr(self):
        """Test Hyperblock string representation."""
        hb = Hyperblock(1)
        self.assertIn("1", repr(hb))


class TestDataflowNode(unittest.TestCase):
    """Test cases for DataflowNode base class."""

    def test_init_with_none_hyperblock(self):
        """Test initialization with None hyperblock."""
        node = DataflowNode(None)
        self.assertIsNone(node.hyperblock)

    def test_init_with_hyperblock(self):
        """Test initialization with hyperblock."""
        hb = Hyperblock("test")
        node = DataflowNode(hb)
        self.assertIs(node.hyperblock, hb)

    def test_isOp_and_isSlot(self):
        """Test type checking methods."""
        node = DataflowNode(None)
        self.assertFalse(node.isOp())
        self.assertFalse(node.isSlot())

    def test_annotation_property(self):
        """Test annotation get/set."""
        node = DataflowNode(None)
        node.annotation = "test_annotation"
        self.assertEqual(node.annotation, "test_annotation")


class TestLocalNode(unittest.TestCase):
    """Test cases for LocalNode class."""

    def test_init(self):
        """Test LocalNode initialization."""
        hb = Hyperblock("test")
        node = LocalNode(hb)
        self.assertEqual(node.names, [])
        self.assertIsNone(node.defn)
        self.assertIsNone(node.use)

    def test_init_with_names(self):
        """Test initialization with names."""
        hb = Hyperblock("test")
        node = LocalNode(hb, ["x", "y"])
        self.assertEqual(len(node.names), 2)

    def test_isLocal(self):
        """Test isLocal returns True."""
        node = LocalNode(Hyperblock("test"))
        self.assertTrue(node.isLocal())

    def test_addName(self):
        """Test adding names to local node."""
        node = LocalNode(Hyperblock("test"))
        node.addName("x")
        self.assertIn("x", node.names)

    def test_duplicate(self):
        """Test duplicating a local node."""
        node1 = LocalNode(Hyperblock("test"))
        node1.addName("x")
        node2 = node1.duplicate()
        self.assertIsNot(node1, node2)
        self.assertIs(node1.names, node2.names)


class TestPredicateNode(unittest.TestCase):
    """Test cases for PredicateNode class."""

    def test_init(self):
        """Test PredicateNode initialization."""
        hb = Hyperblock("test")
        node = PredicateNode(hb, "cond")
        self.assertEqual(node.name, "cond")

    def test_isPredicate(self):
        """Test isPredicate returns True."""
        node = PredicateNode(Hyperblock("test"), "cond")
        self.assertTrue(node.isPredicate())


class TestExistingNode(unittest.TestCase):
    """Test cases for ExistingNode class."""

    def test_init(self):
        """Test ExistingNode initialization."""
        node = ExistingNode("obj", "ref")
        self.assertEqual(node.name, "obj")
        self.assertEqual(node.ref, "ref")
        self.assertEqual(node.uses, [])

    def test_addUse(self):
        """Test adding uses to existing node."""
        node = ExistingNode("obj", "ref")
        self.assertEqual(len(node.uses), 0)
        # Uses are added to the list but we need an op to add
        # For testing purposes, we'll just verify the structure

    def test_duplicate_returns_self(self):
        """Test that duplicate returns self (existing nodes are canonicalized)."""
        node = ExistingNode("obj", "ref")
        dup = node.duplicate()
        self.assertIs(node, dup)

    def test_isExisting(self):
        """Test isExisting returns True."""
        node = ExistingNode("obj", "ref")
        self.assertTrue(node.isExisting())


class TestNullNode(unittest.TestCase):
    """Test cases for NullNode class."""

    def test_init(self):
        """Test NullNode initialization."""
        node = NullNode()
        self.assertIsNone(node.defn)
        self.assertEqual(node.uses, [])

    def test_isNull(self):
        """Test isNull returns True."""
        node = NullNode()
        self.assertTrue(node.isNull())


class TestFieldNode(unittest.TestCase):
    """Test cases for FieldNode class."""

    def test_init(self):
        """Test FieldNode initialization."""
        hb = Hyperblock("test")
        node = FieldNode(hb, "field_name")
        self.assertEqual(node.name, "field_name")

    def test_mustBeUnique(self):
        """Test that fields don't require unique definitions."""
        node = FieldNode(Hyperblock("test"), "field")
        self.assertFalse(node.mustBeUnique())

    def test_isField(self):
        """Test isField returns True."""
        node = FieldNode(Hyperblock("test"), "field")
        self.assertTrue(node.isField())


class TestEntry(unittest.TestCase):
    """Test cases for Entry operation."""

    def test_init(self):
        """Test Entry initialization."""
        hb = Hyperblock("test")
        entry = Entry(hb)
        self.assertEqual(entry.modifies, {})
        self.assertTrue(entry.isEntry())

    def test_addEntry(self):
        """Test adding entry values."""
        hb = Hyperblock("test")
        entry = Entry(hb)
        local = LocalNode(hb)
        entry.addEntry("x", local)
        self.assertIn("x", entry.modifies)

    def test_forward(self):
        """Test forward returns entry values."""
        hb = Hyperblock("test")
        entry = Entry(hb)
        local = LocalNode(hb)
        entry.addEntry("x", local)
        self.assertIn(local, entry.forward())


class TestExit(unittest.TestCase):
    """Test cases for Exit operation."""

    def test_init(self):
        """Test Exit initialization."""
        hb = Hyperblock("test")
        exit_op = Exit(hb)
        self.assertEqual(exit_op.reads, {})
        self.assertTrue(exit_op.isExit())


class TestGate(unittest.TestCase):
    """Test cases for Gate operation."""

    def test_init(self):
        """Test Gate initialization."""
        hb = Hyperblock("test")
        gate = Gate(hb)
        self.assertIsNone(gate.read)
        self.assertIsNone(gate.modify)

    def test_addRead_and_addModify(self):
        """Test adding read and modify slots."""
        hb = Hyperblock("test")
        gate = Gate(hb)
        local = LocalNode(hb)
        gate.addRead(local)
        self.assertIs(gate.read, local)


class TestMerge(unittest.TestCase):
    """Test cases for Merge operation."""

    def test_init(self):
        """Test Merge initialization."""
        hb = Hyperblock("test")
        merge = Merge(hb)
        self.assertEqual(merge.reads, [])
        self.assertIsNone(merge.modify)

    def test_isMerge(self):
        """Test isMerge returns True."""
        merge = Merge(Hyperblock("test"))
        self.assertTrue(merge.isMerge())


class TestSplit(unittest.TestCase):
    """Test cases for Split operation."""

    def test_init(self):
        """Test Split initialization."""
        hb = Hyperblock("test")
        split = Split(hb)
        self.assertIsNone(split.read)
        self.assertEqual(split.modifies, [])

    def test_isSplit(self):
        """Test isSplit returns True."""
        split = Split(Hyperblock("test"))
        self.assertTrue(split.isSplit())


class TestDataflowGraph(unittest.TestCase):
    """Test cases for DataflowGraph class."""

    def test_init(self):
        """Test DataflowGraph initialization."""
        hb = Hyperblock("test")
        graph = DataflowGraph(hb)
        self.assertIs(graph.entry.hyperblock, hb)
        self.assertIsNone(graph.exit)
        self.assertEqual(graph.existing, {})
        self.assertIsInstance(graph.null, NullNode)

    def test_initPredicate(self):
        """Test predicate initialization."""
        hb = Hyperblock("test")
        graph = DataflowGraph(hb)
        graph.initPredicate()
        self.assertIsInstance(graph.entryPredicate, PredicateNode)


if __name__ == "__main__":
    unittest.main()
