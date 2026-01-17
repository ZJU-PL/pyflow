"""Tests for analysis/fsdf/ - Flow-Sensitive Data Flow Analysis."""

import unittest

from pyflow.analysis.fsdf import (
    ReadModifyInfo,
    FindMergeSplit,
    LocalName,
    FieldName,
    Operation,
    Slot,
    HeapSlot,
    isSCC,
    findRecursiveGroups,
)


class TestReadModifyInfo(unittest.TestCase):
    """Test cases for ReadModifyInfo class."""

    def test_init(self):
        """Test ReadModifyInfo initialization."""
        info = ReadModifyInfo()
        
        self.assertEqual(info.localRead, set())
        self.assertEqual(info.localModify, set())
        self.assertEqual(info.heapRead, set())
        self.assertEqual(info.heapModify, set())

    def test_accumulate(self):
        """Test accumulating information from another ReadModifyInfo."""
        info1 = ReadModifyInfo()
        info1.localRead.add("x")
        info1.heapRead.add("field_a")
        
        info2 = ReadModifyInfo()
        info2.localRead.add("y")
        info2.localModify.add("x")
        info2.heapModify.add("field_b")
        
        info1.accumulate(info2)
        
        self.assertEqual(info1.localRead, {"x", "y"})
        self.assertEqual(info1.localModify, {"x"})
        self.assertEqual(info1.heapRead, {"field_a"})
        self.assertEqual(info1.heapModify, {"field_b"})

    def test_accumulate_multiple(self):
        """Test accumulating from multiple sources."""
        info = ReadModifyInfo()
        
        for i in range(5):
            other = ReadModifyInfo()
            other.localRead.add(f"var{i}")
            info.accumulate(other)
        
        self.assertEqual(len(info.localRead), 5)


class TestIsSCC(unittest.TestCase):
    """Test cases for isSCC function."""

    def test_empty_graph(self):
        """Test empty graph returns False."""
        g = {}
        self.assertFalse(isSCC(g))

    def test_no_edges(self):
        """Test graph with nodes but no edges."""
        g = {"a": [], "b": []}
        self.assertFalse(isSCC(g))

    def test_with_edges(self):
        """Test graph with edges returns True."""
        g = {"a": ["b"], "b": ["a"]}
        self.assertTrue(isSCC(g))

    def test_partial_edges(self):
        """Test graph with some nodes having edges."""
        g = {"a": ["b"], "b": [], "c": []}
        self.assertTrue(isSCC(g))


class TestFindRecursiveGroups(unittest.TestCase):
    """Test cases for findRecursiveGroups function."""

    def test_no_recursion(self):
        """Test with no recursive calls."""
        G = {"a": {"b"}, "b": {"c"}, "c": set()}
        result = findRecursiveGroups(G)
        # No cycles, so result should be empty
        self.assertEqual(result, {})

    def test_direct_recursion(self):
        """Test with direct recursion."""
        G = {"a": {"a"}}  # a calls itself
        result = findRecursiveGroups(G)
        # a should be in its own recursive group
        self.assertIn("a", result)
        self.assertEqual(result["a"], frozenset({"a"}))

    def test_mutual_recursion(self):
        """Test with mutual recursion."""
        G = {"a": {"b"}, "b": {"a"}}  # a and b call each other
        result = findRecursiveGroups(G)
        # Both a and b should be in the same group
        self.assertIn("a", result)
        self.assertIn("b", result)
        self.assertEqual(result["a"], result["b"])

    def test_complex_recursion(self):
        """Test with complex recursion pattern."""
        G = {
            "a": {"b"},
            "b": {"c"},
            "c": {"a", "d"},  # cycle: a->b->c->a
            "d": set()
        }
        result = findRecursiveGroups(G)
        # a, b, c should be in recursive group
        self.assertIn("a", result)
        self.assertIn("b", result)
        self.assertIn("c", result)


class TestLocalName(unittest.TestCase):
    """Test cases for LocalName class."""

    def test_init(self):
        """Test LocalName initialization."""
        local = "x"
        context = ("call1",)
        name = LocalName(local, context)
        
        self.assertEqual(name.local, local)
        self.assertEqual(name.context, context)

    def test_is_unique(self):
        """Test isUnique always returns True."""
        name = LocalName("x", "ctx")
        self.assertTrue(name.isUnique())

    def test_canonical_equality(self):
        """Test canonical equality."""
        name1 = LocalName("x", "ctx")
        name2 = LocalName("x", "ctx")
        # Same inputs should produce equal canonical objects
        self.assertEqual(name1, name2)


class TestFieldName(unittest.TestCase):
    """Test cases for FieldName class."""

    def test_init(self):
        """Test FieldName initialization."""
        obj = "obj1"
        field = "field_a"
        context = "ctx1"
        unique = True
        
        name = FieldName(obj, field, context, unique)
        
        self.assertEqual(name.obj, obj)
        self.assertEqual(name.field, field)
        self.assertEqual(name.context, context)
        self.assertEqual(name.unique, unique)

    def test_is_unique_true(self):
        """Test isUnique returns True when unique=True."""
        name = FieldName("obj", "field", "ctx", True)
        self.assertTrue(name.isUnique())

    def test_is_unique_false(self):
        """Test isUnique returns False when unique=False."""
        name = FieldName("obj", "field", "ctx", False)
        self.assertFalse(name.isUnique())

    def test_canonical_equality(self):
        """Test canonical equality."""
        name1 = FieldName("obj", "field", "ctx", True)
        name2 = FieldName("obj", "field", "ctx", True)
        self.assertEqual(name1, name2)

    def test_different_unique_not_equal(self):
        """Test that different unique flag produces different canonical."""
        name1 = FieldName("obj", "field", "ctx", True)
        name2 = FieldName("obj", "field", "ctx", False)
        self.assertNotEqual(name1, name2)


class TestOperation(unittest.TestCase):
    """Test cases for Operation class."""

    def test_init(self):
        """Test Operation initialization."""
        op_node = "assign_expr"
        targets = ["x", "y"]
        
        op = Operation(op_node, targets)
        
        self.assertEqual(op.op, op_node)
        self.assertEqual(op.targets, targets)
        self.assertEqual(op.uses, [])
        self.assertEqual(op.defs, [])
        self.assertEqual(op.heapuses, [])
        self.assertEqual(op.heapdefs, [])


class TestSlot(unittest.TestCase):
    """Test cases for Slot class."""

    def test_init(self):
        """Test Slot initialization."""
        slot = Slot("x")
        
        self.assertEqual(slot.name, "x")
        self.assertFalse(slot.externalDefinition)
        self.assertEqual(slot.defs, [])
        self.assertEqual(slot.uses, [])

    def test_add_use(self):
        """Test adding a use to a slot."""
        slot = Slot("x")
        op = Operation("load", [])
        
        slot.addUse(op)
        
        self.assertIn(op, slot.uses)
        self.assertIn(slot, op.uses)

    def test_add_def(self):
        """Test adding a definition to a slot."""
        slot = Slot("x")
        op = Operation("assign", [])
        
        slot.addDef(op)
        
        self.assertIn(op, slot.defs)
        self.assertIn(slot, op.defs)

    def test_external_definition_prevents_add_def(self):
        """Test that external definitions prevent adding more defs."""
        slot = Slot("x")
        slot.externalDefinition = True
        op = Operation("assign", [])
        
        with self.assertRaises(AssertionError):
            slot.addDef(op)

    def test_repr(self):
        """Test Slot string representation."""
        slot = Slot("x")
        repr_str = repr(slot)
        self.assertIn("Slot", repr_str)
        self.assertIn("x", repr_str)


class TestHeapSlot(unittest.TestCase):
    """Test cases for HeapSlot class."""

    def test_init(self):
        """Test HeapSlot initialization."""
        heap_slot = HeapSlot("obj.field")
        
        self.assertEqual(heap_slot.name, "obj.field")
        self.assertFalse(heap_slot.externalDefinition)
        self.assertEqual(heap_slot.defs, [])
        self.assertEqual(heap_slot.uses, [])

    def test_add_use(self):
        """Test adding a use to a heap slot."""
        heap_slot = HeapSlot("obj.field")
        op = Operation("load", [])
        
        heap_slot.addUse(op)
        
        self.assertIn(op, heap_slot.uses)
        self.assertIn(heap_slot, op.heapuses)

    def test_add_def(self):
        """Test adding a definition to a heap slot."""
        heap_slot = HeapSlot("obj.field")
        op = Operation("store", [])
        
        heap_slot.addDef(op)
        
        self.assertIn(op, heap_slot.defs)
        self.assertIn(heap_slot, op.heapdefs)

    def test_external_definition_prevents_add_def(self):
        """Test that external definitions prevent adding more defs."""
        heap_slot = HeapSlot("obj.field")
        heap_slot.externalDefinition = True
        op = Operation("store", [])
        
        with self.assertRaises(AssertionError):
            heap_slot.addDef(op)

    def test_repr(self):
        """Test HeapSlot string representation."""
        heap_slot = HeapSlot("obj.field")
        repr_str = repr(heap_slot)
        self.assertIn("HeapSlot", repr_str)
        self.assertIn("obj.field", repr_str)


class TestDataflowClasses(unittest.TestCase):
    """Integration tests for FSDF data flow classes."""

    def test_def_use_chain(self):
        """Test building a simple def-use chain."""
        # Create slots
        x = Slot("x")
        
        # Create operations
        assign = Operation("assign", ["x"])
        use = Operation("load", [])
        
        # Build chain: assign -> x -> use
        x.addDef(assign)
        x.addUse(use)
        
        # Verify
        self.assertIn(assign, x.defs)
        self.assertIn(use, x.uses)
        self.assertIn(x, assign.defs)
        self.assertIn(x, use.uses)

    def test_multiple_uses(self):
        """Test a slot with multiple uses."""
        x = Slot("x")
        
        def1 = Operation("def1", ["x"])
        use1 = Operation("use1", [])
        use2 = Operation("use2", [])
        use3 = Operation("use3", [])
        
        x.addDef(def1)
        x.addUse(use1)
        x.addUse(use2)
        x.addUse(use3)
        
        self.assertEqual(len(x.uses), 3)
        self.assertIn(use1, x.uses)
        self.assertIn(use2, x.uses)
        self.assertIn(use3, x.uses)

    def test_heap_def_use(self):
        """Test heap slot def-use chain."""
        obj_field = HeapSlot("obj.field")
        
        store = Operation("store", [])
        load = Operation("load", [])
        
        obj_field.addDef(store)
        obj_field.addUse(load)
        
        self.assertIn(store, obj_field.defs)
        self.assertIn(load, obj_field.uses)


if __name__ == "__main__":
    unittest.main()
