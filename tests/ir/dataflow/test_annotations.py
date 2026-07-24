"""Tests for ir/dataflow/annotations.py - Dataflow Annotations."""

import unittest

from pyflow.ir.dataflow.annotations import (
    CorrelatedAnnotation,
    DataflowAnnotation,
    DataflowOpAnnotation,
    DataflowSlotAnnotation,
    DataflowObjectAnnotation,
)


class TestCorrelatedAnnotation(unittest.TestCase):
    """Test cases for CorrelatedAnnotation class."""

    def test_init(self):
        """Test CorrelatedAnnotation initialization."""
        flat = {"a", "b"}
        correlated = {"c", "d"}
        ann = CorrelatedAnnotation(flat, correlated)
        self.assertEqual(ann.flat, flat)
        self.assertEqual(ann.correlated, correlated)

    def test_slots(self):
        """Test that __slots__ is properly defined."""
        ann = CorrelatedAnnotation({"a"}, {"b"})
        self.assertTrue(hasattr(ann, "flat"))
        self.assertTrue(hasattr(ann, "correlated"))


class TestDataflowOpAnnotation(unittest.TestCase):
    """Test cases for DataflowOpAnnotation class."""

    def test_init(self):
        """Test DataflowOpAnnotation initialization."""
        read = {"slot1"}
        modify = {"slot2"}
        allocate = {"obj1"}
        mask = "mask_data"
        ann = DataflowOpAnnotation(read, modify, allocate, mask)
        self.assertEqual(ann.read, read)
        self.assertEqual(ann.modify, modify)
        self.assertEqual(ann.allocate, allocate)
        self.assertEqual(ann.mask, mask)

    def test_slots(self):
        """Test that __slots__ is properly defined."""
        ann = DataflowOpAnnotation(set(), set(), set(), None)
        self.assertTrue(hasattr(ann, "read"))
        self.assertTrue(hasattr(ann, "modify"))
        self.assertTrue(hasattr(ann, "allocate"))
        self.assertTrue(hasattr(ann, "mask"))

    def test_rewrite_read(self):
        """Test rewriting read field."""
        ann = DataflowOpAnnotation({"a"}, {"b"}, {"c"}, None)
        new_ann = ann.rewrite(read={"x"})
        self.assertEqual(new_ann.read, {"x"})
        self.assertEqual(new_ann.modify, {"b"})
        self.assertEqual(new_ann.allocate, {"c"})

    def test_rewrite_modify(self):
        """Test rewriting modify field."""
        ann = DataflowOpAnnotation({"a"}, {"b"}, {"c"}, None)
        new_ann = ann.rewrite(modify={"y"})
        self.assertEqual(new_ann.read, {"a"})
        self.assertEqual(new_ann.modify, {"y"})
        self.assertEqual(new_ann.allocate, {"c"})

    def test_rewrite_allocate(self):
        """Test rewriting allocate field."""
        ann = DataflowOpAnnotation({"a"}, {"b"}, {"c"}, None)
        new_ann = ann.rewrite(allocate={"z"})
        self.assertEqual(new_ann.read, {"a"})
        self.assertEqual(new_ann.modify, {"b"})
        self.assertEqual(new_ann.allocate, {"z"})

    def test_rewrite_mask(self):
        """Test rewriting mask field."""
        ann = DataflowOpAnnotation({"a"}, {"b"}, {"c"}, "old_mask")
        new_ann = ann.rewrite(mask="new_mask")
        self.assertEqual(new_ann.mask, "new_mask")

    def test_rewrite_multiple(self):
        """Test rewriting multiple fields at once."""
        ann = DataflowOpAnnotation({"a"}, {"b"}, {"c"}, None)
        new_ann = ann.rewrite(read={"x"}, modify={"y"})
        self.assertEqual(new_ann.read, {"x"})
        self.assertEqual(new_ann.modify, {"y"})
        self.assertEqual(new_ann.allocate, {"c"})

    def test_rewrite_unknown_field_raises(self):
        """Test that rewriting unknown field raises AssertionError."""
        ann = DataflowOpAnnotation({"a"}, {"b"}, {"c"}, None)
        with self.assertRaises(AssertionError):
            ann.rewrite(unknown_field="value")


class TestDataflowSlotAnnotation(unittest.TestCase):
    """Test cases for DataflowSlotAnnotation class."""

    def test_init(self):
        """Test DataflowSlotAnnotation initialization."""
        values = {"val1", "val2"}
        unique = True
        ann = DataflowSlotAnnotation(values, unique)
        self.assertEqual(ann.values, values)
        self.assertEqual(ann.unique, unique)

    def test_slots(self):
        """Test that __slots__ is properly defined."""
        ann = DataflowSlotAnnotation(set(), False)
        self.assertTrue(hasattr(ann, "values"))
        self.assertTrue(hasattr(ann, "unique"))

    def test_rewrite_values(self):
        """Test rewriting values field."""
        ann = DataflowSlotAnnotation({"a"}, True)
        new_ann = ann.rewrite(values={"x"})
        self.assertEqual(new_ann.values, {"x"})
        self.assertEqual(new_ann.unique, True)

    def test_rewrite_unique(self):
        """Test rewriting unique field."""
        ann = DataflowSlotAnnotation({"a"}, True)
        new_ann = ann.rewrite(unique=False)
        self.assertEqual(new_ann.values, {"a"})
        self.assertEqual(new_ann.unique, False)


class TestDataflowObjectAnnotation(unittest.TestCase):
    """Test cases for DataflowObjectAnnotation class."""

    def test_init(self):
        """Test DataflowObjectAnnotation initialization."""
        ann = DataflowObjectAnnotation(True, False, "mask", True)
        self.assertEqual(ann.preexisting, True)
        self.assertEqual(ann.unique, False)
        self.assertEqual(ann.mask, "mask")
        self.assertEqual(ann.final, True)

    def test_slots(self):
        """Test that __slots__ is properly defined."""
        ann = DataflowObjectAnnotation(False, False, None, False)
        self.assertTrue(hasattr(ann, "preexisting"))
        self.assertTrue(hasattr(ann, "unique"))
        self.assertTrue(hasattr(ann, "mask"))
        self.assertTrue(hasattr(ann, "final"))

    def test_rewrite_preexisting(self):
        """Test rewriting preexisting field."""
        ann = DataflowObjectAnnotation(True, False, None, False)
        new_ann = ann.rewrite(preexisting=False)
        self.assertEqual(new_ann.preexisting, False)
        self.assertEqual(new_ann.unique, False)

    def test_rewrite_unique(self):
        """Test rewriting unique field."""
        ann = DataflowObjectAnnotation(True, False, None, False)
        new_ann = ann.rewrite(unique=True)
        self.assertEqual(new_ann.unique, True)

    def test_rewrite_mask(self):
        """Test rewriting mask field."""
        ann = DataflowObjectAnnotation(True, False, "old", False)
        new_ann = ann.rewrite(mask="new")
        self.assertEqual(new_ann.mask, "new")

    def test_rewrite_final(self):
        """Test rewriting final field."""
        ann = DataflowObjectAnnotation(True, False, None, False)
        new_ann = ann.rewrite(final=True)
        self.assertEqual(new_ann.final, True)

    def test_repr(self):
        """Test string representation."""
        ann = DataflowObjectAnnotation(True, False, "mask", True)
        repr_str = repr(ann)
        self.assertIn("DataflowObjectAnnotation", repr_str)
        self.assertIn("preexisting", repr_str)
        self.assertIn("unique", repr_str)
        self.assertIn("mask", repr_str)
        self.assertIn("final", repr_str)


if __name__ == "__main__":
    unittest.main()
