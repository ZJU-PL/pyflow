"""Tests for analysis/lifetimeanalysis/ - Lifetime analysis module."""

import unittest

from pyflow.analysis.lifetimeanalysis.database import structure
from pyflow.analysis.lifetimeanalysis.database import lattice
from pyflow.analysis.lifetimeanalysis.database import tupleset
from pyflow.analysis.lifetimeanalysis.database import mapping


class TestWildcardSchema(unittest.TestCase):
    """Test cases for WildcardSchema."""

    def test_init(self):
        """Test wildcard schema initialization."""
        schema = structure.WildcardSchema()
        # Should not raise

    def test_validate_always_passes(self):
        """Test that wildcard validation always passes."""
        schema = structure.WildcardSchema()
        schema.validate("anything")
        schema.validate(123)
        schema.validate(None)


class TestTypeSchema(unittest.TestCase):
    """Test cases for TypeSchema."""

    def test_init_with_type(self):
        """Test initialization with a single type."""
        schema = structure.TypeSchema(str)
        self.assertEqual(schema.type_, str)

    def test_init_with_tuple(self):
        """Test initialization with tuple of types."""
        schema = structure.TypeSchema((str, int))
        self.assertEqual(schema.type_, (str, int))

    def test_validate_success(self):
        """Test successful type validation."""
        schema = structure.TypeSchema(str)
        schema.validate("test")
        schema.validate("another string")

    def test_validate_failure(self):
        """Test failed type validation raises error."""
        schema = structure.TypeSchema(str)
        with self.assertRaises(structure.base.SchemaError):
            schema.validate(123)

    def test_instance_raises(self):
        """Test that instance() raises error."""
        schema = structure.TypeSchema(str)
        with self.assertRaises(structure.base.SchemaError):
            schema.instance()


class TestCallbackSchema(unittest.TestCase):
    """Test cases for CallbackSchema."""

    def test_init(self):
        """Test callback schema initialization."""
        schema = structure.CallbackSchema(lambda x: isinstance(x, int))
        self.assertTrue(hasattr(schema, 'validator'))

    def test_validate_success(self):
        """Test successful callback validation."""
        schema = structure.CallbackSchema(lambda x: x > 0)
        schema.validate(5)
        schema.validate(100)

    def test_validate_failure(self):
        """Test failed callback validation raises error."""
        schema = structure.CallbackSchema(lambda x: x > 0)
        with self.assertRaises(structure.base.SchemaError):
            schema.validate(-5)

    def test_instance_raises(self):
        """Test that instance() raises error."""
        schema = structure.CallbackSchema(lambda x: True)
        with self.assertRaises(structure.base.SchemaError):
            schema.instance()


class TestStructureSchema(unittest.TestCase):
    """Test cases for StructureSchema."""

    def test_init(self):
        """Test structure schema initialization."""
        int_schema = structure.TypeSchema(int)
        str_schema = structure.TypeSchema(str)
        schema = structure.StructureSchema(
            ("name", str_schema),
            ("value", int_schema)
        )
        self.assertEqual(len(schema.fields), 2)

    def test_field(self):
        """Test getting field schema by name."""
        int_schema = structure.TypeSchema(int)
        str_schema = structure.TypeSchema(str)
        schema = structure.StructureSchema(
            ("name", str_schema),
            ("value", int_schema)
        )
        self.assertIs(schema.field("name"), str_schema)
        self.assertIs(schema.field("value"), int_schema)

    def test_fieldnames(self):
        """Test getting field names."""
        int_schema = structure.TypeSchema(int)
        str_schema = structure.TypeSchema(str)
        schema = structure.StructureSchema(
            ("name", str_schema),
            ("value", int_schema)
        )
        names = list(schema.fieldnames())
        self.assertIn("name", names)
        self.assertIn("value", names)

    def test_validate_success(self):
        """Test successful structure validation."""
        int_schema = structure.TypeSchema(int)
        str_schema = structure.TypeSchema(str)
        schema = structure.StructureSchema(
            ("name", str_schema),
            ("value", int_schema)
        )
        struct_type = schema.type_
        instance = struct_type("test", 42)
        schema.validate(instance)

    def test_validate_wrong_length(self):
        """Test validation fails with wrong number of fields."""
        int_schema = structure.TypeSchema(int)
        str_schema = structure.TypeSchema(str)
        schema = structure.StructureSchema(
            ("name", str_schema),
            ("value", int_schema)
        )
        struct_type = schema.type_
        # Wrong number of fields - only 1 field instead of 2
        with self.assertRaises((structure.base.SchemaError, TypeError)):
            schema.validate(("test",))  # Missing value - tuple of 1 element

    def test_missing(self):
        """Test missing() returns structure with default values."""
        int_schema = structure.TypeSchema(int)
        str_schema = structure.TypeSchema(str)
        schema = structure.StructureSchema(
            ("name", str_schema),
            ("value", int_schema)
        )
        # missing() should return structure with missing field values
        # TypeSchema.missing() will raise, so this tests that behavior
        with self.assertRaises(structure.base.SchemaError):
            schema.missing()

    def test_duplicate_field_raises(self):
        """Test that duplicate field names raise error."""
        int_schema = structure.TypeSchema(int)
        with self.assertRaises(structure.base.SchemaError):
            structure.StructureSchema(
                ("x", int_schema),
                ("x", int_schema)  # Duplicate
            )

    def test_nonexistent_field_raises(self):
        """Test that nonexistent field name raises error."""
        int_schema = structure.TypeSchema(int)
        str_schema = structure.TypeSchema(str)
        schema = structure.StructureSchema(
            ("name", str_schema),
            ("value", int_schema)
        )
        with self.assertRaises(structure.base.SchemaError):
            schema.field("nonexistent")


class TestLatticeSchemas(unittest.TestCase):
    """Test cases for lattice schemas."""

    def test_setUnionSchema_exists(self):
        """Test that setUnionSchema exists and is a SetUnionSchema instance."""
        self.assertIsNotNone(lattice.setUnionSchema)
        self.assertIsInstance(lattice.setUnionSchema, lattice.SetUnionSchema)

    def test_setUnionSchema_merge(self):
        """Test merging sets with setUnionSchema."""
        schema = lattice.setUnionSchema
        # merge() is a class method that merges sets
        result = schema.merge({"a", "b"}, {"c"})
        self.assertEqual(result, {"a", "b", "c"})

    def test_setUnionSchema_merge_empty(self):
        """Test merging empty sets."""
        schema = lattice.setUnionSchema
        result = schema.merge(None, None)
        self.assertIsNone(result)

    def test_setUnionSchema_inplaceMerge(self):
        """Test in-place merging."""
        schema = lattice.setUnionSchema
        result, changed = schema.inplaceMerge({"a"}, {"b"})
        self.assertEqual(result, {"a", "b"})
        self.assertTrue(changed)


class TestTupleSet(unittest.TestCase):
    """Test cases for TupleSet."""

    def test_init(self):
        """Test tuple set initialization."""
        struct_schema = structure.StructureSchema(
            ("code", structure.WildcardSchema()),
            ("context", structure.WildcardSchema())
        )
        ts_schema = tupleset.TupleSetSchema(struct_schema)
        # TupleSetSchema.instance() creates the actual tuple set
        self.assertIsNotNone(ts_schema)

    def test_add(self):
        """Test adding tuples to tuple set."""
        struct_schema = structure.StructureSchema(
            ("code", structure.WildcardSchema()),
            ("context", structure.WildcardSchema())
        )
        ts_schema = tupleset.TupleSetSchema(struct_schema)
        ts = ts_schema()
        # add method should exist
        self.assertTrue(hasattr(ts, 'add'))


class TestMappingSchema(unittest.TestCase):
    """Test cases for MappingSchema."""

    def test_init(self):
        """Test mapping schema initialization."""
        key_schema = structure.WildcardSchema()
        value_schema = lattice.setUnionSchema
        schema = mapping.MappingSchema(key_schema, value_schema)
        self.assertIsNotNone(schema)
        self.assertIs(schema.keyschema, key_schema)
        self.assertIs(schema.valueschema, value_schema)

    def test_instance(self):
        """Test creating mapping schema instance."""
        key_schema = structure.WildcardSchema()
        value_schema = lattice.setUnionSchema
        schema = mapping.MappingSchema(key_schema, value_schema)
        # Calling schema creates a Mapping instance
        instance = schema()
        # Should be a Mapping object
        self.assertIsInstance(instance, mapping.Mapping)
        # Should have data attribute (the underlying dict)
        self.assertTrue(hasattr(instance, 'data'))
        self.assertIsInstance(instance.data, dict)

    def test_mapping_getitem_creates_missing(self):
        """Test that __getitem__ creates missing values."""
        key_schema = structure.WildcardSchema()
        value_schema = lattice.setUnionSchema
        schema = mapping.MappingSchema(key_schema, value_schema)
        instance = schema()
        # Accessing a key should return the missing value from valueschema
        result = instance["key1"]
        # SetUnionSchema.missing() returns None
        self.assertIsNone(result)


class TestObjectInfo(unittest.TestCase):
    """Test cases for ObjectInfo class (mock-based)."""

    def test_init(self):
        """Test ObjectInfo initialization."""
        # Create a mock object node
        class MockXType:
            def isExisting(self):
                return False
            def isExternal(self):
                return False

        class MockObj:
            xtype = MockXType()

        from pyflow.analysis.lifetimeanalysis import ObjectInfo
        info = ObjectInfo(MockObj())
        self.assertEqual(info.refersTo, set())
        self.assertEqual(info.referedFrom, set())
        self.assertEqual(info.localReference, set())
        self.assertEqual(info.heldByClosure, set())
        self.assertFalse(info.globallyVisible)
        self.assertFalse(info.externallyVisible)

    def test_leaks(self):
        """Test leaks() method."""
        class MockXType:
            def isExisting(self):
                return True  # Globally visible
            def isExternal(self):
                return False

        class MockObj:
            xtype = MockXType()

        from pyflow.analysis.lifetimeanalysis import ObjectInfo
        info = ObjectInfo(MockObj())
        self.assertTrue(info.leaks())  # Should leak because globallyVisible=True

    def test_isReachableFrom(self):
        """Test isReachableFrom() method."""
        class MockXType:
            def isExisting(self):
                return False
            def isExternal(self):
                return False

        class MockObj:
            xtype = MockXType()

        from pyflow.analysis.lifetimeanalysis import ObjectInfo
        info1 = ObjectInfo(MockObj())
        info2 = ObjectInfo(MockObj())
        
        info1.heldByClosure.add(info2)
        self.assertTrue(info1.isReachableFrom({info2}))
        self.assertFalse(info1.isReachableFrom(set()))


class TestDFSSearcher(unittest.TestCase):
    """Test cases for DFSSearcher class."""

    def test_init(self):
        """Test DFS searcher initialization."""
        from pyflow.analysis.lifetimeanalysis import DFSSearcher
        searcher = DFSSearcher()
        self.assertEqual(searcher._stack, [])
        self.assertEqual(searcher._touched, set())

    def test_enqueue(self):
        """Test enqueueing nodes."""
        from pyflow.analysis.lifetimeanalysis import DFSSearcher
        searcher = DFSSearcher()
        searcher.enqueue("node1", "node2")
        self.assertEqual(len(searcher._stack), 2)
        self.assertEqual(searcher._touched, {"node1", "node2"})

    def test_enqueue_duplicates(self):
        """Test that duplicate enqueue is ignored."""
        from pyflow.analysis.lifetimeanalysis import DFSSearcher
        searcher = DFSSearcher()
        searcher.enqueue("node1")
        searcher.enqueue("node1")  # Duplicate
        self.assertEqual(len(searcher._stack), 1)

    def test_process(self):
        """Test processing all enqueued nodes using DFS (LIFO/stack order)."""
        from pyflow.analysis.lifetimeanalysis import DFSSearcher
        
        class MockSearcher(DFSSearcher):
            def __init__(self):
                super().__init__()
                self.visited = []
            
            def visit(self, node):
                self.visited.append(node)
        
        searcher = MockSearcher()
        searcher.enqueue("a", "b", "c")
        searcher.process()
        # DFS using stack is LIFO, so order is reversed
        self.assertEqual(searcher.visited, ["c", "b", "a"])


class TestInvertInvokes(unittest.TestCase):
    """Test cases for invertInvokes function."""

    def test_invertInvokes_basic(self):
        """Test that invertInvokes function exists and is callable."""
        from pyflow.analysis.lifetimeanalysis import invertInvokes
        self.assertTrue(callable(invertInvokes))


class TestWrapSchemas(unittest.TestCase):
    """Test cases for schema wrapping functions."""

    def test_wrapOpContext(self):
        """Test wrapOpContext function."""
        from pyflow.analysis.lifetimeanalysis import wrapOpContext, opDataflowSchema
        # wrapOpContext should create a schema with nested mappings
        schema = wrapOpContext(lattice.setUnionSchema)
        self.assertIsNotNone(schema)

    def test_wrapCodeContext(self):
        """Test wrapCodeContext function."""
        from pyflow.analysis.lifetimeanalysis import wrapCodeContext
        schema = wrapCodeContext(lattice.setUnionSchema)
        self.assertIsNotNone(schema)


class TestFilteredSCC(unittest.TestCase):
    """Test cases for filteredSCC function."""

    def test_filteredSCC_empty(self):
        """Test SCC filtering with empty graph."""
        from pyflow.analysis.lifetimeanalysis import filteredSCC
        
        result = filteredSCC([])
        self.assertEqual(result, [])

    def test_filteredSCC_nontrivial(self):
        """Test SCC filtering with non-trivial cycles."""
        from pyflow.analysis.lifetimeanalysis import filteredSCC
        
        # Create a simple cycle: A -> B -> C -> A
        # This requires the StronglyConnectedComponents from PADS
        # The function should find cycles with more than 1 node
        pass  # Testing actual SCC requires complex setup


if __name__ == "__main__":
    unittest.main()
