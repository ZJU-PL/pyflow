from __future__ import absolute_import
import unittest

from pyflow.analysis.storegraph import storegraph, canonicalobjects, extendedtypes
from pyflow.util.application.console import Console
from pyflow.application.context import CompilerContext
from pyflow.frontend.programextractor import Extractor
from pyflow.util.python import replaceGlobals


class TestStoreGraph(unittest.TestCase):
    def setUp(self):
        self.console = Console()
        self.compiler = CompilerContext(self.console)
        self.extractor = Extractor(self.compiler)
        self.compiler.extractor = self.extractor

    def test_basic_object_creation(self):
        """Test basic object and slot creation in store graph."""
        # Create a simple object
        obj = self.extractor.getObject(42)
        self.assertIsNotNone(obj)

        # Create a store graph
        canonical = canonicalobjects.CanonicalObjects()
        store_graph = storegraph.StoreGraph(self.extractor, canonical)

        self.assertIsNotNone(store_graph)
        self.assertEqual(len(store_graph.slots), 0)

    def test_slot_name_creation(self):
        """Test slot name creation for different types."""
        from pyflow.language.python import ast

        # Create a mock code object
        code = ast.Code("test", ast.CodeParameters(None, [], [], [], None, None, []), ast.Suite([]))

        # Test local slot name
        local_slot = canonicalobjects.LocalSlotName(code, ast.Local("x"), None)
        self.assertTrue(local_slot.isLocal())
        self.assertTrue(local_slot.isRoot())

        # Test existing slot name
        obj = self.extractor.getObject(int)
        existing_slot = canonicalobjects.ExistingSlotName(code, obj, None)
        self.assertTrue(existing_slot.isExisting())

    def test_object_relationships(self):
        """Test object relationships and field access."""
        canonical = canonicalobjects.CanonicalObjects()
        store_graph = storegraph.StoreGraph(self.extractor, canonical)

        # Test field name creation
        int_type = self.extractor.getObject(int)
        field_name = canonical.fieldName("Attribute", int_type)
        self.assertIsNotNone(field_name)

        # Test method type creation
        list_type = self.extractor.getObject(list)
        method_type = canonical.methodType(None, None, list_type, None)
        self.assertIsNotNone(method_type)

    def test_type_extensions(self):
        """Test extended type handling."""
        # Test basic extended type
        obj = self.extractor.getObject(42)
        xtype = extendedtypes.ExtendedObjectType(obj, None)
        self.assertEqual(xtype.obj, obj)
        self.assertFalse(xtype.isExternal())

        # Test external type
        external_xtype = extendedtypes.ExternalObjectType(obj, None)
        self.assertTrue(external_xtype.isExternal())

    def test_store_graph_integration(self):
        """Test store graph with actual object relationships."""
        canonical = canonicalobjects.CanonicalObjects()
        store_graph = storegraph.StoreGraph(self.extractor, canonical)

        # Create some objects
        int_obj = self.extractor.getObject(int)
        str_obj = self.extractor.getObject(str)

        # Test field name creation for different slot types
        field_name = canonical.fieldName("Attribute", str_obj)
        self.assertIsNotNone(field_name)

        # Test that store graph can handle different slot types
        self.assertIsNotNone(store_graph.typeSlotName)
        self.assertIsNotNone(store_graph.lengthSlotName)

        # Test that the store graph has proper initialization
        self.assertIsNotNone(store_graph.regionHint)
        self.assertIsNotNone(store_graph.setManager)


if __name__ == "__main__":
    unittest.main()
