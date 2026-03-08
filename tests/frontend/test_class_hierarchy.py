"""Unit tests for class_hierarchy module."""

import unittest
from pyflow.frontend.class_hierarchy import (
    ClassHierarchy,
    ClassInfo,
    CrossModuleResolver,
    MROError,
)


class TestClassInfo(unittest.TestCase):
    """Test cases for the ClassInfo dataclass."""

    def test_create_class_info(self):
        """Test creating a ClassInfo instance."""
        info = ClassInfo(
            name="MyClass",
            qualified_name="mymodule.MyClass",
            module="mymodule",
            bases=["Base"],
            methods={"foo", "bar"},
            attributes={"x", "y"},
        )
        self.assertEqual(info.name, "MyClass")
        self.assertEqual(info.qualified_name, "mymodule.MyClass")
        self.assertEqual(info.module, "mymodule")
        self.assertEqual(info.bases, ["Base"])
        self.assertEqual(info.methods, {"foo", "bar"})
        self.assertEqual(info.attributes, {"x", "y"})

    def test_default_values(self):
        """Test default values for optional fields."""
        info = ClassInfo(
            name="Simple",
            qualified_name="mod.Simple",
            module="mod",
        )
        self.assertEqual(info.bases, [])
        self.assertEqual(info.methods, set())
        self.assertEqual(info.attributes, set())
        self.assertIsNone(info.ast_node)
        self.assertIsNone(info.code)


class TestClassHierarchy(unittest.TestCase):
    """Test cases for the ClassHierarchy class."""

    def setUp(self):
        """Set up test fixtures."""
        self.hierarchy = ClassHierarchy(verbose=False)

    def test_builtin_registration(self):
        """Test that built-in types are registered."""
        self.assertIn("builtins.object", self.hierarchy.classes)
        self.assertIn("builtins.int", self.hierarchy.classes)
        self.assertIn("builtins.str", self.hierarchy.classes)

    def test_register_simple_class(self):
        """Test registering a simple class."""
        qname = self.hierarchy.register_class(
            name="MyClass",
            bases=[],
            module="mymodule",
            methods={"foo"},
        )
        self.assertEqual(qname, "mymodule.MyClass")
        self.assertIn(qname, self.hierarchy.classes)

    def test_register_class_with_bases(self):
        """Test registering a class with base classes."""
        self.hierarchy.register_class("Base", [], "mod1", methods={"base_method"})
        qname = self.hierarchy.register_class(
            name="Derived",
            bases=["Base"],
            module="mod2",
            methods={"derived_method"},
        )
        
        cls_info = self.hierarchy.get_class_info(qname)
        self.assertIsNotNone(cls_info)
        self.assertEqual(cls_info.bases, ["Base"])

    def test_resolve_base_class_same_module(self):
        """Test resolving base class in same module."""
        self.hierarchy.register_class("Base", [], "mymodule")
        
        resolved = self.hierarchy.resolve_base_class("Base", "mymodule")
        self.assertEqual(resolved, "mymodule.Base")

    def test_resolve_base_class_builtin(self):
        """Test resolving built-in base class."""
        resolved = self.hierarchy.resolve_base_class("object", "mymodule")
        self.assertEqual(resolved, "builtins.object")

    def test_resolve_base_class_with_imports(self):
        """Test resolving base class using import mapping."""
        self.hierarchy.register_class("External", [], "external")
        
        imports = {"External": "external.External"}
        resolved = self.hierarchy.resolve_base_class("External", "mymodule", imports)
        self.assertEqual(resolved, "external.External")

    def test_resolve_base_class_does_not_guess_across_modules(self):
        """Ambiguous simple names should remain unresolved without an import."""
        self.hierarchy.register_class("Base", [], "pkg1")
        self.hierarchy.register_class("Base", [], "pkg2")

        resolved = self.hierarchy.resolve_base_class("Base", "consumer")
        self.assertIsNone(resolved)

    def test_resolve_dotted_base_class_through_import_alias(self):
        """Aliased module prefixes should be expanded before dotted-base lookup."""
        self.hierarchy.register_class("Base", [], "pkg")

        imports = {"p": "pkg"}
        resolved = self.hierarchy.resolve_base_class("p.Base", "mymodule", imports)
        self.assertEqual(resolved, "pkg.Base")

    def test_get_mro_simple_class(self):
        """Test MRO for a simple class."""
        self.hierarchy.register_class("Simple", [], "mod")
        
        mro = self.hierarchy.get_mro("mod.Simple")
        self.assertEqual(mro[0], "mod.Simple")
        self.assertIn("builtins.object", mro)

    def test_get_mro_single_inheritance(self):
        """Test MRO for single inheritance chain."""
        self.hierarchy.register_class("A", [], "mod")
        self.hierarchy.register_class("B", ["A"], "mod")
        
        cls_a = self.hierarchy.get_class_info("mod.A")
        cls_b = self.hierarchy.get_class_info("mod.B")
        cls_a.resolved_bases = []
        cls_b.resolved_bases = ["mod.A"]
        self.hierarchy._invalidate_cache("mod.B")
        
        mro = self.hierarchy.get_mro("mod.B")
        self.assertEqual(mro[0], "mod.B")
        self.assertEqual(mro[1], "mod.A")

    def test_get_mro_diamond_inheritance(self):
        """Test MRO for diamond inheritance."""
        self.hierarchy.register_class("A", [], "mod", methods={"a"})
        self.hierarchy.register_class("B", ["A"], "mod", methods={"b"})
        self.hierarchy.register_class("C", ["A"], "mod", methods={"c"})
        self.hierarchy.register_class("D", ["B", "C"], "mod", methods={"d"})
        
        self.hierarchy.resolve_bases([], "mod", {})
        
        cls_b = self.hierarchy.get_class_info("mod.B")
        cls_c = self.hierarchy.get_class_info("mod.C")
        cls_d = self.hierarchy.get_class_info("mod.D")
        
        cls_b.resolved_bases = ["mod.A"]
        cls_c.resolved_bases = ["mod.A"]
        cls_d.resolved_bases = ["mod.B", "mod.C"]
        
        self.hierarchy._invalidate_cache("mod.D")
        
        mro = self.hierarchy.get_mro("mod.D")
        
        self.assertEqual(mro[0], "mod.D")
        self.assertIn("mod.B", mro)
        self.assertIn("mod.C", mro)
        self.assertIn("mod.A", mro)
        
        self.assertLess(mro.index("mod.B"), mro.index("mod.A"))
        self.assertLess(mro.index("mod.C"), mro.index("mod.A"))

    def test_resolve_method_simple(self):
        """Test method resolution in simple class."""
        self.hierarchy.register_class("A", [], "mod", methods={"foo"})
        
        result = self.hierarchy.resolve_method("mod.A", "foo")
        self.assertEqual(result, "mod.A")

    def test_resolve_method_inheritance(self):
        """Test method resolution through inheritance."""
        self.hierarchy.register_class("Base", [], "mod", methods={"base_method"})
        self.hierarchy.register_class("Derived", ["Base"], "mod", methods={"derived_method"})
        
        cls_base = self.hierarchy.get_class_info("mod.Base")
        cls_derived = self.hierarchy.get_class_info("mod.Derived")
        cls_base.resolved_bases = []
        cls_derived.resolved_bases = ["mod.Base"]
        
        result = self.hierarchy.resolve_method("mod.Derived", "base_method")
        self.assertEqual(result, "mod.Base")

    def test_resolve_method_not_found(self):
        """Test method resolution when method doesn't exist."""
        self.hierarchy.register_class("A", [], "mod")
        
        result = self.hierarchy.resolve_method("mod.A", "nonexistent")
        self.assertIsNone(result)

    def test_get_all_subclasses(self):
        """Test getting all subclasses."""
        self.hierarchy.register_class("A", [], "mod")
        self.hierarchy.register_class("B", ["A"], "mod")
        self.hierarchy.register_class("C", ["A"], "mod")
        self.hierarchy.register_class("D", ["B"], "mod")
        
        cls_a = self.hierarchy.get_class_info("mod.A")
        cls_b = self.hierarchy.get_class_info("mod.B")
        cls_c = self.hierarchy.get_class_info("mod.C")
        cls_d = self.hierarchy.get_class_info("mod.D")
        
        cls_a.resolved_bases = []
        cls_b.resolved_bases = ["mod.A"]
        cls_c.resolved_bases = ["mod.A"]
        cls_d.resolved_bases = ["mod.B"]
        
        subclasses = self.hierarchy.get_all_subclasses("mod.A")
        self.assertIn("mod.B", subclasses)
        self.assertIn("mod.C", subclasses)
        self.assertIn("mod.D", subclasses)

    def test_is_subclass(self):
        """Test subclass check."""
        self.hierarchy.register_class("A", [], "mod")
        self.hierarchy.register_class("B", ["A"], "mod")
        
        cls_a = self.hierarchy.get_class_info("mod.A")
        cls_b = self.hierarchy.get_class_info("mod.B")
        cls_a.resolved_bases = []
        cls_b.resolved_bases = ["mod.A"]
        
        self.assertTrue(self.hierarchy.is_subclass("mod.B", "mod.A"))
        self.assertFalse(self.hierarchy.is_subclass("mod.A", "mod.B"))

    def test_common_ancestor(self):
        """Test finding common ancestor."""
        self.hierarchy.register_class("A", [], "mod")
        self.hierarchy.register_class("B", ["A"], "mod")
        self.hierarchy.register_class("C", ["A"], "mod")
        
        cls_a = self.hierarchy.get_class_info("mod.A")
        cls_b = self.hierarchy.get_class_info("mod.B")
        cls_c = self.hierarchy.get_class_info("mod.C")
        cls_a.resolved_bases = []
        cls_b.resolved_bases = ["mod.A"]
        cls_c.resolved_bases = ["mod.A"]
        
        ancestor = self.hierarchy.common_ancestor("mod.B", "mod.C")
        self.assertEqual(ancestor, "mod.A")

    def test_get_all_methods(self):
        """Test getting all methods available on a class."""
        self.hierarchy.register_class("Base", [], "mod", methods={"base_method"})
        self.hierarchy.register_class("Derived", ["Base"], "mod", methods={"derived_method"})
        
        cls_base = self.hierarchy.get_class_info("mod.Base")
        cls_derived = self.hierarchy.get_class_info("mod.Derived")
        cls_base.resolved_bases = []
        cls_derived.resolved_bases = ["mod.Base"]
        
        methods = self.hierarchy.get_all_methods("mod.Derived")
        self.assertIn("derived_method", methods)
        self.assertIn("base_method", methods)


class TestCrossModuleResolver(unittest.TestCase):
    """Test cases for the CrossModuleResolver class."""

    def setUp(self):
        """Set up test fixtures."""
        self.hierarchy = ClassHierarchy(verbose=False)
        self.resolver = CrossModuleResolver(self.hierarchy, verbose=False)

    def test_register_module(self):
        """Test registering a module."""
        self.resolver.register_module(
            module_name="mymodule",
            classes={
                "MyClass": ClassInfo(
                    name="MyClass",
                    qualified_name="mymodule.MyClass",
                    module="mymodule",
                    methods={"foo"},
                )
            },
            functions={"my_func": object()},
            imports={"External": "external.Module"},
        )
        
        self.assertIn("mymodule", self.resolver.modules)
        self.assertIn("mymodule.MyClass", self.hierarchy.classes)
        self.assertIn("mymodule", self.resolver.imports)

    def test_resolve_name_local_class(self):
        """Test resolving a local class name."""
        self.hierarchy.register_class("LocalClass", [], "mymodule")
        
        result = self.resolver.resolve_name("LocalClass", "mymodule")
        self.assertEqual(result, ("mymodule.LocalClass", "class"))

    def test_resolve_name_via_import(self):
        """Test resolving a name through import."""
        self.hierarchy.register_class("External", [], "external")
        self.resolver.imports["mymodule"] = {"External": "external.External"}
        
        result = self.resolver.resolve_name("External", "mymodule")
        self.assertEqual(result, ("external.External", "class"))

    def test_resolve_name_builtin(self):
        """Test resolving a built-in type."""
        result = self.resolver.resolve_name("int", "mymodule")
        self.assertEqual(result, ("builtins.int", "class"))

    def test_resolve_name_not_found(self):
        """Test resolving a name that doesn't exist."""
        result = self.resolver.resolve_name("NonExistent", "mymodule")
        self.assertIsNone(result)


class TestMROError(unittest.TestCase):
    """Test cases for MROError exception."""

    def test_mro_error(self):
        """Test raising MROError."""
        with self.assertRaises(MROError):
            raise MROError("Inconsistent hierarchy")


if __name__ == "__main__":
    unittest.main()
