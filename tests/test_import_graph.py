"""
Unit tests for pyflow.machinery.import_graph module
"""
import ast
import unittest

from pyflow.machinery.import_graph import Tree, ImportGraph


class TestTree(unittest.TestCase):
    """Test cases for the Tree class"""

    def test_tree_initialization(self):
        """Test Tree node initialization"""
        node = Tree("test_module")
        self.assertEqual(node.name, "test_module")
        self.assertEqual(node.children, [])
        self.assertIsNone(node.parent)
        self.assertEqual(node.cargo, {})

    def test_tree_str_representation(self):
        """Test string representation of Tree node"""
        node = Tree("module_name")
        self.assertEqual(str(node), "module_name")


class TestImportGraph(unittest.TestCase):
    """Test cases for the ImportGraph class"""

    def test_import_graph_initialization(self):
        """Test ImportGraph initialization"""
        entry_point = "test_package/module.py"
        graph = ImportGraph(entry_point)
        self.assertEqual(graph.entry_point, entry_point)
        self.assertEqual(graph.root.name, "module.py")  # basename of entry_point
        self.assertIsNone(graph.root.parent)

    def test_parse_import(self):
        """Test parsing import statements from AST"""
        source_code = """
from .module_b import func_b
from . import module_c
from ..parent import something
import standard_lib
"""
        tree = ast.parse(source_code)

        import_map = ImportGraph.parse_import(tree)

        # Check different types of imports
        self.assertIn('module_b', import_map)  # module name for 'from .module_b import func_b'
        self.assertIn(1, import_map)  # relative import level 1 for 'from . import module_c'
        self.assertIn('parent', import_map)  # module name for level 2 import

        # Check imported names for module_b
        module_b_imports = import_map['module_b']
        self.assertIn('func_b', module_b_imports)

        # Check imported names for level 1 imports
        level_1_imports = import_map[1]
        self.assertIn('module_c', level_1_imports)

        # Check level 2 import (stored under module name 'parent')
        parent_imports = import_map['parent']
        self.assertIn('something', parent_imports)

        # Note: Regular imports (like 'import standard_lib') are not currently handled

    def test_leaf2root(self):
        """Test generating full path from leaf to root"""
        # Create a mock tree structure: root -> child -> grandchild
        root = Tree("root")
        child = Tree("module_a.py")
        child.parent = root
        grandchild = Tree("function")
        grandchild.parent = child

        # Test path generation for .py file
        path = ImportGraph.leaf2root(child)
        self.assertIn("root", path)
        self.assertIn("module_a", path)

        # Test path generation for non-.py file
        path = ImportGraph.leaf2root(grandchild)
        self.assertIn("root", path)
        self.assertIn("module_a", path)
        self.assertIn("function", path)

    def test_find_node_by_name(self):
        """Test finding nodes by name"""
        # Create test nodes
        nodes = [
            Tree("module_a.py"),
            Tree("module_b.py"),
            Tree("__init__.py"),
            Tree("utils.py")
        ]

        # Test finding by exact name
        found = ImportGraph.find_node_by_name(nodes, "module_a.py")
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "module_a.py")

        # Test finding without .py extension
        found = ImportGraph.find_node_by_name(nodes, "module_b")
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "module_b.py")

        # Test finding __init__.py by name
        found = ImportGraph.find_node_by_name(nodes, "__init__.py")
        self.assertIsNotNone(found)

        # Test not found
        not_found = ImportGraph.find_node_by_name(nodes, "nonexistent")
        self.assertIsNone(not_found)

    def test_find_child_by_name(self):
        """Test finding child nodes by name"""
        # Create test nodes
        root = Tree("root")
        child1 = Tree("module_a.py")
        child2 = Tree("module_b.py")
        root.children = [child1, child2]

        # Test finding child by name
        found = ImportGraph.find_child_by_name(root, "module_a.py")
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "module_a.py")

        # Test not finding child
        not_found = ImportGraph.find_child_by_name(root, "nonexistent")
        self.assertIsNone(not_found)


if __name__ == "__main__":
    unittest.main()
