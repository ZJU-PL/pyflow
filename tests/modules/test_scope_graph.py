"""Tests for language/modules/_scope_graph.py - Scope graph construction for name resolution."""

import unittest
import ast

from pyflow.language.modules._scope_graph import ScopeGraph


class TestScopeGraph(unittest.TestCase):
    """Test cases for ScopeGraph class."""

    def test_empty_module(self):
        """Test scope graph on empty module."""
        code = ""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("Mod", sg.references)
        self.assertIn("Mod", sg.declarations)

    def test_function_declaration(self):
        """Test that function declarations are tracked."""
        code = """
def my_function():
    pass
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("my_function", sg.declarations["Mod"])

    def test_class_declaration(self):
        """Test that class declarations are tracked."""
        code = """
class MyClass:
    pass
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("MyClass", sg.declarations["Mod"])

    def test_variable_assignment(self):
        """Test that variable assignments are tracked as declarations."""
        code = """
x = 1
y = 2
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("x", sg.declarations["Mod"])
        self.assertIn("y", sg.declarations["Mod"])

    def test_variable_reference(self):
        """Test that variable references are tracked."""
        code = """
x = 1
y = x + 1
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        # x is declared then referenced
        self.assertIn("x", sg.declarations["Mod"])
        # y is declared, x is referenced
        self.assertIn("x", sg.references["Mod"])
        self.assertIn("y", sg.declarations["Mod"])

    def test_nested_function_scope(self):
        """Test scope tracking for nested functions."""
        code = """
def outer():
    def inner():
        pass
    return inner
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("outer", sg.declarations["Mod"])
        self.assertIn("inner", sg.declarations["outer"])

    def test_class_with_method(self):
        """Test scope tracking for class methods."""
        code = """
class MyClass:
    def method(self):
        x = 1
        return x
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("MyClass", sg.declarations["Mod"])
        self.assertIn("method", sg.declarations["MyClass"])
        self.assertIn("x", sg.declarations["method"])

    def test_import_statement(self):
        """Test that import statements are tracked."""
        code = """
import os
import sys as system
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("os", sg.imports["Mod"])
        # The module stores the original name, not the alias
        self.assertIn("sys", sg.imports["Mod"])

    def test_import_from_statement(self):
        """Test that from-import statements are tracked."""
        code = """
from os import path
from collections import OrderedDict as OD
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("path", sg.imports["Mod"])
        # The module stores the original name, not the alias
        self.assertIn("OrderedDict", sg.imports["Mod"])

    def test_inheritance_graph(self):
        """Test that class inheritance is tracked."""
        code = """
class Base:
    pass

class Derived(Base):
    pass
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("Base", sg.ig.nodes())
        self.assertIn("Derived", sg.ig.nodes())
        self.assertTrue(sg.ig.has_edge("Derived", "Base"))

    def test_multiple_inheritance(self):
        """Test multiple inheritance tracking."""
        code = """
class A:
    pass

class B:
    pass

class C(A, B):
    pass
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertTrue(sg.ig.has_edge("C", "A"))
        self.assertTrue(sg.ig.has_edge("C", "B"))

    def test_scope_graph_structure(self):
        """Test that scope relationships are tracked in the graph."""
        code = """
def outer():
    x = 1
    def inner():
        y = 2
        return y
    return inner
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        # Check that scopes exist
        self.assertIn("outer", sg.declarations)
        self.assertIn("inner", sg.declarations["outer"])

    def test_variable_in_inner_scope(self):
        """Test that variables in inner scopes don't leak."""
        code = """
def outer():
    x = 1
    def inner():
        x = 2
        return x
    return inner
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        # x is declared in both outer and inner scopes
        self.assertIn("x", sg.declarations["outer"])
        self.assertIn("x", sg.declarations["inner"])

    def test_loop_variable_reference(self):
        """Test that loop variables are properly tracked."""
        code = """
for i in range(10):
    print(i)
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        # Loop variable i should be declared in module scope
        self.assertIn("i", sg.declarations["Mod"])

    def test_lambda_reference(self):
        """Test that lambda references are tracked."""
        code = """
f = lambda x: x + 1
result = f(5)
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        self.assertIn("f", sg.declarations["Mod"])
        self.assertIn("f", sg.references["Mod"])

    def test_add_scope(self):
        """Test the add_scope method."""
        sg = ScopeGraph()
        sg.add_scope("test_scope", "Mod")
        
        self.assertIn("test_scope", sg.parent_relations)
        self.assertEqual(sg.parent_relations["test_scope"], "Mod")

    def test_get_parent(self):
        """Test the get_parent method."""
        sg = ScopeGraph()
        sg.add_scope("child_scope", "parent_scope")
        
        parent = sg.get_parent("child_scope")
        self.assertEqual(parent, "parent_scope")

    def test_get_parent_missing_scope(self):
        """Test that get_parent raises exception for missing scope."""
        sg = ScopeGraph()
        
        with self.assertRaises(Exception):
            sg.get_parent("nonexistent")

    def test_add_reference_load(self):
        """Test adding a load reference."""
        sg = ScopeGraph()
        sg.add_reference("Mod", "my_var", "load")
        # Bug M fix: add_reference now appends to a list instead of overwriting.
        # Use assertIn (consistent with all other tests in this file).
        self.assertIn("my_var", sg.references["Mod"])

    def test_add_reference_store(self):
        """Test adding a store reference."""
        sg = ScopeGraph()
        sg.add_reference("Mod", "my_var", "store")
        # Bug M fix: add_reference now appends to a list instead of overwriting.
        self.assertIn("my_var", sg.declarations["Mod"])

    def test_add_reference_unknown_context(self):
        """Test that unknown context raises exception."""
        sg = ScopeGraph()
        
        with self.assertRaises(Exception):
            sg.add_reference("Mod", "my_var", "unknown")

    def test_print_out(self):
        """Test print_out method doesn't raise exceptions."""
        code = """
class MyClass:
    pass
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        # Should not raise any exception
        sg.print_out()

    def test_build_with_complex_code(self):
        """Test building scope graph with complex code."""
        code = """
import os
from sys import path

MODULE_VAR = 42

class MyClass:
    class_attr = []
    
    def __init__(self, value):
        self.value = value
    
    def method(self, x):
        local_var = x * 2
        return self.value + local_var

def my_function(a, b):
    result = MyClass(a).method(b)
    return result

# Use the function
output = my_function(1, 2)
"""
        tree = ast.parse(code)
        sg = ScopeGraph()
        sg.build(tree)
        
        # Check module-level declarations
        self.assertIn("MODULE_VAR", sg.declarations["Mod"])
        self.assertIn("MyClass", sg.declarations["Mod"])
        self.assertIn("my_function", sg.declarations["Mod"])
        self.assertIn("output", sg.declarations["Mod"])
        
        # Check imports
        self.assertIn("os", sg.imports["Mod"])
        self.assertIn("path", sg.imports["Mod"])
        
        # Check class method
        self.assertIn("method", sg.declarations["MyClass"])
        self.assertIn("__init__", sg.declarations["MyClass"])


if __name__ == "__main__":
    unittest.main()
