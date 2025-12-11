"""Unit tests for dependency_resolver module."""

import unittest
from unittest.mock import Mock, patch

from pyflow.frontend.dependency_resolver import DependencyResolver, DependencyStrategy


class TestDependencyStrategy(unittest.TestCase):
    """Test cases for DependencyStrategy enum."""

    def test_strategy_values(self):
        """Test that all strategies have correct values."""
        self.assertEqual(DependencyStrategy.AUTO.value, "auto")
        self.assertEqual(DependencyStrategy.STUBS.value, "stubs")
        self.assertEqual(DependencyStrategy.NOOP.value, "noop")
        self.assertEqual(DependencyStrategy.STRICT.value, "strict")
        self.assertEqual(DependencyStrategy.AST_ONLY.value, "ast_only")


class TestDependencyResolver(unittest.TestCase):
    """Test cases for the DependencyResolver class."""

    def setUp(self):
        """Set up test fixtures."""
        self.resolver = DependencyResolver(strategy="auto", verbose=False)

    def test_init_default(self):
        """Test DependencyResolver initialization with defaults."""
        resolver = DependencyResolver()
        self.assertEqual(resolver.strategy, DependencyStrategy.AUTO)
        self.assertFalse(resolver.verbose)
        self.assertIsNotNone(resolver.safe_modules)
        self.assertIsInstance(resolver._module_cache, dict)

    def test_init_custom_strategy(self):
        """Test DependencyResolver initialization with custom strategy."""
        resolver = DependencyResolver(strategy="strict", verbose=True)
        self.assertEqual(resolver.strategy, DependencyStrategy.STRICT)
        self.assertTrue(resolver.verbose)

    def test_init_custom_safe_modules(self):
        """Test DependencyResolver initialization with custom safe modules."""
        safe_modules = ['math', 'json']
        resolver = DependencyResolver(safe_modules=safe_modules)
        self.assertEqual(resolver.safe_modules, safe_modules)

    def test_extract_functions_auto(self):
        """Test extract_functions with AUTO strategy."""
        source = """
def test_func():
    return 42
"""
        functions = self.resolver.extract_functions(source, "test.py")
        self.assertIsInstance(functions, dict)

    def test_extract_functions_strict(self):
        """Test extract_functions with STRICT strategy."""
        resolver = DependencyResolver(strategy="strict", verbose=False)
        source = """
def test_func():
    return 42
"""
        functions = resolver.extract_functions(source, "test.py")
        self.assertIsInstance(functions, dict)

    def test_extract_functions_stubs(self):
        """Test extract_functions with STUBS strategy."""
        resolver = DependencyResolver(strategy="stubs", verbose=False)
        source = """
def test_func():
    return 42
"""
        functions = resolver.extract_functions(source, "test.py")
        self.assertIsInstance(functions, dict)

    def test_extract_functions_noop(self):
        """Test extract_functions with NOOP strategy."""
        resolver = DependencyResolver(strategy="noop", verbose=False)
        source = """
def test_func():
    return 42
"""
        functions = resolver.extract_functions(source, "test.py")
        self.assertIsInstance(functions, dict)

    def test_extract_functions_ast_only(self):
        """Test extract_functions with AST_ONLY strategy."""
        resolver = DependencyResolver(strategy="ast_only", verbose=False)
        source = """
def test_func():
    return 42
"""
        functions = resolver.extract_functions(source, "test.py")
        self.assertIsInstance(functions, dict)
        # AST-only should extract function names
        self.assertIn("test_func", functions)

    def test_extract_functions_with_imports(self):
        """Test extract_functions with import statements."""
        source = """
import math

def test_func(x):
    return math.sqrt(x)
"""
        functions = self.resolver.extract_functions(source, "test.py")
        self.assertIsInstance(functions, dict)

    def test_extract_functions_with_missing_imports(self):
        """Test extract_functions with missing imports."""
        source = """
import nonexistent_module

def test_func():
    return nonexistent_module.something()
"""
        functions = self.resolver.extract_functions(source, "test.py")
        # Should handle gracefully
        self.assertIsInstance(functions, dict)

    def test_extract_functions_multiple_functions(self):
        """Test extract_functions with multiple functions."""
        source = """
def func1():
    return 1

def func2():
    return 2

def func3():
    return 3
"""
        functions = self.resolver.extract_functions(source, "test.py")
        self.assertIsInstance(functions, dict)

    def test_extract_functions_with_parameters(self):
        """Test extract_functions with function parameters."""
        source = """
def test_func(a, b, c=10):
    return a + b + c
"""
        functions = self.resolver.extract_functions(source, "test.py")
        self.assertIsInstance(functions, dict)

    def test_extract_functions_with_args_kwargs(self):
        """Test extract_functions with *args and **kwargs."""
        source = """
def test_func(*args, **kwargs):
    return len(args) + len(kwargs)
"""
        functions = self.resolver.extract_functions(source, "test.py")
        self.assertIsInstance(functions, dict)

    def test_extract_functions_private_functions(self):
        """Test that private functions are filtered out."""
        source = """
def public_func():
    return 1

def _private_func():
    return 2
"""
        functions = self.resolver.extract_functions(source, "test.py")
        # Private functions should be filtered out
        self.assertNotIn("_private_func", functions)

    def test_create_safe_exec_globals(self):
        """Test creating safe execution globals."""
        globals_dict = self.resolver._create_safe_exec_globals()
        self.assertIsInstance(globals_dict, dict)
        # vars(builtins) returns the module dict, not __builtins__
        # Check for common builtin functions instead
        self.assertIn('len', globals_dict)
        self.assertIn('print', globals_dict)

    def test_find_imports(self):
        """Test finding imports in source code."""
        source = """
import math
import os
from sys import argv
"""
        imports = self.resolver._find_imports(source)
        self.assertIsInstance(imports, set)
        self.assertIn('math', imports)
        self.assertIn('os', imports)
        self.assertIn('sys', imports)

    def test_find_imports_no_imports(self):
        """Test finding imports when there are none."""
        source = """
def test_func():
    return 42
"""
        imports = self.resolver._find_imports(source)
        self.assertEqual(len(imports), 0)

    def test_find_imports_invalid_syntax(self):
        """Test finding imports with invalid syntax."""
        source = "invalid syntax here"
        imports = self.resolver._find_imports(source)
        # Should return empty set on error
        self.assertEqual(imports, set())

    def test_create_stub_module(self):
        """Test creating a stub module."""
        stub_module = self.resolver._create_stub_module("test_module")
        self.assertIsNotNone(stub_module)
        self.assertEqual(stub_module.__name__, "test_module")
        # Should allow attribute access
        attr = stub_module.some_attr
        self.assertIsNotNone(attr)

    def test_create_noop_module(self):
        """Test creating a no-op module."""
        noop_module = self.resolver._create_noop_module("test_module")
        self.assertIsNotNone(noop_module)
        self.assertEqual(noop_module.__name__, "test_module")

    def test_create_ast_stub(self):
        """Test creating an AST stub function."""
        import ast as python_ast
        
        source = "def test_func(a, b): return a + b"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        stub_func = self.resolver._create_ast_stub(func_node)
        self.assertIsNotNone(stub_func)
        self.assertEqual(stub_func.__name__, "test_func")
        # Should be callable
        result = stub_func()
        self.assertIsNone(result)  # No-op returns None

    def test_filter_functions(self):
        """Test filtering functions from module globals."""
        def test_func():
            return 1
        
        module_globals = {
            'test_func': test_func,
            'builtin_func': len,  # Built-in should be filtered
            '__builtins__': __builtins__,
        }
        
        filtered = self.resolver._filter_functions(module_globals, "test.py")
        self.assertIsInstance(filtered, dict)
        # Built-in functions should be filtered out
        self.assertNotIn('builtin_func', filtered)

    def test_filter_functions_with_code_filename(self):
        """Test filtering functions with code filename matching."""
        def test_func():
            return 1
        
        # Use a real function - the actual filename will be the test file
        # The filter checks if code.co_filename matches the file_path
        module_globals = {'test_func': test_func}
        # Use the actual test file path
        import os
        test_file = os.path.abspath(__file__)
        filtered = self.resolver._filter_functions(module_globals, test_file)
        # Should return a dict (might be empty if filename doesn't match exactly)
        self.assertIsInstance(filtered, dict)

    def test_extract_ast_functions(self):
        """Test extracting functions using AST only."""
        source = """
def func1():
    return 1

def func2(x, y):
    return x + y
"""
        functions = self.resolver._extract_ast_functions(source, "test.py")
        self.assertIsInstance(functions, dict)
        self.assertIn("func1", functions)
        self.assertIn("func2", functions)

    def test_extract_ast_functions_invalid_syntax(self):
        """Test extracting functions with invalid syntax."""
        source = "invalid syntax here"
        functions = self.resolver._extract_ast_functions(source, "test.py")
        # Should return empty dict on error
        self.assertEqual(functions, {})

    def test_handle_import_errors(self):
        """Test handling import errors."""
        source = "import nonexistent_module"
        exec_globals = self.resolver._create_safe_exec_globals()
        result = self.resolver._handle_import_errors(source, exec_globals)
        self.assertIsInstance(result, dict)
        # Should have stub for missing module
        self.assertIn('nonexistent_module', result)


if __name__ == "__main__":
    unittest.main()
