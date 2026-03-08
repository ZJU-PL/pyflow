"""Unit tests for dependency_resolver module."""

import unittest
from unittest.mock import Mock, patch
import inspect

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

    def test_extract_functions_private_functions_with_toggle(self):
        """Private top-level functions can be included with include_private."""
        resolver = DependencyResolver(
            strategy="ast_only", verbose=False, include_private=True
        )
        source = """
def public_func():
    return 1

def _private_func():
    return 2
"""
        functions = resolver.extract_functions(source, "pkg/mod.py")
        self.assertIn("public_func", functions)
        self.assertIn("_private_func", functions)

    def test_create_safe_exec_globals(self):
        """Test creating safe execution globals."""
        globals_dict = self.resolver._create_safe_exec_globals()
        self.assertIsInstance(globals_dict, dict)
        # vars(builtins) returns the module dict, not __builtins__
        # Check for common builtin functions instead
        self.assertIn('len', globals_dict)
        self.assertIn('print', globals_dict)
        self.assertIsNot(globals_dict['os'], __import__('os'))

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

    def test_handle_import_errors_makes_import_statement_executable(self):
        """Stubbed modules should be importable during runtime extraction."""
        source = (
            "import nonexistent_module\n"
            "value = nonexistent_module.some_attr()\n"
        )
        exec_globals = self.resolver._create_safe_exec_globals()
        exec_globals = self.resolver._handle_import_errors(source, exec_globals, "example.py")
        compiled = compile(source, "example.py", "exec")
        self.resolver._exec_with_stub_modules(compiled, exec_globals)
        self.assertIn("value", exec_globals)
        self.assertIsNone(exec_globals["value"])

    def test_exec_with_stub_modules_isolates_safe_runtime_modules(self):
        """Safe runtime module stubs should not mutate process-global modules."""
        import os

        real_system = os.system
        exec_globals = self.resolver._create_safe_exec_globals()
        compiled = compile("import os\nvalue = os\nresult = os.system('ignored')\n", "example.py", "exec")
        self.resolver._exec_with_stub_modules(compiled, exec_globals)

        self.assertIsNot(exec_globals["value"], os)
        self.assertEqual(exec_globals["result"], 0)
        self.assertIs(os.system, real_system)

    def test_auto_strategy_is_side_effect_free(self):
        """AUTO should not execute module top-level code."""
        resolver = DependencyResolver(strategy="auto", verbose=False)
        source = "raise RuntimeError('boom')\n\ndef f():\n    return 1\n"
        functions = resolver.extract_functions(source, "example.py")
        self.assertIn("f", functions)

    def test_ast_proxy_has_code_and_signature(self):
        """AST extracted functions should look like callables with code/signature."""
        resolver = DependencyResolver(strategy="ast_only", verbose=False)
        source = "def f(a, /, b=1, *args, c=2, **kwargs):\n    return a\n"
        functions = resolver.extract_functions(source, "example.py")
        f = functions["f"]

        self.assertTrue(callable(f))
        self.assertTrue(hasattr(f, "__code__"))
        self.assertEqual(f.__code__.co_filename, "example.py")
        self.assertEqual(f.__code__.co_firstlineno, 1)

        sig = inspect.signature(f)
        kinds = [p.kind for p in sig.parameters.values()]
        self.assertIn(inspect.Parameter.POSITIONAL_ONLY, kinds)
        self.assertIn(inspect.Parameter.VAR_POSITIONAL, kinds)
        self.assertIn(inspect.Parameter.KEYWORD_ONLY, kinds)
        self.assertIn(inspect.Parameter.VAR_KEYWORD, kinds)

    def test_ast_only_skips_nested_functions(self):
        """AST extraction should return only top-level functions."""
        resolver = DependencyResolver(strategy="ast_only", verbose=False)
        source = "def outer():\n    def inner():\n        return 1\n    return inner()\n"
        functions = resolver.extract_functions(source, "example.py")
        self.assertIn("outer", functions)
        self.assertNotIn("inner", functions)

    def test_class_proxies_preserve_inherited_public_methods(self):
        """Subclass proxies should expose inherited methods via MRO."""
        resolver = DependencyResolver(strategy="ast_only", verbose=False)
        source = (
            "class Base:\n"
            "    def m(self):\n"
            "        return 1\n\n"
            "class Child(Base):\n"
            "    pass\n"
        )
        resolver.extract_functions(source, "example.py")
        child = resolver.get_module_classes("example.py")["Child"]
        methods = resolver.get_public_method_specs(child)
        self.assertIn("m", methods)

    def test_class_proxies_preserve_inherited_methods_for_generic_bases(self):
        """Subscripted bases should resolve to the underlying class in proxy MRO."""
        resolver = DependencyResolver(strategy="ast_only", verbose=False)
        source = (
            "class Base:\n"
            "    def m(self):\n"
            "        return 1\n\n"
            "class Child(Base[int]):\n"
            "    pass\n"
        )
        resolver.extract_functions(source, "example.py")
        child = resolver.get_module_classes("example.py")["Child"]
        methods = resolver.get_public_method_specs(child)
        self.assertIn("m", methods)

    def test_get_module_name_from_path_uses_dotted_name(self):
        """Module naming should preserve package path segments."""
        resolver = DependencyResolver(strategy="ast_only", verbose=False)
        module = resolver._get_module_name_from_path("tests/frontend/sample_module.py")
        self.assertTrue(module.endswith("tests.frontend.sample_module"))

    def test_get_module_name_from_absolute_path_does_not_depend_on_cwd(self):
        """Absolute paths outside the repo should not inherit cwd path segments."""
        resolver = DependencyResolver(strategy="ast_only", verbose=False)
        module = resolver._get_module_name_from_path("/tmp/demo/pkg/mod.py")
        self.assertEqual(module, "mod")

    def test_import_graph_records_edges(self):
        """Resolver should track deterministic module import graph edges."""
        resolver = DependencyResolver(strategy="ast_only", verbose=False)
        source = "import os\nfrom .pkg import mod\n"
        resolver.extract_functions(source, "proj/app/main.py")
        graph = resolver.get_import_graph()
        self.assertIn("proj.app.main", graph)
        self.assertIn("os", graph["proj.app.main"])
        self.assertIn("proj.app.pkg", graph["proj.app.main"])

    def test_source_map_resolution_prefers_in_memory_files(self):
        """Module source lookup should prefer provided source map."""
        resolver = DependencyResolver(
            strategy="ast_only",
            verbose=False,
            source_files={"proj/pkg/util.py": "def f():\n    return 1\n"},
        )
        path = resolver._find_module_source("proj.pkg.util")
        self.assertEqual(path, "proj/pkg/util.py")
        telemetry = resolver.get_telemetry()
        self.assertGreaterEqual(telemetry["source_map_hits"], 1)


if __name__ == "__main__":
    unittest.main()
