"""Unit tests for function_extractor module."""

import unittest
import ast as python_ast
from unittest.mock import Mock, patch

from pyflow.frontend.function_extractor import FunctionExtractor
from pyflow.application.program import Program
from pyflow.language.python import ast as pyflow_ast


class TestFunctionExtractor(unittest.TestCase):
    """Test cases for the FunctionExtractor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.extractor = FunctionExtractor(verbose=False)

    def test_init(self):
        """Test FunctionExtractor initialization."""
        extractor = FunctionExtractor(verbose=True)
        self.assertTrue(extractor.verbose)
        self.assertIsNotNone(extractor.ast_converter)

    def test_convert_function_simple(self):
        """Test converting a simple function."""
        def test_func():
            return 1
        
        source = "def test_func(): return 1"
        code = self.extractor.convert_function(test_func, source_code=source)
        self.assertIsInstance(code, pyflow_ast.Code)
        self.assertEqual(code.name, "test_func")

    def test_convert_function_with_parameters(self):
        """Test converting a function with parameters."""
        def test_func(a, b):
            return a + b
        
        source = "def test_func(a, b): return a + b"
        code = self.extractor.convert_function(test_func, source_code=source)
        self.assertIsInstance(code, pyflow_ast.Code)
        self.assertEqual(len(code.codeparameters.params), 2)

    def test_convert_function_with_defaults(self):
        """Test converting a function with default parameters."""
        def test_func(a, b=10):
            return a + b
        
        source = "def test_func(a, b=10): return a + b"
        code = self.extractor.convert_function(test_func, source_code=source)
        self.assertIsInstance(code, pyflow_ast.Code)
        self.assertEqual(len(code.codeparameters.defaults), 1)

    def test_convert_function_with_args_kwargs(self):
        """Test converting a function with *args and **kwargs."""
        def test_func(*args, **kwargs):
            return len(args) + len(kwargs)
        
        source = "def test_func(*args, **kwargs): return len(args) + len(kwargs)"
        code = self.extractor.convert_function(test_func, source_code=source)
        self.assertIsInstance(code, pyflow_ast.Code)
        self.assertIsNotNone(code.codeparameters.vparam)  # *args
        self.assertIsNotNone(code.codeparameters.kparam)  # **kwargs

    def test_convert_function_with_return_statement(self):
        """Test converting a function with return statement."""
        def test_func(x):
            return x * 2
        
        source = "def test_func(x): return x * 2"
        code = self.extractor.convert_function(test_func, source_code=source)
        self.assertIsInstance(code, pyflow_ast.Code)

    def test_convert_function_without_source_code(self):
        """Test converting a function without source code."""
        def test_func():
            return 1
        
        code = self.extractor.convert_function(test_func)
        # Should fall back to inspect.getsource or create minimal code
        self.assertIsNotNone(code)

    def test_convert_function_with_multiple_statements(self):
        """Test converting a function with multiple statements."""
        def test_func(x):
            y = x * 2
            return y
        
        source = """
def test_func(x):
    y = x * 2
    return y
"""
        code = self.extractor.convert_function(test_func, source_code=source)
        self.assertIsInstance(code, pyflow_ast.Code)

    def test_convert_function_with_conditional(self):
        """Test converting a function with conditional."""
        def test_func(x):
            if x > 0:
                return x
            else:
                return -x
        
        source = """
def test_func(x):
    if x > 0:
        return x
    else:
        return -x
"""
        code = self.extractor.convert_function(test_func, source_code=source)
        self.assertIsInstance(code, pyflow_ast.Code)

    def test_convert_function_with_loop(self):
        """Test converting a function with a loop."""
        def test_func(n):
            total = 0
            for i in range(n):
                total += i
            return total
        
        source = """
def test_func(n):
    total = 0
    for i in range(n):
        total += i
    return total
"""
        code = self.extractor.convert_function(test_func, source_code=source)
        self.assertIsInstance(code, pyflow_ast.Code)

    def test_convert_function_error_handling(self):
        """Test error handling in convert_function."""
        def test_func():
            return 1
        
        # Use invalid source code
        source = "invalid syntax here"
        code = self.extractor.convert_function(test_func, source_code=source)
        # Should create minimal code on error
        self.assertIsNotNone(code)
        self.assertIsInstance(code, pyflow_ast.Code)

    def test_create_minimal_code(self):
        """Test creating minimal code."""
        def test_func():
            return 1
        
        code = self.extractor._create_minimal_code(test_func)
        self.assertIsInstance(code, pyflow_ast.Code)
        self.assertEqual(code.name, "test_func")
        self.assertIsNotNone(code.codeparameters)
        self.assertIsNotNone(code.ast)  # Code uses 'ast' not 'body'
        self.assertIsNotNone(code.annotation)

    def test_create_minimal_code_annotation(self):
        """Test that minimal code has correct annotation."""
        def test_func():
            return 1
        
        code = self.extractor._create_minimal_code(test_func)
        annotation = code.annotation
        self.assertIsNotNone(annotation)
        self.assertFalse(annotation.descriptive)
        self.assertFalse(annotation.primitive)
        self.assertFalse(annotation.staticFold)
        self.assertFalse(annotation.dynamicFold)

    def test_extract_function(self):
        """Test extracting a function from AST."""
        source = "def test_func(): return 1"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        program = Program()
        self.extractor.extract_function(func_node, program)
        
        # Should add function to program's liveCode
        self.assertTrue(hasattr(program, 'liveCode'))
        self.assertIsNotNone(program.liveCode)
        self.assertGreater(len(program.liveCode), 0)

    def test_extract_function_without_livecode(self):
        """Test extracting function when program has no liveCode."""
        source = "def test_func(): return 1"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        program = Program()
        # Remove liveCode if it exists
        if hasattr(program, 'liveCode'):
            delattr(program, 'liveCode')
        
        self.extractor.extract_function(func_node, program)
        # Should create liveCode
        self.assertTrue(hasattr(program, 'liveCode'))

    def test_extract_class(self):
        """Test extracting a class from AST."""
        source = """
class TestClass:
    def method(self):
        return 42
"""
        tree = python_ast.parse(source)
        class_node = tree.body[0]
        
        program = Program()
        # Should not raise an exception
        self.extractor.extract_class(class_node, program)

    def test_convert_function_args(self):
        """Test converting function arguments."""
        source = "def test_func(a, b, c=10): pass"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        codeparams = self.extractor._convert_function_args(func_node.args, None)
        self.assertIsInstance(codeparams, pyflow_ast.CodeParameters)
        self.assertEqual(len(codeparams.params), 3)
        self.assertEqual(len(codeparams.defaults), 1)

    def test_convert_function_args_with_vararg(self):
        """Test converting function arguments with *args."""
        source = "def test_func(*args): pass"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        codeparams = self.extractor._convert_function_args(func_node.args, None)
        self.assertIsNotNone(codeparams.vparam)

    def test_convert_function_args_with_kwarg(self):
        """Test converting function arguments with **kwargs."""
        source = "def test_func(**kwargs): pass"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        codeparams = self.extractor._convert_function_args(func_node.args, None)
        self.assertIsNotNone(codeparams.kparam)

    def test_convert_function_args_ensures_returnparams(self):
        """Test that function args always have returnparams."""
        source = "def test_func(): pass"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        codeparams = self.extractor._convert_function_args(func_node.args, None)
        self.assertIsNotNone(codeparams.returnparams)
        self.assertGreater(len(codeparams.returnparams), 0)

    def test_convert_python_function_to_pyflow(self):
        """Test converting Python function to PyFlow AST."""
        source = "def test_func(x): return x + 1"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        def test_func(x):
            return x + 1
        
        code = self.extractor._convert_python_function_to_pyflow(func_node, test_func)
        self.assertIsInstance(code, pyflow_ast.Code)
        self.assertEqual(code.name, "test_func")
        self.assertIsNotNone(code.annotation)

    def test_convert_python_function_to_pyflow_without_func(self):
        """Test converting Python function to PyFlow AST without func object."""
        source = "def test_func(x): return x + 1"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        code = self.extractor._convert_python_function_to_pyflow(func_node, None)
        self.assertIsInstance(code, pyflow_ast.Code)
        self.assertEqual(code.name, "test_func")


if __name__ == "__main__":
    unittest.main()
