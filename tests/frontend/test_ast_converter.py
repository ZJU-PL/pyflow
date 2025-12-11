"""Unit tests for ast_converter module."""

import unittest
import ast as python_ast
from unittest.mock import Mock, patch

from pyflow.frontend.ast_converter import ASTConverter
from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.program import Object


class TestASTConverter(unittest.TestCase):
    """Test cases for the ASTConverter class."""

    def setUp(self):
        """Set up test fixtures."""
        self.converter = ASTConverter(verbose=False)

    def test_init(self):
        """Test ASTConverter initialization."""
        converter = ASTConverter(verbose=True)
        self.assertTrue(converter.verbose)

    def test_convert_python_ast_to_pyflow_empty(self):
        """Test converting empty Python AST."""
        suite = self.converter.convert_python_ast_to_pyflow([])
        self.assertIsInstance(suite, pyflow_ast.Suite)
        self.assertEqual(len(suite.blocks), 0)

    def test_convert_return_statement(self):
        """Test converting return statement."""
        source = "return 42"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Return)
        self.assertEqual(len(result.exprs), 1)

    def test_convert_return_statement_no_value(self):
        """Test converting return statement without value."""
        source = "return"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Return)
        self.assertEqual(len(result.exprs), 0)

    def test_convert_assign_statement(self):
        """Test converting assignment statement."""
        source = "x = 42"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Assign)

    def test_convert_assign_multiple_targets(self):
        """Test converting assignment with multiple targets."""
        source = "x = y = 42"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Assign)
        self.assertEqual(len(result.lcls), 2)

    def test_convert_augassign(self):
        """Test converting augmented assignment."""
        source = "x += 1"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Assign)

    def test_convert_if_statement(self):
        """Test converting if statement."""
        source = """
if x > 0:
    return x
else:
    return -x
"""
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Switch)

    def test_convert_for_loop(self):
        """Test converting for loop."""
        source = """
for i in range(10):
    print(i)
"""
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.For)

    def test_convert_while_loop(self):
        """Test converting while loop."""
        source = """
while x > 0:
    x -= 1
"""
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.While)

    def test_convert_break_statement(self):
        """Test converting break statement."""
        source = "break"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Break)

    def test_convert_continue_statement(self):
        """Test converting continue statement."""
        source = "continue"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Continue)

    def test_convert_pass_statement(self):
        """Test converting pass statement."""
        source = "pass"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Suite)

    def test_convert_expression_statement(self):
        """Test converting expression statement."""
        source = "print('hello')"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Discard)

    def test_convert_name_expression(self):
        """Test converting name expression."""
        source = "x"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.Local)

    def test_convert_constant_expression(self):
        """Test converting constant expression."""
        source = "42"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.Existing)

    def test_convert_string_constant(self):
        """Test converting string constant."""
        source = "'hello'"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.Existing)

    def test_convert_call_expression(self):
        """Test converting function call expression."""
        source = "func(1, 2, 3)"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.Call)

    def test_convert_call_with_keywords(self):
        """Test converting function call with keywords."""
        source = "func(a=1, b=2)"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.Call)

    def test_convert_binop_expression(self):
        """Test converting binary operation."""
        source = "a + b"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.Call)

    def test_convert_compare_expression(self):
        """Test converting comparison expression."""
        source = "a == b"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, (pyflow_ast.Call, pyflow_ast.Existing))

    def test_convert_subscript_expression(self):
        """Test converting subscript expression."""
        source = "arr[0]"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.Call)

    def test_convert_attribute_expression(self):
        """Test converting attribute expression."""
        source = "obj.attr"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.GetAttr)

    def test_convert_list_expression(self):
        """Test converting list expression."""
        source = "[1, 2, 3]"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.BuildList)

    def test_convert_tuple_expression(self):
        """Test converting tuple expression."""
        source = "(1, 2, 3)"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.BuildTuple)

    def test_convert_dict_expression(self):
        """Test converting dict expression."""
        source = "{'a': 1, 'b': 2}"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.BuildMap)

    def test_convert_lambda_expression(self):
        """Test converting lambda expression."""
        source = "lambda x: x + 1"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.MakeFunction)

    def test_convert_try_except(self):
        """Test converting try-except block."""
        source = """
try:
    x = 1 / 0
except ZeroDivisionError:
    x = 0
"""
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.TryExceptFinally)

    def test_convert_try_except_finally(self):
        """Test converting try-except-finally block."""
        # Use a specific exception type to avoid None type issues
        source = """
try:
    x = 1
except ValueError:
    x = 0
finally:
    pass
"""
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.TryExceptFinally)

    def test_convert_raise_statement(self):
        """Test converting raise statement."""
        source = "raise ValueError('error')"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Raise)

    def test_convert_assert_statement(self):
        """Test converting assert statement."""
        source = "assert x > 0"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Assert)

    def test_convert_global_statement(self):
        """Test converting global statement."""
        source = "global x"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Discard)

    def test_convert_nonlocal_statement(self):
        """Test converting nonlocal statement."""
        source = "nonlocal x"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Discard)

    def test_convert_with_statement(self):
        """Test converting with statement."""
        source = """
with open('file.txt') as f:
    content = f.read()
"""
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        # Should return a Suite (body of with statement)
        self.assertIsNotNone(result)

    def test_convert_import_statement(self):
        """Test converting import statement."""
        source = "import math"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Discard)

    def test_convert_import_from_statement(self):
        """Test converting from-import statement."""
        source = "from math import sqrt"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Discard)

    def test_convert_function_def(self):
        """Test converting function definition."""
        source = """
def test_func(x):
    return x + 1
"""
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.FunctionDef)

    def test_convert_class_def(self):
        """Test converting class definition."""
        source = """
class TestClass:
    def method(self):
        pass
"""
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.ClassDef)

    def test_convert_expression_safe_none(self):
        """Test convert_expression_safe with None result."""
        # Create a mock node that returns None
        mock_node = Mock()
        with patch.object(self.converter, '_convert_expression', return_value=None):
            result = self.converter._convert_expression_safe(mock_node)
            self.assertIsInstance(result, pyflow_ast.Existing)

    def test_convert_function_args(self):
        """Test converting function arguments."""
        source = "def func(a, b, c=10): pass"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        codeparams = self.converter._convert_function_args(func_node.args)
        self.assertIsInstance(codeparams, pyflow_ast.CodeParameters)
        self.assertEqual(len(codeparams.params), 3)

    def test_convert_function_args_with_vararg(self):
        """Test converting function arguments with *args."""
        source = "def func(*args): pass"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        codeparams = self.converter._convert_function_args(func_node.args)
        self.assertIsNotNone(codeparams.vparam)

    def test_convert_function_args_with_kwarg(self):
        """Test converting function arguments with **kwargs."""
        source = "def func(**kwargs): pass"
        tree = python_ast.parse(source)
        func_node = tree.body[0]
        
        codeparams = self.converter._convert_function_args(func_node.args)
        self.assertIsNotNone(codeparams.kparam)

    def test_convert_assignment_target_name(self):
        """Test converting assignment target (name)."""
        source = "x = 1"
        tree = python_ast.parse(source)
        node = tree.body[0]
        target = node.targets[0]
        
        result = self.converter._convert_assignment_target(target)
        self.assertIsInstance(result, pyflow_ast.Local)

    def test_convert_assignment_target_attribute(self):
        """Test converting assignment target (attribute)."""
        source = "obj.attr = 1"
        tree = python_ast.parse(source)
        node = tree.body[0]
        target = node.targets[0]
        
        result = self.converter._convert_assignment_target(target)
        self.assertIsInstance(result, pyflow_ast.Local)

    def test_convert_assignment_target_subscript(self):
        """Test converting assignment target (subscript)."""
        source = "arr[0] = 1"
        tree = python_ast.parse(source)
        node = tree.body[0]
        target = node.targets[0]
        
        result = self.converter._convert_assignment_target(target)
        self.assertIsInstance(result, pyflow_ast.Local)


if __name__ == "__main__":
    unittest.main()
