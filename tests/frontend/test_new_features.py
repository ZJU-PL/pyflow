"""Tests for new Python features in ast_converter."""

import unittest
import ast as python_ast
import sys

from pyflow.frontend.ast_converter import ASTConverter
from pyflow.language.python import ast as pyflow_ast


class TestAsyncAwait(unittest.TestCase):
    """Test async/await support (Python 3.5+)."""

    def setUp(self):
        self.converter = ASTConverter(verbose=False)

    def test_convert_await(self):
        """Test converting await expression."""
        source = "await coro"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.Await)

    def test_convert_async_function_def(self):
        """Test converting async function definition."""
        source = """
async def fetch():
    return await coro
"""
        tree = python_ast.parse(source)
        result = self.converter.convert_python_ast_to_pyflow(tree.body)
        self.assertIsInstance(result, pyflow_ast.Suite)

    def test_convert_async_for(self):
        """Test converting async for loop."""
        source = """
async def process():
    async for item in async_iter:
        pass
"""
        tree = python_ast.parse(source)
        result = self.converter.convert_python_ast_to_pyflow(tree.body)
        self.assertIsInstance(result, pyflow_ast.Suite)

    def test_convert_async_with(self):
        """Test converting async with statement."""
        source = """
async def process():
    async with async_cm() as f:
        pass
"""
        tree = python_ast.parse(source)
        result = self.converter.convert_python_ast_to_pyflow(tree.body)
        self.assertIsInstance(result, pyflow_ast.Suite)


class TestWalrusOperator(unittest.TestCase):
    """Test walrus operator support (Python 3.8+)."""

    def setUp(self):
        self.converter = ASTConverter(verbose=False)

    @unittest.skipIf(sys.version_info < (3, 8), "Requires Python 3.8+")
    def test_convert_walrus_simple(self):
        """Test converting simple walrus operator."""
        source = "(x := 5)"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.NamedExpr)

    @unittest.skipIf(sys.version_info < (3, 8), "Requires Python 3.8+")
    def test_convert_walrus_in_while(self):
        """Test converting walrus operator in while condition."""
        source = """
while (line := f.readline()):
    pass
"""
        tree = python_ast.parse(source)
        result = self.converter.convert_python_ast_to_pyflow(tree.body)
        self.assertIsInstance(result, pyflow_ast.Suite)


class TestPatternMatching(unittest.TestCase):
    """Test pattern matching support (Python 3.10+)."""

    def setUp(self):
        self.converter = ASTConverter(verbose=False)

    @unittest.skipIf(sys.version_info < (3, 10), "Requires Python 3.10+")
    def test_convert_match_simple(self):
        """Test converting simple match statement."""
        source = """
match x:
    case 1:
        pass
    case _:
        pass
"""
        tree = python_ast.parse(source)
        result = self.converter.convert_python_ast_to_pyflow(tree.body)
        self.assertIsInstance(result, pyflow_ast.Suite)

    @unittest.skipIf(sys.version_info < (3, 10), "Requires Python 3.10+")
    def test_convert_match_with_guard(self):
        """Test converting match with guard."""
        source = """
match x:
    case n if n > 0:
        pass
"""
        tree = python_ast.parse(source)
        result = self.converter.convert_python_ast_to_pyflow(tree.body)
        self.assertIsInstance(result, pyflow_ast.Suite)


class TestTypeAnnotations(unittest.TestCase):
    """Test type annotation support."""

    def setUp(self):
        self.converter = ASTConverter(verbose=False)

    def test_convert_annassign_with_value(self):
        """Test converting annotated assignment with value."""
        source = "x: int = 5"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.AnnAssign)

    def test_convert_annassign_no_value(self):
        """Test converting annotation-only (no value)."""
        source = "x: int"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.AnnAssign)


class TestGlobalNonlocal(unittest.TestCase):
    """Test improved global/nonlocal handling."""

    def setUp(self):
        self.converter = ASTConverter(verbose=False)

    def test_convert_global_returns_suite(self):
        """Test that global returns a Suite with GlobalDecl nodes."""
        source = "global x, y"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Suite)

    def test_convert_nonlocal_returns_suite(self):
        """Test that nonlocal returns a Suite with NonlocalDecl nodes."""
        source = "nonlocal x, y"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Suite)


class TestComprehensions(unittest.TestCase):
    """Test comprehension handling."""

    def setUp(self):
        self.converter = ASTConverter(verbose=False)

    def test_list_comp_returns_suite(self):
        """Test that list comprehension returns an expression node (Call).

        Bug #15 fix: comprehensions appear in expression position so the
        converter must return an Expression, not a Suite.  The result is now
        a Call to the synthetic helper ``interpreter_comprehension`` whose
        single argument is a NamedExpr that initialises the accumulator.
        """
        source = "[x for x in range(10)]"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body

        result = self.converter._convert_expression(node)
        # Must be an expression node (Call), not a Suite.
        self.assertIsInstance(result, pyflow_ast.Call)
        # The call must reference the synthetic comprehension helper.
        self.assertIsInstance(result.expr, pyflow_ast.Existing)
        self.assertEqual(result.expr.object.pyobj, "interpreter_comprehension")
        # The single argument must be a NamedExpr (accumulator initialisation).
        self.assertEqual(len(result.args), 1)
        self.assertIsInstance(result.args[0], pyflow_ast.NamedExpr)

    def test_gen_exp_not_none(self):
        """Test that generator expression returns MakeFunction (a generator function)."""
        source = "(x for x in range(10))"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.MakeFunction)


if __name__ == "__main__":
    unittest.main()