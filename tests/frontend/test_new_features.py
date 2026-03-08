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
    """Test walrus operator support (Python 3.10+)."""

    def setUp(self):
        self.converter = ASTConverter(verbose=False)

    @unittest.skipIf(sys.version_info < (3, 10), "Requires Python 3.10+")
    def test_convert_walrus_simple(self):
        """Test converting simple walrus operator."""
        source = "(x := 5)"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.NamedExpr)

    @unittest.skipIf(sys.version_info < (3, 10), "Requires Python 3.10+")
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
        """List comprehension should lower to callable expression IR."""
        source = "[x for x in range(10)]"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body

        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.Call)
        self.assertIsInstance(result.expr, pyflow_ast.MakeFunction)
        self.assertEqual(len(result.args), 0)

    def test_gen_exp_not_none(self):
        """Test that generator expression returns MakeFunction (a generator function)."""
        source = "(x for x in range(10))"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.MakeFunction)

    def test_set_comp_uses_set_builder(self):
        """Set comprehensions should initialize a set and add into it."""
        source = "{x for x in range(10)}"
        tree = python_ast.parse(source, mode="eval")
        result = self.converter._convert_expression(tree.body)

        self.assertIsInstance(result, pyflow_ast.Call)
        self.assertIsInstance(result.expr, pyflow_ast.MakeFunction)
        code_ast = result.expr.code.ast
        self.assertIsInstance(code_ast.blocks[0].expr, pyflow_ast.BuildSet)

    def test_dict_comp_uses_map_builder(self):
        """Dict comprehensions should initialize a map and lower to setitem calls."""
        source = "{k: v for k, v in items}"
        tree = python_ast.parse(source, mode="eval")
        result = self.converter._convert_expression(tree.body)

        self.assertIsInstance(result, pyflow_ast.Call)
        self.assertIsInstance(result.expr, pyflow_ast.MakeFunction)
        code_ast = result.expr.code.ast
        self.assertIsInstance(code_ast.blocks[0].expr, pyflow_ast.BuildMap)


class TestContextManagers(unittest.TestCase):
    """Test context manager lowering."""

    def setUp(self):
        self.converter = ASTConverter(verbose=False)

    def test_convert_with_keeps_enter_preamble(self):
        """with statements should retain enter/binding operations in try body."""
        source = """
with cm() as value:
    body()
"""
        tree = python_ast.parse(source)
        result = self.converter._convert_node(tree.body[0])

        self.assertIsInstance(result, pyflow_ast.Suite)
        self.assertIsInstance(result.blocks[0], pyflow_ast.TryExceptFinally)
        outer = result.blocks[0]
        self.assertGreater(len(outer.body.blocks), 2)
        self.assertEqual(len(outer.handlers), 1)
        self.assertTrue(outer.else_.blocks)
        self.assertIsNone(outer.finally_)

    def test_convert_async_with_awaits_aenter(self):
        """async with should await __aenter__ before binding the result."""
        source = """
async with cm() as value:
    body()
"""
        tree = python_ast.parse(source)
        result = self.converter._convert_node(tree.body[0])

        self.assertIsInstance(result, pyflow_ast.Suite)
        outer = result.blocks[0]
        self.assertIsInstance(outer, pyflow_ast.TryExceptFinally)
        awaited_assigns = [
            block
            for block in outer.body.blocks
            if isinstance(block, pyflow_ast.Assign)
            and isinstance(block.expr, pyflow_ast.Await)
        ]
        self.assertTrue(awaited_assigns)
        self.assertEqual(len(outer.handlers), 1)
        self.assertTrue(outer.else_.blocks)

    def test_multi_with_lowers_as_nested_contexts(self):
        """Multiple context managers should lower as nested with blocks."""
        source = """
with a() as x, b() as y:
    body()
"""
        tree = python_ast.parse(source)
        result = self.converter._convert_node(tree.body[0])

        self.assertIsInstance(result, pyflow_ast.Suite)
        outer = result.blocks[0]
        self.assertIsInstance(outer, pyflow_ast.TryExceptFinally)
        inner = outer.body.blocks[-1]
        self.assertIsInstance(inner, pyflow_ast.TryExceptFinally)

    def test_with_handler_uses_exception_details(self):
        """Exceptional exit path should pass exception details, not all None."""
        source = """
with cm():
    body()
"""
        tree = python_ast.parse(source)
        result = self.converter._convert_node(tree.body[0])

        handler = result.blocks[0].handlers[0]
        switch = handler.body.blocks[0]
        self.assertIsInstance(switch, pyflow_ast.Switch)
        assign = switch.t.blocks[0]
        self.assertIsInstance(assign, pyflow_ast.Assign)
        self.assertIsInstance(assign.expr, pyflow_ast.Call)
        self.assertEqual(assign.expr.expr.object.pyobj, "interpreter_exit")
        self.assertIsInstance(assign.expr.args[1], pyflow_ast.Call)
        self.assertEqual(assign.expr.args[1].expr.object.pyobj, "interpreter_exception_type")

    @unittest.skipIf(sys.version_info < (3, 10), "Requires Python 3.10+")
    def test_or_pattern_preserves_branch_bindings(self):
        """OR-pattern bindings should be materialized before the case body."""
        source = """
match x:
    case [1 as y] | [2 as y]:
        z = y
"""
        tree = python_ast.parse(source)
        result = self.converter._convert_node(tree.body[0])

        self.assertIsInstance(result, pyflow_ast.Suite)
        match_switch = result.blocks[1]
        self.assertIsInstance(match_switch, pyflow_ast.Switch)
        binding_switches = [
            block for block in match_switch.t.blocks if isinstance(block, pyflow_ast.Switch)
        ]
        self.assertTrue(binding_switches)


if __name__ == "__main__":
    unittest.main()
