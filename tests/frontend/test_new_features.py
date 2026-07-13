"""Tests for new Python features in ast_converter."""

import unittest
import ast as python_ast
import sys

from pyflow.frontend.ast_converter import ASTConverter
from pyflow.analysis.ir_utils import code_closure_cells
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

    @unittest.skipIf(sys.version_info < (3, 10), "Requires Python 3.10+")
    def test_class_pattern_uses_match_args_helper(self):
        """Positional class patterns should use __match_args__, not sequence indexing."""
        source = """
match x:
    case Point(a, b):
        pass
"""
        tree = python_ast.parse(source)
        result = self.converter._convert_node(tree.body[0])
        match_switch = result.blocks[1]
        helper_assigns = [
            block
            for block in match_switch.t.blocks
            if isinstance(block, pyflow_ast.Assign)
            and isinstance(block.expr, pyflow_ast.Call)
            and block.expr.expr.object.pyobj == "interpreter_match_class_arg"
        ]
        self.assertEqual(len(helper_assigns), 2)


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
        self.assertIsInstance(result, pyflow_ast.Suite)
        self.assertIsInstance(result.blocks[0], pyflow_ast.Assign)
        self.assertIsInstance(result.blocks[1], pyflow_ast.SetSubscript)

    def test_convert_annassign_no_value(self):
        """Test converting annotation-only (no value)."""
        source = "x: int"
        tree = python_ast.parse(source)
        node = tree.body[0]
        
        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Suite)
        self.assertEqual(len(result.blocks), 1)
        self.assertIsInstance(result.blocks[0], pyflow_ast.SetSubscript)

    @unittest.skipIf(not hasattr(python_ast, "TypeAlias"), "Requires Python 3.12+")
    def test_convert_type_alias_emits_marker_and_binding(self):
        """Type aliases should not be silently dropped."""
        source = "type Alias = int"
        tree = python_ast.parse(source)
        node = tree.body[0]

        result = self.converter._convert_node(node)
        self.assertIsInstance(result, pyflow_ast.Suite)
        self.assertIsInstance(result.blocks[0], pyflow_ast.TypeAlias)
        self.assertIsInstance(result.blocks[1], pyflow_ast.Assign)


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

    def test_global_assignment_and_read_lower_to_global_nodes(self):
        """Explicit globals should bind through GetGlobal/SetGlobal."""
        source = """
x = 0
def f():
    global x
    x = 1
    return x
"""
        tree = python_ast.parse(source)
        result = self.converter.convert_python_ast_to_pyflow(tree.body)

        top_level_globals = [
            block
            for stmt in result.blocks
            for block in (stmt.blocks if isinstance(stmt, pyflow_ast.Suite) else [stmt])
            if isinstance(block, pyflow_ast.SetGlobal)
        ]
        self.assertTrue(top_level_globals)
        func_defs = [stmt for stmt in result.blocks if isinstance(stmt, pyflow_ast.FunctionDef)]
        self.assertTrue(func_defs)
        func_def = func_defs[0]
        self.assertTrue(
            any(isinstance(block, pyflow_ast.SetGlobal) for block in func_def.code.ast.blocks)
        )
        self.assertIsInstance(func_def.code.ast.blocks[-1].exprs[0], pyflow_ast.GetGlobal)

    def test_nonlocal_assignment_and_read_share_cell(self):
        """Explicit nonlocals should use shared cell dereferences."""
        source = """
def outer():
    x = 0
    def inner():
        nonlocal x
        x = 1
        return x
"""
        tree = python_ast.parse(source)
        result = self.converter.convert_python_ast_to_pyflow(tree.body)
        outer = result.blocks[0]
        inner_defs = [
            block
            for block in outer.code.ast.blocks
            if isinstance(block, pyflow_ast.FunctionDef)
        ]
        self.assertTrue(inner_defs)
        inner = inner_defs[0]

        outer_cell_writes = [
            block for block in outer.code.ast.blocks if isinstance(block, pyflow_ast.SetCellDeref)
        ]
        inner_cell_writes = [
            block for block in inner.code.ast.blocks if isinstance(block, pyflow_ast.SetCellDeref)
        ]
        self.assertTrue(outer_cell_writes)
        self.assertTrue(inner_cell_writes)
        self.assertIsInstance(inner.code.ast.blocks[-1].exprs[0], pyflow_ast.GetCellDeref)

    def test_implicit_free_variable_is_recorded_as_a_closure_cell(self):
        source = """
def outer():
    value = object()
    def inner():
        return value
    return inner
"""
        tree = python_ast.parse(source)
        result = self.converter.convert_python_ast_to_pyflow(tree.body)
        outer = result.blocks[0]
        inner = next(
            block
            for block in outer.code.ast.blocks
            if isinstance(block, pyflow_ast.FunctionDef)
        )
        self.assertTrue(code_closure_cells(inner.code))
        self.assertTrue(
            any(
                isinstance(block, pyflow_ast.SetCellDeref)
                for block in outer.code.ast.blocks
            )
        )
        self.assertIsInstance(
            inner.code.ast.blocks[-1].exprs[0],
            pyflow_ast.GetCellDeref,
        )


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
        self.assertIsInstance(result, pyflow_ast.DirectCall)
        self.assertIsNotNone(result.code)
        self.assertEqual([arg.name for arg in result.args], ["range"])

    def test_gen_exp_not_none(self):
        """Generator expressions create a deferred generator activation."""
        source = "(x for x in range(10))"
        tree = python_ast.parse(source, mode='eval')
        node = tree.body
        
        result = self.converter._convert_expression(node)
        self.assertIsInstance(result, pyflow_ast.DirectCall)
        self.assertIn("converted_genexpr", result.code.annotation.origin)

    def test_set_comp_uses_set_builder(self):
        """Set comprehensions should initialize a set and add into it."""
        source = "{x for x in range(10)}"
        tree = python_ast.parse(source, mode="eval")
        result = self.converter._convert_expression(tree.body)

        self.assertIsInstance(result, pyflow_ast.DirectCall)
        code_ast = result.code.ast
        self.assertIsInstance(code_ast.blocks[0].expr, pyflow_ast.BuildSet)

    def test_dict_comp_uses_map_builder(self):
        """Dict comprehensions should initialize a map and lower to setitem calls."""
        source = "{k: v for k, v in items}"
        tree = python_ast.parse(source, mode="eval")
        result = self.converter._convert_expression(tree.body)

        self.assertIsInstance(result, pyflow_ast.DirectCall)
        code_ast = result.code.ast
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

    @unittest.skipIf(sys.version_info < (3, 10), "Requires Python 3.10+")
    def test_sequence_star_pattern_uses_min_length_and_slice_binding(self):
        """Starred sequence patterns should use >= length and bind only the middle slice."""
        source = """
match x:
    case [head, *rest, tail]:
        y = rest
"""
        tree = python_ast.parse(source)
        result = self.converter._convert_node(tree.body[0])

        self.assertIsInstance(result, pyflow_ast.Suite)
        match_switch = result.blocks[1]
        self.assertIsInstance(match_switch, pyflow_ast.Switch)
        self.assertIsInstance(match_switch.condition.conditional, pyflow_ast.ShortCircutAnd)

        def _find_len_min_call(node):
            if isinstance(node, pyflow_ast.Call):
                if node.expr.object.pyobj == "interpreter_match_sequence_len_min":
                    return node
                return None
            if isinstance(node, pyflow_ast.ShortCircutAnd):
                for term in node.terms:
                    found = _find_len_min_call(term)
                    if found is not None:
                        return found
            return None

        len_min = _find_len_min_call(match_switch.condition.conditional)
        self.assertIsNotNone(len_min)

        slice_binds = [
            block
            for block in match_switch.t.blocks
            if isinstance(block, pyflow_ast.Assign)
            and block.lcls[0].name == "rest"
        ]
        self.assertTrue(slice_binds)
        rest_value = slice_binds[0].expr.args[0]
        self.assertIsInstance(rest_value, pyflow_ast.Call)
        self.assertEqual(rest_value.expr.object.pyobj, "interpreter_getitem")
        self.assertIsInstance(rest_value.args[1], pyflow_ast.BuildSlice)

    @unittest.skipIf(sys.version_info < (3, 10), "Requires Python 3.10+")
    def test_mapping_rest_pattern_binds_rest_name(self):
        """Mapping patterns with **rest should bind the residual mapping."""
        source = """
match x:
    case {"a": y, **rest}:
        z = rest
"""
        tree = python_ast.parse(source)
        result = self.converter._convert_node(tree.body[0])

        self.assertIsInstance(result, pyflow_ast.Suite)
        match_switch = result.blocks[1]
        self.assertIsInstance(match_switch, pyflow_ast.Switch)
        rest_binds = [
            block
            for block in match_switch.t.blocks
            if isinstance(block, pyflow_ast.Assign) and block.lcls[0].name == "rest"
        ]
        self.assertTrue(rest_binds)
        self.assertIsInstance(rest_binds[0].expr, pyflow_ast.Call)
        self.assertEqual(
            rest_binds[0].expr.expr.object.pyobj, "interpreter_match_mapping_rest"
        )

    @unittest.skipIf(sys.version_info < (3, 11), "Requires Python 3.11+")
    def test_try_star_handlers_keep_original_group_for_residual_raise(self):
        """except* handlers should keep residual exceptional flow explicit."""
        source = """
try:
    body()
except* ValueError as err:
    handle(err)
"""
        tree = python_ast.parse(source)
        result = self.converter._convert_node(tree.body[0])

        self.assertIsInstance(result, pyflow_ast.TryExceptFinally)
        handler = result.handlers[0]
        self.assertEqual(handler.value.name, "__exc_group__")
        self.assertNotIsInstance(handler.body.blocks[-1], pyflow_ast.Raise)


if __name__ == "__main__":
    unittest.main()
