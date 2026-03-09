"""Tests for optimization/rewrite.py - AST rewriting utilities."""

import unittest
from pyflow.optimization.rewrite import Rewriter, rewriteTerm, rewrite
from pyflow.language.python import ast


class MockAnnotation:
    """Mock annotation for testing."""

    def __init__(self):
        self.references = None


class MockCode:
    """Mock code object for testing."""

    def __init__(self, descriptive=False):
        self.annotation = MockAnnotation()
        self._descriptive = descriptive

    def replaceChildren(self, visitor):
        return self

    def rewriteChildren(self, visitor):
        return self

    def isCode(self):
        return True

    def isStandardCode(self):
        return True

    def descriptive(self):
        return self._descriptive


class MockCompiler:
    """Mock compiler for testing."""

    pass


class MockProgram:
    """Mock program for testing."""

    def __init__(self):
        self.storeGraph = None


class TestRewriter(unittest.TestCase):
    """Test cases for Rewriter class."""

    def test_init_empty_replacements(self):
        """Test Rewriter initialization with empty replacements."""
        rewriter = Rewriter({})
        self.assertEqual(rewriter.replacements, {})
        self.assertEqual(rewriter.replaced, set())

    def test_init_with_replacements(self):
        """Test Rewriter initialization with replacements."""
        replacements = {"key": "value"}
        rewriter = Rewriter(replacements)
        self.assertEqual(rewriter.replacements, replacements)

    def test_replaced_set_starts_empty(self):
        """Test that replaced set is empty initially."""
        rewriter = Rewriter({})
        self.assertEqual(len(rewriter.replaced), 0)

    def test_visitLeaf_no_replacement(self):
        """Test that leaf without replacement returns unchanged."""
        rewriter = Rewriter({})
        node = ast.Local("x")
        result = rewriter.visitLeaf(node)
        self.assertEqual(result, node)

    def test_visitLeaf_with_replacement(self):
        """Test that leaf with replacement returns replacement."""
        old_node = ast.Local("x")
        new_node = ast.Local("y")
        rewriter = Rewriter({old_node: new_node})
        result = rewriter.visitLeaf(old_node)
        self.assertEqual(result, new_node)

    def test_visitContainer_empty_list(self):
        """Test visitContainer with empty list."""
        rewriter = Rewriter({})
        result = rewriter.visitContainer([])
        self.assertEqual(result, [])

    def test_visitContainer_with_elements(self):
        """Test visitContainer with list elements."""
        rewriter = Rewriter({})
        local_x = ast.Local("x")
        local_y = ast.Local("y")
        result = rewriter.visitContainer([local_x, local_y])
        self.assertEqual(len(result), 2)

    def test_visitContainer_with_tuple(self):
        """Test visitContainer with tuple."""
        rewriter = Rewriter({})
        local_x = ast.Local("x")
        result = rewriter.visitContainer((local_x,))
        self.assertIsInstance(result, tuple)

    def test_rewrite_term_preserves_keyword_tuple_shape(self):
        old_node = ast.Local("x")
        new_node = ast.Local("y")
        call = ast.Call(ast.Local("func"), [], [("name", old_node)], None, None)

        result = rewriteTerm(call, {old_node: new_node})

        self.assertEqual(result.kwds[0][0], "name")
        self.assertIsInstance(result.kwds[0], tuple)
        self.assertIs(result.kwds[0][1], new_node)

    def test_processCode_returns_code(self):
        """Test that processCode returns the code object."""
        rewriter = Rewriter({})
        code = MockCode()
        result = rewriter.processCode(code)
        self.assertEqual(result, code)


class TestRewriteTerm(unittest.TestCase):
    """Test cases for rewriteTerm function."""

    def test_empty_replace(self):
        """Test with empty replacement dict."""
        node = ast.Local("x")
        result = rewriteTerm(node, {})
        self.assertEqual(result, node)

    def test_none_replace(self):
        """Test with None replacement dict."""
        node = ast.Local("x")
        result = rewriteTerm(node, None)
        self.assertEqual(result, node)

    def test_with_replacement(self):
        """Test with actual replacement."""
        old_node = ast.Local("x")
        new_node = ast.Local("y")
        result = rewriteTerm(old_node, {old_node: new_node})
        self.assertEqual(result, new_node)


class TestRewrite(unittest.TestCase):
    """Test cases for rewrite function."""

    def test_empty_replace(self):
        """Test with empty replacement dict."""
        code = MockCode()
        result = rewrite(MockCompiler(), code, {})
        self.assertEqual(result, code)

    def test_none_replace(self):
        """Test with None replacement dict."""
        code = MockCode()
        result = rewrite(MockCompiler(), code, None)
        self.assertEqual(result, code)

    def test_with_replacement(self):
        """Test with actual replacement."""
        code = MockCode()
        old_node = ast.Local("x")
        new_node = ast.Local("y")
        result = rewrite(MockCompiler(), code, {old_node: new_node})
        self.assertEqual(result, code)


if __name__ == "__main__":
    unittest.main()
