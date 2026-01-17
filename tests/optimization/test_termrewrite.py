"""Tests for optimization/termrewrite.py - Term rewriting utilities."""

import unittest

from pyflow.optimization import termrewrite
from pyflow.language.python import ast
from pyflow.language.python import program


class MockAnnotation:
    """Mock annotation for testing."""

    def __init__(self, references=None):
        self.references = references


class TestHasNumArgs(unittest.TestCase):
    """Test cases for hasNumArgs function."""

    def test_exact_args(self):
        """Test with exact number of arguments."""
        node = ast.Call(ast.Local("func"), [], [], None, None)
        node.annotation = MockAnnotation()
        result = termrewrite.hasNumArgs(node, 0)
        self.assertTrue(result)

    def test_too_few_args(self):
        """Test with fewer arguments than expected."""
        node = ast.Call(ast.Local("func"), [], [], None, None)
        node.annotation = MockAnnotation()
        result = termrewrite.hasNumArgs(node, 2)
        self.assertFalse(result)

    def test_too_many_args(self):
        """Test with more arguments than expected."""
        node = ast.Call(ast.Local("func"), [ast.Local("a"), ast.Local("b")], [], None, None)
        node.annotation = MockAnnotation()
        result = termrewrite.hasNumArgs(node, 1)
        self.assertFalse(result)


class TestIsSimpleCall(unittest.TestCase):
    """Test cases for isSimpleCall function."""

    def test_simple_call(self):
        """Test a simple call without keywords or *args."""
        node = ast.Call(ast.Local("func"), [], [], None, None)
        result = termrewrite.isSimpleCall(node)
        self.assertTrue(result)

    def test_with_keywords(self):
        """Test call with keywords is not simple."""
        node = ast.Call(ast.Local("func"), [], [("key", ast.Local("val"))], None, None)
        result = termrewrite.isSimpleCall(node)
        self.assertFalse(result)

    def test_with_vargs(self):
        """Test call with *args is not simple."""
        node = ast.Call(ast.Local("func"), [], [], ast.Local("args"), None)
        result = termrewrite.isSimpleCall(node)
        self.assertFalse(result)

    def test_with_kargs(self):
        """Test call with **kwargs is not simple."""
        node = ast.Call(ast.Local("func"), [], [], None, ast.Local("kwargs"))
        result = termrewrite.isSimpleCall(node)
        self.assertFalse(result)


class TestIsZero(unittest.TestCase):
    """Test cases for isZero function."""

    def test_zero_constant(self):
        """Test with zero constant."""
        obj = program.Object(0)
        node = ast.Existing(obj)
        result = termrewrite.isZero(node)
        self.assertTrue(result)

    def test_nonzero_constant(self):
        """Test with nonzero constant."""
        obj = program.Object(5)
        node = ast.Existing(obj)
        result = termrewrite.isZero(node)
        self.assertFalse(result)

    def test_local_variable(self):
        """Test with local variable."""
        node = ast.Local("x")
        result = termrewrite.isZero(node)
        self.assertFalse(result)


class TestIsOne(unittest.TestCase):
    """Test cases for isOne function."""

    def test_one_constant(self):
        """Test with one constant."""
        obj = program.Object(1)
        node = ast.Existing(obj)
        result = termrewrite.isOne(node)
        self.assertTrue(result)

    def test_nonzero_constant(self):
        """Test with nonzero constant."""
        obj = program.Object(5)
        node = ast.Existing(obj)
        result = termrewrite.isOne(node)
        self.assertFalse(result)

    def test_local_variable(self):
        """Test with local variable."""
        node = ast.Local("x")
        result = termrewrite.isOne(node)
        self.assertFalse(result)


class TestIsNegativeOne(unittest.TestCase):
    """Test cases for isNegativeOne function."""

    def test_negative_one_constant(self):
        """Test with -1 constant."""
        obj = program.Object(-1)
        node = ast.Existing(obj)
        result = termrewrite.isNegativeOne(node)
        self.assertTrue(result)

    def test_nonzero_constant(self):
        """Test with nonzero constant."""
        obj = program.Object(5)
        node = ast.Existing(obj)
        result = termrewrite.isNegativeOne(node)
        self.assertFalse(result)


class TestIsAnalysis(unittest.TestCase):
    """Test cases for isAnalysis function."""

    def test_constant_in_set(self):
        """Test with constant in test set."""
        obj = program.Object(1)
        node = ast.Existing(obj)
        result = termrewrite.isAnalysis(node, {1, 2, 3})
        self.assertTrue(result)

    def test_constant_not_in_set(self):
        """Test with constant not in test set."""
        obj = program.Object(5)
        node = ast.Existing(obj)
        result = termrewrite.isAnalysis(node, {1, 2, 3})
        self.assertFalse(result)

    def test_local_variable(self):
        """Test with local variable."""
        node = ast.Local("x")
        result = termrewrite.isAnalysis(node, {1, 2, 3})
        self.assertFalse(result)


class TestIsAnalysisInstance(unittest.TestCase):
    """Test cases for isAnalysisInstance function."""

    def test_constant_int(self):
        """Test with integer constant."""
        obj = program.Object(5)
        node = ast.Existing(obj)
        result = termrewrite.isAnalysisInstance(node, int)
        self.assertTrue(result)

    def test_constant_wrong_type(self):
        """Test with constant of wrong type."""
        obj = program.Object("hello")
        node = ast.Existing(obj)
        result = termrewrite.isAnalysisInstance(node, int)
        self.assertFalse(result)

    def test_constant_str(self):
        """Test with string constant."""
        obj = program.Object("hello")
        node = ast.Existing(obj)
        result = termrewrite.isAnalysisInstance(node, str)
        self.assertTrue(result)


class TestDirectCallRewriter(unittest.TestCase):
    """Test cases for DirectCallRewriter class."""

    def test_init(self):
        """Test DirectCallRewriter initialization."""
        class MockExtractor:
            pass
        
        rewriter = termrewrite.DirectCallRewriter(MockExtractor())
        self.assertIsNotNone(rewriter)
        self.assertEqual(rewriter.rewrites, {})

    def test_init_with_stubs(self):
        """Test DirectCallRewriter with stubs."""
        class MockStubs:
            exports = {}
        
        class MockExtractor:
            stubs = MockStubs()
        
        rewriter = termrewrite.DirectCallRewriter(MockExtractor())
        self.assertIsNotNone(rewriter)

    def test_add_rewrite(self):
        """Test adding rewrite rules."""
        class MockStubs:
            exports = {}
        
        class MockExtractor:
            stubs = MockStubs()
        
        rewriter = termrewrite.DirectCallRewriter(MockExtractor())
        
        def my_rewrite(self, node):
            return None
        
        rewriter.addRewrite("test_pattern", my_rewrite)
        self.assertTrue(hasattr(rewriter, 'addRewrite'))


class TestTermRewriteUtilities(unittest.TestCase):
    """Test cases for term rewriting utility functions."""

    def test_isZero_callable(self):
        """Test that isZero is callable."""
        self.assertTrue(callable(termrewrite.isZero))

    def test_isOne_callable(self):
        """Test that isOne is callable."""
        self.assertTrue(callable(termrewrite.isOne))

    def test_isNegativeOne_callable(self):
        """Test that isNegativeOne is callable."""
        self.assertTrue(callable(termrewrite.isNegativeOne))

    def test_isAnalysisInstance_callable(self):
        """Test that isAnalysisInstance is callable."""
        self.assertTrue(callable(termrewrite.isAnalysisInstance))


if __name__ == "__main__":
    unittest.main()
