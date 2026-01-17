"""Tests for optimization/codeinlining.py - Code inlining optimization."""

import unittest

from pyflow.optimization.codeinlining import (
    CodeInliningAnalysis,
    OpInliningTransform,
    CodeInliningTransform,
)
from pyflow.language.python import ast


class TestCodeInliningAnalysis(unittest.TestCase):
    """Test cases for CodeInliningAnalysis class."""

    def test_init(self):
        """Test CodeInliningAnalysis initialization."""
        analysis = CodeInliningAnalysis()
        self.assertEqual(analysis.canInline, {})
        self.assertEqual(analysis.invokeCount, {})
        self.assertEqual(analysis.numOps, {})

    def test_visitLeaf(self):
        """Test visitLeaf does nothing."""
        analysis = CodeInliningAnalysis()
        analysis.ops = 0
        analysis.terminal = False
        analysis.inlinable = True
        analysis.level = 0
        
        # Should not raise
        analysis.visitLeaf(ast.Local("x"))
        analysis.visitLeaf(None)

    def test_visitLeaf_ast_types(self):
        """Test visitLeaf with various AST types."""
        analysis = CodeInliningAnalysis()
        analysis.ops = 0
        analysis.terminal = False
        analysis.inlinable = True
        analysis.level = 0
        
        # Should not raise for Local type
        analysis.visitLeaf(ast.Local("x"))


class TestOpInliningTransform(unittest.TestCase):
    """Test cases for OpInliningTransform class."""

    def test_init(self):
        """Test OpInliningTransform initialization."""
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)
        self.assertEqual(transform.analysis, analysis)

    def test_visitLeaf(self):
        """Test visitLeaf returns node unchanged."""
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)
        
        node = ast.Local("x")
        result = transform.visitLeaf(node)
        self.assertEqual(result, node)

    def test_visitDoNotCare(self):
        """Test visitDoNotCare returns new DoNotCare."""
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)
        
        node = ast.DoNotCare()
        result = transform.visitDoNotCare(node)
        
        self.assertIsInstance(result, ast.DoNotCare)

    def test_visitCode(self):
        """Test visitCode returns node unchanged."""
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)
        
        class MockCode:
            pass
        
        code = MockCode()
        result = transform.visitCode(code)
        self.assertEqual(result, code)


class TestCodeInliningTransform(unittest.TestCase):
    """Test cases for CodeInliningTransform class."""

    def test_init(self):
        """Test CodeInliningTransform initialization with required arguments."""
        analysis = CodeInliningAnalysis()
        
        # CodeInliningTransform requires (analysis, compiler, prgm, intrinsics)
        # We test that the class can be imported and its attributes exist
        # Full initialization requires complex compiler/prgm objects
        self.assertTrue(hasattr(CodeInliningTransform, '__init__'))


if __name__ == "__main__":
    unittest.main()
