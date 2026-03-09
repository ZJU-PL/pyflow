"""Tests for optimization/fold.py - Constant folding optimization."""

import unittest

from pyflow.optimization.fold import (
    FoldRewrite,
    FoldTraverse,
    makeCallRewrite,
)
from pyflow.language.python import ast
from pyflow.language.python import program


class MockExtractor:
    """Mock extractor for testing."""

    def __init__(self):
        self.objects = {}

    def getObject(self, pyobj):
        if pyobj not in self.objects:
            self.objects[pyobj] = program.Object(pyobj)
        return self.objects[pyobj]


class MockAnnotation:
    """Mock annotation for testing."""

    def __init__(self, descriptive=False, has_contexts=False):
        self.descriptive = descriptive
        self.contexts = ["context1", "context2"] if has_contexts else None


class MockCode:
    """Mock code object for testing."""

    def __init__(self, descriptive=False):
        self.annotation = MockAnnotation(descriptive)


class MockStoreGraph:
    """Mock store graph for testing."""

    def __init__(self):
        pass

    def canonical(self):
        pass


class TestFoldRewrite(unittest.TestCase):
    """Test cases for FoldRewrite class."""

    def test_init(self):
        """Test FoldRewrite initialization."""
        extractor = MockExtractor()
        code = MockCode()
        
        fr = FoldRewrite(extractor, None, code)
        
        self.assertEqual(fr.extractor, extractor)
        self.assertEqual(fr.code, code)
        self.assertIsNone(fr.storeGraph)
        self.assertEqual(len(fr.created), 0)

    def test_init_with_storegraph(self):
        """Test FoldRewrite initialization with store graph."""
        extractor = MockExtractor()
        code = MockCode()
        
        sg = MockStoreGraph()
        fr = FoldRewrite(extractor, sg, code)
        
        self.assertEqual(fr.storeGraph, sg)

    def test_init_with_contexts(self):
        """Test FoldRewrite with contexts for annotations."""
        extractor = MockExtractor()
        code = MockCode()
        code.annotation.contexts = ["context1", "context2"]
        
        fr = FoldRewrite(extractor, MockStoreGraph(), code)
        
        self.assertTrue(fr.annotationsExist)

    def test_init_without_contexts(self):
        """Test FoldRewrite without contexts."""
        extractor = MockExtractor()
        code = MockCode()
        code.annotation.contexts = None
        
        fr = FoldRewrite(extractor, None, code)
        
        self.assertFalse(fr.annotationsExist)

    def test_descriptive_true(self):
        """Test descriptive() returns True."""
        code = MockCode(descriptive=True)
        fr = FoldRewrite(MockExtractor(), None, code)
        
        self.assertTrue(fr.descriptive())

    def test_descriptive_false(self):
        """Test descriptive() returns False."""
        code = MockCode(descriptive=False)
        fr = FoldRewrite(MockExtractor(), None, code)
        
        self.assertFalse(fr.descriptive())

    def test_visitOK_returns_node(self):
        """Test that visitOK returns node unchanged."""
        fr = FoldRewrite(MockExtractor(), None, MockCode())
        
        node = ast.Local("x")
        result = fr.visitOK(node)
        self.assertEqual(result, node)


class TestMakeCallRewrite(unittest.TestCase):
    """Test cases for makeCallRewrite function."""

    def test_creates_rewriter(self):
        """Test that makeCallRewrite creates a rewriter."""
        extractor = MockExtractor()
        call_rewrite = makeCallRewrite(extractor)
        self.assertIsNotNone(call_rewrite)


class IdentityStrategy:
    def __call__(self, node):
        return node


class TestFoldTraverse(unittest.TestCase):
    def test_visit_list_preserves_keyword_tuples(self):
        traverse = FoldTraverse(IdentityStrategy(), MockCode())
        value = ast.Local("value")

        result = traverse.visitList([("name", value), "sentinel"])

        self.assertEqual(result[0][0], "name")
        self.assertIs(result[0][1], value)
        self.assertEqual(result[1], "sentinel")


if __name__ == "__main__":
    unittest.main()
