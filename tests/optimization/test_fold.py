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

    def test_legacy_annotation_contexts_do_not_enable_fact_based_folding(self):
        extractor = MockExtractor()
        code = MockCode()
        code.annotation.contexts = ["context1", "context2"]
        
        fr = FoldRewrite(extractor, MockStoreGraph(), code)
        
        self.assertFalse(fr.annotationsExist)

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

    def test_convert_to_bool_keeps_value_producing_short_circuit_and(self):
        expression = ast.ShortCircutAnd(
            [
                ast.Existing(program.Object(1)),
                ast.Existing(program.Object(2)),
            ]
        )
        conversion = ast.ConvertToBool(expression)
        rewrite = FoldRewrite(MockExtractor(), None, MockCode())

        result = rewrite.visitConvertToBool(conversion)

        self.assertIs(result, conversion)

    def test_getObjects_unsupported_ref_is_conservative(self):
        fr = FoldRewrite(MockExtractor(), None, MockCode())
        self.assertEqual(fr.getObjects(object()), ())

    def test_eliminateDeadArguments_keeps_effectful_selfarg(self):
        fr = FoldRewrite(MockExtractor(), None, MockCode())
        code = ast.Code(
            "callee",
            ast.CodeParameters(
                selfparam=ast.DoNotCare(),
                posonlyparams=(),
                posonlynames=(),
                params=(),
                paramnames=(),
                defaults=(),
                vparam=None,
                kparam=None,
                returnparams=(),
                type_params=None,
            ),
            ast.Suite([]),
        )
        node = ast.DirectCall(
            code,
            ast.Call(ast.Local("callee"), [], [], None, None),
            [],
            [],
            None,
            None,
        )
        node.annotation = MockAnnotation()

        result = fr.eliminateDeadArguments(node)

        self.assertIs(result, node)


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
