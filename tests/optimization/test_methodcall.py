"""Tests for optimization/methodcall.py."""

import unittest

from pyflow.language.asttools.annotation import annotationSet, makeContextualAnnotation
from pyflow.language.python import ast
from pyflow.optimization import dataflow
from pyflow.optimization.methodcall import MethodPatternFinder, MethodRewrite, methodMeet


class MockAnnotation:
    def __init__(self, invokes=None):
        self.invokes = invokes

    def rewrite(self, **kwargs):
        return MockAnnotation(kwargs.get("invokes", self.invokes))


class TestMethodMeet(unittest.TestCase):
    def test_empty_values_returns_top(self):
        self.assertIs(methodMeet([]), dataflow.base.top)

    def test_mismatched_values_returns_top(self):
        self.assertIs(methodMeet([("a",), ("b",)]), dataflow.base.top)

    def test_identical_values_returns_value(self):
        value = ("same",)
        self.assertEqual(methodMeet([value, value]), value)


class TestMethodPatternFinder(unittest.TestCase):
    def test_resolve_invoke_targets_falls_back_to_original_target(self):
        finder = MethodPatternFinder()
        finder.invokeLUT = {}

        target = ("callee", "ctx")

        self.assertEqual(finder.resolveInvokeTargets(target), annotationSet((target,)))


class TestMethodRewrite(unittest.TestCase):
    def test_transfer_op_info_keeps_original_targets_when_lookup_missing(self):
        pattern = MethodPatternFinder()
        pattern.invokeLUT = {}
        rewrite = MethodRewrite(pattern)

        node = ast.Call(ast.Local("func"), [], [], None, None)
        target = ("callee", "ctx")
        node.annotation = MockAnnotation(invokes=((), [annotationSet((target,))]))

        rewritten = ast.MethodCall(ast.Local("obj"), ast.Local("name"), [], [], None, None)
        rewrite.transferOpInfo(node, rewritten)

        expected = makeContextualAnnotation([annotationSet((target,))])
        self.assertEqual(rewritten.annotation.invokes, expected)


if __name__ == "__main__":
    unittest.main()
