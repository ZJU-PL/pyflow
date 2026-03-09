"""Tests for optimization/argumentnormalization.py."""

import unittest

from pyflow.language.python import ast
from pyflow.optimization.argumentnormalization import (
    ArgumentNormalizationAnalysis,
    ArgumentNormalizationTransform,
)


class TestArgumentNormalizationAnalysis(unittest.TestCase):
    def test_visit_call_marks_vargs_usage_inapplicable(self):
        analysis = ArgumentNormalizationAnalysis(None)
        analysis.applicable = True
        analysis.vparam = ast.Local("args")

        node = ast.Call(ast.Local("func"), [], [], analysis.vparam, None)

        analysis.visitCall(node)

        self.assertFalse(analysis.applicable)

    def test_visit_direct_call_marks_vargs_usage_inapplicable(self):
        analysis = ArgumentNormalizationAnalysis(None)
        analysis.applicable = True
        analysis.vparam = ast.Local("args")

        node = ast.DirectCall(None, ast.Local("self"), [], [], analysis.vparam, None)

        analysis.visitDirectCall(node)

        self.assertFalse(analysis.applicable)


class TestArgumentNormalizationTransform(unittest.TestCase):
    def test_visit_container_preserves_keyword_tuple_shape(self):
        transform = ArgumentNormalizationTransform(None)
        value = ast.Local("value")

        result = transform.visitContainer([("name", value)])

        self.assertEqual(result[0][0], "name")
        self.assertIsInstance(result[0], tuple)
        self.assertIs(result[0][1], value)


if __name__ == "__main__":
    unittest.main()
