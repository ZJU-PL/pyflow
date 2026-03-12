"""Tests for optimization/simplify.py - Simplification pass."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pyflow.language.python import ast
from pyflow.optimization import simplify


class TestSimplifyModule(unittest.TestCase):
    """Test cases for simplify module."""

    def test_evaluateCode_exists(self):
        """Test that evaluateCode function exists."""
        self.assertTrue(callable(simplify.evaluateCode))

    def test_evaluate_exists(self):
        """Test that evaluate function exists."""
        self.assertTrue(callable(simplify.evaluate))

    def test_evaluateCode_detects_same_size_structural_mutation(self):
        code = ast.Code(
            "f",
            ast.CodeParameters(
                selfparam=ast.Local("self"),
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

        def mutate_params(_compiler, _prgm, node):
            node.codeparameters = ast.CodeParameters(
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
            )

        with patch("pyflow.optimization.simplify.fold.evaluateCode", side_effect=mutate_params):
            with patch("pyflow.optimization.simplify.dce.evaluateCode"):
                changed = simplify.evaluateCode(SimpleNamespace(), None, code)

        self.assertTrue(changed)


if __name__ == "__main__":
    unittest.main()
