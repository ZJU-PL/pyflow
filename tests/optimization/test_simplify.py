"""Tests for optimization/simplify.py - Simplification pass."""

import unittest
from pyflow.optimization import simplify


class TestSimplifyModule(unittest.TestCase):
    """Test cases for simplify module."""

    def test_evaluateCode_exists(self):
        """Test that evaluateCode function exists."""
        self.assertTrue(callable(simplify.evaluateCode))

    def test_evaluate_exists(self):
        """Test that evaluate function exists."""
        self.assertTrue(callable(simplify.evaluate))


if __name__ == "__main__":
    unittest.main()
