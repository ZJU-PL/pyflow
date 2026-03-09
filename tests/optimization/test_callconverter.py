"""Tests for optimization/callconverter.py."""

import unittest

from pyflow.language.python import ast
from pyflow.optimization.callconverter import ConvertCalls


class MockExtractor:
    def __init__(self):
        self.stubs = type("Stubs", (), {"exports": {}})()


class TestConvertCalls(unittest.TestCase):
    def test_visit_container_preserves_keyword_tuple_shape(self):
        converter = ConvertCalls(MockExtractor(), None)
        value = ast.Local("value")

        result = converter.visitContainer([("name", value)])

        self.assertEqual(result[0][0], "name")
        self.assertIsInstance(result[0], tuple)
        self.assertIs(result[0][1], value)


if __name__ == "__main__":
    unittest.main()
