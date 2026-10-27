"""Regression tests for CFG-to-Dataflow IR conversion."""

import ast as python_ast
import sys
import unittest

from pyflow.application.context import CompilerContext
from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.frontend.extractor import Extractor
from pyflow.ir.dataflow.convert import evaluateCode
from pyflow.ir.ddg.construction import construct_ddg


class TestDataflowConversionRegressions(unittest.TestCase):
    def setUp(self):
        self.compiler = CompilerContext(None)
        self.compiler.extractor = Extractor(self.compiler)

    def _convert(self, source: str):
        py_node = python_ast.parse(source).body[0]
        code = ASTConverter()._convert_function_def(py_node).code
        dataflow = evaluateCode(self.compiler, code)
        return code, dataflow

    def test_convert_attribute_and_subscript_modifications(self):
        source = """
def mutate(obj, d, key, val):
    obj.field = val
    d[key] = val
    assert val is not None
    del d[key]
    del obj.field
    del val
    return d
"""
        code, dataflow = self._convert(source)
        self.assertIsNotNone(dataflow)
        ddg = construct_ddg(dataflow)
        self.assertIsNotNone(ddg)

    def test_convert_unpack_sequence_and_slice_mutations(self):
        source = """
def mutate_slices(items, val):
    items[0:2] = val
    del items[0:1]
    return items
"""
        code, dataflow = self._convert(source)
        self.assertIsNotNone(dataflow)
        ddg = construct_ddg(dataflow)
        self.assertIsNotNone(ddg)

    @unittest.skipIf(sys.version_info < (3, 12), "PEP 695 type alias syntax requires Python 3.12")
    def test_convert_scope_declarations_and_type_alias(self):
        source = """
def declarations(x):
    global g
    nonlocal n
    type T = int
    return x
"""
        code, dataflow = self._convert(source)
        self.assertIsNotNone(dataflow)
        ddg = construct_ddg(dataflow)
        self.assertIsNotNone(ddg)


if __name__ == "__main__":
    unittest.main()
