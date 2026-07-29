"""Tests for optimization/methodcall.py."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pyflow.language.python import ast
from pyflow.ir.core import ensure_code_indexed
from pyflow.optimization import dataflow
from pyflow.optimization.methodcall import (
    MethodAnalysis,
    MethodPatternFinder,
    MethodRewrite,
    methodMeet,
    opThatInvokes,
)


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
    def test_resolve_invoke_targets_keeps_leaf_target(self):
        finder = MethodPatternFinder()
        finder.invokeLUT = {}

        target = ("callee", "ctx")

        self.assertEqual(finder.resolveInvokeTargets(target), frozenset((target,)))

    def test_build_invoke_lut_skips_codes_without_unique_invocation_op(self):
        class DummyCode:
            pass

        finder = MethodPatternFinder()
        finder.facts = object()
        context = object()
        code = DummyCode()
        code.annotation = SimpleNamespace(contexts=[context])
        finder.mcallsC = {(code, context)}
        finder.icallsC = set()

        with patch("pyflow.optimization.methodcall.opThatInvokes", return_value=None):
            finder.buildInvokeLUT()

        self.assertEqual(finder.invokeLUT, {})


class TestOpThatInvokes(unittest.TestCase):
    class Facts:
        def __init__(self, targets):
            self.targets = targets

        def merged_call_targets(self, _func, op):
            return self.targets.get(op, ())

    def test_returns_none_when_no_invoking_operation_exists(self):
        func = object()
        op = object()
        facts = self.Facts({})

        with patch("pyflow.optimization.methodcall.tools.codeOps", return_value=[op]):
            self.assertIsNone(opThatInvokes(facts, func))

    def test_returns_none_when_multiple_invoking_operations_exist(self):
        func = object()
        op1 = object()
        op2 = object()
        facts = self.Facts({op1: {("a", "ctx")}, op2: {("b", "ctx")}})

        with patch("pyflow.optimization.methodcall.tools.codeOps", return_value=[op1, op2]):
            self.assertIsNone(opThatInvokes(facts, func))


class TestMethodRewrite(unittest.TestCase):
    def test_transfer_op_info_keeps_original_targets_when_lookup_missing(self):
        pattern = MethodPatternFinder()
        pattern.invokeLUT = {}
        rewrite = MethodRewrite(pattern, code=None)

        node = ast.Call(ast.Local("func"), [], [], None, None)
        node.annotation = MockAnnotation()

        rewritten = ast.MethodCall(ast.Local("obj"), ast.Local("name"), [], [], None, None)
        rewrite.transferOpInfo(node, rewritten)

        self.assertIs(rewritten.annotation, node.annotation)


class TestMethodAnalysis(unittest.TestCase):
    @staticmethod
    def indexed_code_for(expr):
        code = ast.Code(
            "test",
            ast.CodeParameters(
                selfparam=None,
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
            ast.Suite([ast.Discard(expr)]),
        )
        ensure_code_indexed(code)
        return code

    def test_delete_kills_tracked_method_binding(self):
        analysis = MethodAnalysis(pattern=None)
        analysis.flow = dataflow.base.FlowDict()

        expr = ast.Local("expr")
        name = ast.Local("name")
        meth = ast.Local("meth")
        key = (expr, name, meth)

        analysis.flow.define(("expr", expr), key)
        analysis.flow.define(("name", name), key)
        analysis.flow.define(("meth", meth), key)

        analysis.visitDelete(ast.Delete(meth))

        self.assertIs(analysis.flow.lookup(("expr", expr)), dataflow.base.undefined)
        self.assertIs(analysis.flow.lookup(("name", name)), dataflow.base.undefined)
        self.assertIs(analysis.flow.lookup(("meth", meth)), dataflow.base.undefined)

    def test_side_effecting_op_invalidates_all_tracked_method_bindings(self):
        expr = ast.Local("expr")
        name = ast.Local("name")
        meth = ast.Local("meth")
        key = (expr, name, meth)
        call = ast.Call(ast.Local("callee"), [], [], None, None)
        analysis = MethodAnalysis(pattern=None, code=self.indexed_code_for(call))
        analysis.flow = dataflow.base.FlowDict()
        analysis.flow.define(("expr", expr), key)
        analysis.flow.define(("name", name), key)
        analysis.flow.define(("meth", meth), key)

        analysis.visitMayLeak(call)

        self.assertIs(analysis.flow.lookup(("expr", expr)), dataflow.base.undefined)
        self.assertIs(analysis.flow.lookup(("name", name)), dataflow.base.undefined)
        self.assertIs(analysis.flow.lookup(("meth", meth)), dataflow.base.undefined)

    def test_non_effecting_op_preserves_method_binding(self):
        expr = ast.Local("expr")
        name = ast.Local("name")
        meth = ast.Local("meth")
        key = (expr, name, meth)
        load = ast.Load(ast.Local("other_obj"), "LowLevel", ast.Local("other_name"))
        analysis = MethodAnalysis(pattern=None, code=self.indexed_code_for(load))
        analysis.flow = dataflow.base.FlowDict()
        analysis.flow.define(("expr", expr), key)
        analysis.flow.define(("name", name), key)
        analysis.flow.define(("meth", meth), key)

        analysis.visitMayLeak(load)

        self.assertEqual(analysis.flow.lookup(("expr", expr)), key)
        self.assertEqual(analysis.flow.lookup(("name", name)), key)
        self.assertEqual(analysis.flow.lookup(("meth", meth)), key)


if __name__ == "__main__":
    unittest.main()
