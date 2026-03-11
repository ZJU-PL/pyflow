"""Regression tests for optimization dataflow traversers."""

import unittest

from pyflow.language.python import ast
from pyflow.optimization.dataflow import base, forward, reverse


def union_meet(values):
    merged = set()
    for value in values:
        merged.update(value)
    return frozenset(merged)


class RecordingAnalyze(object):
    def __init__(self):
        self.seen = []

    def __call__(self, node):
        self.seen.append(type(node).__name__)


class IdentityRewrite(object):
    def __call__(self, node):
        return node


class RecordingStrategy(object):
    def __init__(self):
        self.flow = None
        self.snapshots = []

    def __call__(self, node):
        current = None
        if self.flow._current is not None:
            current = self.flow.lookup("live")
        self.snapshots.append((type(node).__name__, current))
        return node

    def marker(self, node):
        self.snapshots.append(("marker", type(node).__name__))


class TestForwardDataflow(unittest.TestCase):
    def make_traverse(self, analyze=None):
        analyze = analyze or RecordingAnalyze()
        traverse = forward.ForwardFlowTraverse(union_meet, analyze, IdentityRewrite())
        return traverse, analyze

    def test_short_circuit_and_is_traversed(self):
        traverse, analyze = self.make_traverse()

        result = traverse(ast.ShortCircutAnd([ast.Local("a"), ast.Local("b")]))

        self.assertIsInstance(result, ast.ShortCircutAnd)
        self.assertEqual(analyze.seen, ["Local", "Local"])
        self.assertIsNotNone(traverse.flow._current)

    def test_call_children_are_visited_and_kwds_shape_is_preserved(self):
        traverse, analyze = self.make_traverse()
        node = ast.Call(
            ast.Local("func"),
            [ast.Local("arg")],
            [("kw", ast.Local("kw"))],
            ast.Local("varg"),
            ast.Local("karg"),
        )

        result = traverse(node)

        self.assertIsInstance(result, ast.Call)
        self.assertEqual(
            analyze.seen,
            ["Local", "Local", "Local", "Local", "Local", "Call"],
        )
        self.assertEqual(result.kwds[0][0], "kw")
        self.assertIsInstance(result.kwds[0], tuple)

    def test_return_expression_is_traversed_before_saving_return_flow(self):
        traverse, analyze = self.make_traverse()

        result = traverse(ast.Return([ast.Local("value")]))

        self.assertIsInstance(result, ast.Return)
        self.assertEqual(analyze.seen, ["Local", "Return"])
        self.assertIn("return", traverse.flow.bags)

    def test_loop_fixpoint_has_iteration_safety_cap(self):
        traverse, _analyze = self.make_traverse()
        self.assertEqual(traverse.maxLoopIterations, 128)


class TestReverseDataflow(unittest.TestCase):
    def make_traverse(self):
        strategy = RecordingStrategy()
        traverse = reverse.ReverseFlowTraverse(union_meet, strategy)
        strategy.flow = traverse.flow
        return traverse, strategy

    def test_short_circuit_or_is_traversed(self):
        traverse, strategy = self.make_traverse()
        traverse.flow.restore(base.DynamicDict())

        result = traverse(ast.ShortCircutOr([ast.Local("a"), ast.Local("b")]))

        self.assertIsInstance(result, ast.ShortCircutOr)
        self.assertEqual(
            [name for name, current in strategy.snapshots],
            ["Local", "Local"],
        )

    def test_exceptional_flow_is_merged_before_strategy_runs(self):
        traverse, strategy = self.make_traverse()

        normal = base.DynamicDict()
        normal.define("live", frozenset({"normal"}))

        raise_one = base.DynamicDict()
        raise_one.define("live", frozenset({"raise-1"}))

        raise_two = base.DynamicDict()
        raise_two.define("live", frozenset({"raise-2"}))

        traverse.flow.restore(normal)
        traverse.flow.bags["raise"] = [raise_one, raise_two]
        traverse.flow.tryLevel = 1

        traverse(ast.Assert(ast.Local("cond"), None))

        self.assertEqual(
            strategy.snapshots,
            [("Assert", frozenset({"normal", "raise-1", "raise-2"}))],
        )

    def test_tuple_container_shape_is_preserved(self):
        traverse, _strategy = self.make_traverse()
        traverse.flow.restore(base.DynamicDict())

        result = traverse.visitContainer((ast.Local("a"), ast.Local("b")))

        self.assertIsInstance(result, tuple)

    def test_reverse_loop_has_iteration_safety_cap(self):
        traverse, _strategy = self.make_traverse()
        self.assertEqual(traverse.maxLoopIterations, 128)

    def test_reverse_while_handles_none_initial_frame(self):
        traverse, _strategy = self.make_traverse()
        node = ast.While(
            ast.Condition(ast.Suite([]), ast.Local("cond")),
            ast.Suite([]),
            ast.Suite([]),
        )

        result = traverse(node)
        self.assertIsInstance(result, ast.While)


if __name__ == "__main__":
    unittest.main()
