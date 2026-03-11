"""Tests for optimization/argumentnormalization.py."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pyflow.language.python import ast
from pyflow.optimization.argumentnormalization import (
    ArgumentNormalizationAnalysis,
    ArgumentNormalizationTransform,
    _ContainsLocalRef,
    evaluate,
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

    def test_contains_local_ref_finds_identity(self):
        target = ast.Local("args")
        finder = _ContainsLocalRef(target)
        finder(ast.Suite([ast.Discard(target)]))
        self.assertTrue(finder.found)

    def test_process_skips_when_vparam_local_is_still_in_body(self):
        vparam = ast.Local("args")
        code = SimpleNamespace(codeparameters=SimpleNamespace(vparam=vparam), ast=vparam)
        transform = ArgumentNormalizationTransform(None)

        changed = transform.process(code, 1)

        self.assertFalse(changed)


class TestArgumentNormalizationEvaluate(unittest.TestCase):
    def test_evaluate_reports_safety_blocked_normalization(self):
        class _Console:
            def __init__(self):
                self.messages = []

            def output(self, msg):
                self.messages.append(str(msg))

            def scope(self, _name):
                class _Scope:
                    def __enter__(self_inner):
                        return self_inner

                    def __exit__(self_inner, exc_type, exc, tb):
                        return False

                return _Scope()

        compiler = SimpleNamespace(console=_Console())
        prgm = SimpleNamespace(storeGraph=None, liveCode=[object()])

        def _blocked(self, _code, _vlen):
            self.last_skip_reason = "vparam_local_referenced_in_body"
            return False

        with patch.object(ArgumentNormalizationAnalysis, "process", return_value=(True, 1)), patch.object(
            ArgumentNormalizationTransform,
            "process",
            autospec=True,
            side_effect=_blocked,
        ):
            changed = evaluate(compiler, prgm)

        self.assertFalse(changed)
        self.assertTrue(
            any("skipped" in message and "safety guards" in message for message in compiler.console.messages)
        )


if __name__ == "__main__":
    unittest.main()
