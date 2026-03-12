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
        candidate = SimpleNamespace(
            codeparameters=SimpleNamespace(vparam=object(), selfparam=None),
            ast=ast.Suite([]),
        )
        prgm = SimpleNamespace(storeGraph=None, liveCode=[candidate])

        def _blocked(self, _code, _vlen):
            self.last_skip_reason = "vparam_local_referenced_in_body"
            return False

        with patch.object(ArgumentNormalizationAnalysis, "process", return_value=(True, 1)), patch(
            "pyflow.optimization.argumentnormalization.codeOps",
            return_value=[],
        ), patch.object(ArgumentNormalizationTransform, "process", autospec=True, side_effect=_blocked):
            changed = evaluate(compiler, prgm)

        self.assertFalse(changed)
        self.assertTrue(
            any("skipped" in message and "safety guards" in message for message in compiler.console.messages)
        )

    def test_evaluate_skips_entry_point_normalization(self):
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
        candidate = object()
        prgm = SimpleNamespace(
            storeGraph=None,
            liveCode=[candidate],
            interface=SimpleNamespace(entryCode=lambda: frozenset((candidate,))),
        )

        def _process_analysis(self, code):
            return (True, 1) if code is candidate else (False, 0)

        with patch.object(
            ArgumentNormalizationAnalysis,
            "process",
            autospec=True,
            side_effect=_process_analysis,
        ), patch.object(
            ArgumentNormalizationTransform,
            "process",
            autospec=True,
            return_value=True,
        ) as transform_process:
            changed = evaluate(compiler, prgm)

        self.assertFalse(changed)
        transform_process.assert_not_called()

    def test_evaluate_skips_unsupported_incoming_call_conventions(self):
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
        class _Candidate:
            def __init__(self):
                self.codeparameters = SimpleNamespace(vparam=object(), selfparam=None)
                self.ast = ast.Suite([])

        candidate = _Candidate()
        caller = object()
        context = object()
        incoming = ast.Call(ast.Local("func"), [], [], ast.Local("star"), None)
        incoming.annotation = SimpleNamespace(
            invokes=(((candidate, context),), (((candidate, context),),))
        )

        prgm = SimpleNamespace(
            storeGraph=None,
            liveCode=[candidate, caller],
            interface=SimpleNamespace(entryCode=lambda: frozenset()),
        )

        def _process_analysis(self, code):
            return (True, 1) if code is candidate else (False, 0)

        with patch.object(
            ArgumentNormalizationAnalysis,
            "process",
            autospec=True,
            side_effect=_process_analysis,
        ), patch("pyflow.optimization.argumentnormalization.codeOps") as mock_code_ops, patch.object(
            ArgumentNormalizationTransform,
            "process",
            autospec=True,
            return_value=True,
        ) as transform_process:
            mock_code_ops.side_effect = lambda code: [incoming] if code is caller else []
            changed = evaluate(compiler, prgm)

        self.assertFalse(changed)
        transform_process.assert_not_called()

    def test_evaluate_skips_incoming_call_arity_mismatch(self):
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
        class _Candidate:
            def __init__(self):
                self.codeparameters = SimpleNamespace(
                    posonlyparams=[],
                    params=[object()],
                    vparam=object(),
                    selfparam=None,
                )
                self.ast = ast.Suite([])

        candidate = _Candidate()
        caller = object()
        context = object()
        incoming = ast.Call(ast.Local("func"), [], [], None, None)
        incoming.annotation = SimpleNamespace(
            invokes=(((candidate, context),), (((candidate, context),),))
        )

        prgm = SimpleNamespace(
            storeGraph=None,
            liveCode=[candidate, caller],
            interface=SimpleNamespace(entryCode=lambda: frozenset()),
        )

        def _process_analysis(self, code):
            return (True, 1) if code is candidate else (False, 0)

        with patch.object(
            ArgumentNormalizationAnalysis,
            "process",
            autospec=True,
            side_effect=_process_analysis,
        ), patch("pyflow.optimization.argumentnormalization.codeOps") as mock_code_ops, patch.object(
            ArgumentNormalizationTransform,
            "process",
            autospec=True,
            return_value=True,
        ) as transform_process:
            mock_code_ops.side_effect = lambda code: [incoming] if code is caller else []
            changed = evaluate(compiler, prgm)

        self.assertFalse(changed)
        transform_process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
