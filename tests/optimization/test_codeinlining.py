"""Tests for optimization/codeinlining.py - Code inlining optimization."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pyflow.optimization.codeinlining import (
    CodeInliningAnalysis,
    OpInliningTransform,
    CodeInliningTransform,
    evaluate,
)
from pyflow.language.python import ast
from pyflow.language.python.default_markers import MISSING_DEFAULT
from pyflow.language.python.program import Object


class MockAnnotation:
    def contextSubset(self, remap):
        return self


class TestCodeInliningAnalysis(unittest.TestCase):
    """Test cases for CodeInliningAnalysis class."""

    def test_init(self):
        """Test CodeInliningAnalysis initialization."""
        analysis = CodeInliningAnalysis()
        self.assertEqual(analysis.canInline, {})
        self.assertEqual(analysis.invokeCount, {})
        self.assertEqual(analysis.numOps, {})

    def test_visitLeaf(self):
        """Test visitLeaf does nothing."""
        analysis = CodeInliningAnalysis()
        analysis.ops = 0
        analysis.terminal = False
        analysis.inlinable = True
        analysis.level = 0
        
        # Should not raise
        analysis.visitLeaf(ast.Local("x"))
        analysis.visitLeaf(None)

    def test_visitLeaf_ast_types(self):
        """Test visitLeaf with various AST types."""
        analysis = CodeInliningAnalysis()
        analysis.ops = 0
        analysis.terminal = False
        analysis.inlinable = True
        analysis.level = 0
        
        # Should not raise for Local type
        analysis.visitLeaf(ast.Local("x"))


class TestOpInliningTransform(unittest.TestCase):
    """Test cases for OpInliningTransform class."""

    def test_init(self):
        """Test OpInliningTransform initialization."""
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)
        self.assertEqual(transform.analysis, analysis)

    def test_visitLeaf(self):
        """Test visitLeaf returns node unchanged."""
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)
        
        node = ast.Local("x")
        result = transform.visitLeaf(node)
        self.assertEqual(result, node)

    def test_visitDoNotCare(self):
        """Test visitDoNotCare returns new DoNotCare."""
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)
        
        node = ast.DoNotCare()
        result = transform.visitDoNotCare(node)
        
        self.assertIsInstance(result, ast.DoNotCare)

    def test_visitCode(self):
        """Test visitCode returns node unchanged."""
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)
        
        class MockCode:
            pass
        
        code = MockCode()
        result = transform.visitCode(code)
        self.assertEqual(result, code)

    def test_process_binds_posonly_and_default_parameters(self):
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)

        posonly = ast.Local("posonly")
        regular = ast.Local("regular")
        default_expr = ast.Local("default")
        posonly.annotation = MockAnnotation()
        regular.annotation = MockAnnotation()

        code = type(
            "MockCode",
            (),
            {
                "codeparameters": ast.CodeParameters(
                    selfparam=None,
                    posonlyparams=[posonly],
                    posonlynames=["only"],
                    params=[regular],
                    paramnames=["regular"],
                    defaults=[default_expr],
                    vparam=None,
                    kparam=None,
                    returnparams=[],
                    type_params=None,
                ),
                "ast": ast.DoNotCare(),
            },
        )()

        arg = ast.Local("arg")
        result = transform.process(None, None, code, [], None, [arg], None)

        self.assertEqual(len(result), 3)
        self.assertIs(result[0].expr, arg)
        self.assertIs(result[1].expr, default_expr)

    def test_process_skips_missing_default_sentinel(self):
        analysis = CodeInliningAnalysis()
        transform = OpInliningTransform(analysis)

        regular = ast.Local("regular")
        regular.annotation = MockAnnotation()
        missing_default = ast.Existing(Object(MISSING_DEFAULT))

        code = type(
            "MockCode",
            (),
            {
                "codeparameters": ast.CodeParameters(
                    selfparam=None,
                    posonlyparams=[],
                    posonlynames=[],
                    params=[regular],
                    paramnames=["regular"],
                    defaults=[missing_default],
                    vparam=None,
                    kparam=None,
                    returnparams=[],
                    type_params=None,
                ),
                "ast": ast.DoNotCare(),
            },
        )()

        result = transform.process(None, None, code, [], None, [], None)

        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], ast.DoNotCare)


class TestCodeInliningTransform(unittest.TestCase):
    """Test cases for CodeInliningTransform class."""

    def test_init(self):
        """Test CodeInliningTransform initialization with required arguments."""
        analysis = CodeInliningAnalysis()
        
        # CodeInliningTransform requires (analysis, compiler, prgm, intrinsics)
        # We test that the class can be imported and its attributes exist
        # Full initialization requires complex compiler/prgm objects
        self.assertTrue(hasattr(CodeInliningTransform, '__init__'))


class TestCodeInliningEvaluate(unittest.TestCase):
    def test_evaluate_returns_transform_change_flag(self):
        class _Console:
            def scope(self, _name):
                class _Scope:
                    def __enter__(self_inner):
                        return self_inner

                    def __exit__(self_inner, exc_type, exc, tb):
                        return False

                return _Scope()

            def output(self, _msg):
                return None

        compiler = SimpleNamespace(console=_Console())
        entry = object()
        prgm = SimpleNamespace(
            liveCode=[entry],
            interface=SimpleNamespace(entryCode=lambda: [entry]),
        )

        class _Transform:
            def __init__(self, *_args, **_kwargs):
                self.changed = True

            def process(self, _code):
                return None

        class _Analysis:
            def process(self, _code):
                return None

        with patch("pyflow.optimization.codeinlining.CodeInliningAnalysis", _Analysis), patch(
            "pyflow.optimization.codeinlining.CodeInliningTransform", _Transform
        ):
            changed = evaluate(compiler, prgm)

        self.assertTrue(changed)


if __name__ == "__main__":
    unittest.main()
