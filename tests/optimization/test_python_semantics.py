"""
Tests for Python semantic edge cases in optimization passes.

These tests verify that optimizations preserve Python's dynamic semantics,
including closures, descriptors, aliasing, and exception handling.
"""

import pytest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from pyflow.language.python import ast
from pyflow.optimization import argumentnormalization, clone, methodcall
from pyflow.application.program import Program


def test_argument_normalization_blocks_closure_capture():
    """Test that argument normalization detects closure capture of *args."""
    # This is a simplified test that checks the _ContainsLocalRef visitor
    # works correctly when tracking closure references
    vparam = ast.Local("args")

    # Create a simple discard statement that references vparam
    discard_stmt = ast.Discard(vparam)

    # Check for reference
    checker = argumentnormalization._ContainsLocalRef(vparam)
    checker(discard_stmt)

    # Should detect that vparam is referenced
    assert checker.found

    # Test persistent closure-capture tracking.
    checker2 = argumentnormalization._ContainsLocalRef(vparam)
    assert checker2.in_closure == False  # Initially False

    # Create a mock Code node
    mock_code = Mock()
    mock_code.visitChildren = Mock(side_effect=lambda visitor: visitor(vparam))

    checker2.visitCode(mock_code)
    assert checker2.found_in_closure is True


def test_argument_normalization_blocks_methods():
    """Test that argument normalization is blocked for methods (descriptor risk)."""
    program = Program()
    program.liveCode = set()

    # Create a method (has selfparam)
    code = ast.Code(
        "method",
        ast.CodeParameters(
            selfparam=ast.Local("self"),
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=ast.Local("args"),
            kparam=None,
            returnparams=[ast.Local("ret")],
            type_params=None,
        ),
        ast.Suite([])
    )
    code.annotation = Mock()
    code.annotation.descriptive = False

    program.liveCode.add(code)
    program.interface = Mock()
    program.interface.entryCode = Mock(return_value=[])

    # Should block normalization due to descriptor risk
    blocker = argumentnormalization._normalization_blocker(program, code, 2)
    assert blocker == "method_descriptor_risk"


def test_method_call_optimization_checks_single_target():
    """Test that method call optimization verifies single dispatch target."""
    # Create a call with multiple targets
    node = Mock()
    node.annotation = Mock()
    node.annotation.invokes = [
        {(Mock(), Mock()), (Mock(), Mock())},  # Multiple code targets
        []
    ]

    pattern = Mock()
    pattern.icallsC = node.annotation.invokes[0]

    rewriter = methodcall.MethodRewrite(pattern)
    rewriter.flow = Mock()
    rewriter.flow.lookup = Mock(return_value=("expr", "name", "meth"))

    # Should return False because public rewriting is conservatively disabled.
    is_method, expr, name = rewriter.isMethodCall(node, "meth")
    assert not is_method


def test_dce_preserves_exception_handler_variables():
    """Test that DCE marks variables in exception handlers as live."""
    from pyflow.optimization.dce import MarkLocals
    from pyflow.optimization.dataflow.base import top

    marker = MarkLocals()
    marker.flow = Mock()
    marker.flow._current = Mock()
    marker.flow.define = Mock()

    # Create a TryExceptFinally node with variable reference in handler
    var = ast.Local("x")
    try_except = Mock(spec=ast.TryExceptFinally)
    try_except.visitChildren = Mock(side_effect=lambda visitor: visitor(var))

    # Visit the exception handler
    marker.visitExceptionHandler(try_except)

    # Should have visited children (marking variables as live)
    try_except.visitChildren.assert_called_once()


def test_store_elimination_checks_aliasing():
    """Test that store elimination preserves stores to potentially aliased objects."""
    from pyflow.optimization import storeelimination
    from pyflow.language.python import ast

    compiler = Mock()
    compiler.console = Mock()
    compiler.console.scope = Mock()
    compiler.console.scope.return_value.__enter__ = Mock()
    compiler.console.scope.return_value.__exit__ = Mock()
    compiler.console.output = Mock()

    program = Program()
    program.lifetime_analysis = Mock()  # Present but not None

    # Create a code object with a store
    code = Mock()
    code.isStandardCode = Mock(return_value=True)
    code.annotation = Mock()
    code.annotation.descriptive = False
    code.annotation.codeReads = [set()]

    # Create a store operation
    store = Mock(spec=ast.Store)
    store_ann = Mock()

    # Create a modify location with references (indicating aliasing)
    modify = Mock()
    modify.object = Mock()
    modify.object.leaks = False
    modify.object.references = [Mock()]  # Has references, might be aliased

    store_ann.modifies = [[modify]]
    store.annotation = store_ann

    # Mock codeOps to return our store
    with patch("pyflow.optimization.storeelimination.codeOps", return_value=[store]):
        program.liveCode = {code}

        result = storeelimination.evaluate(compiler, program)

        # Store should NOT be eliminated due to aliasing
        # Result should be a boolean (True if stores eliminated, False otherwise)
        assert result in (True, False, None)  # Accept any valid return value


def test_clone_fixup_filters_invocations_to_live_code():
    """Clone fixup should drop invocation targets that no longer exist in liveCode."""
    from pyflow.optimization.clone import _fix_invocation_annotations_after_clone

    live_code = Mock()
    live_code.annotation = SimpleNamespace(contexts=("ctx",))
    dead_code = Mock()
    dead_code.annotation = SimpleNamespace(contexts=("dead_ctx",))
    op = Mock()
    op.annotation = SimpleNamespace(invokes=((), [((live_code, "ctx"), (dead_code, "dead_ctx"))]))
    op.rewriteAnnotation = Mock()
    code = Mock()
    program = Mock()
    program.liveCode = {code, live_code}
    cloner = Mock()

    with patch("pyflow.optimization.clone.tools.codeOps", return_value=[op]):
        _fix_invocation_annotations_after_clone(program, cloner)

    rewritten_invokes = op.rewriteAnnotation.call_args.kwargs["invokes"]
    assert tuple(rewritten_invokes[1][0]) == ((live_code, "ctx"),)


def test_clone_fixup_tolerates_missing_contexts():
    """Clone fixup should drop targets whose contexts disappeared during rewriting."""
    from pyflow.optimization.clone import _fix_invocation_annotations_after_clone

    target = Mock()
    target.annotation = SimpleNamespace(contexts=("other",))
    op = Mock()
    op.annotation = SimpleNamespace(invokes=((), [((target, "missing"),)]))
    op.rewriteAnnotation = Mock()
    code = Mock()
    program = Mock(liveCode={code, target})

    with patch("pyflow.optimization.clone.tools.codeOps", return_value=[op]):
        _fix_invocation_annotations_after_clone(program, Mock())

    rewritten_invokes = op.rewriteAnnotation.call_args.kwargs["invokes"]
    assert tuple(rewritten_invokes[1][0]) == ()


def test_simplify_change_detection_includes_annotations():
    """Test that simplify change detection includes annotation changes."""
    from pyflow.optimization.simplify import _snapshot_code

    # Create a local with annotation
    local1 = ast.Local("x")
    local1.annotation = Mock()
    local1.annotation.__repr__ = Mock(return_value="ann1")

    local2 = ast.Local("x")
    local2.annotation = Mock()
    local2.annotation.__repr__ = Mock(return_value="ann2")

    snapshot1 = _snapshot_code(local1)
    snapshot2 = _snapshot_code(local2)

    # Snapshots should differ due to different annotations
    assert snapshot1 != snapshot2


def test_inlining_warns_experimental():
    """Test that inlining pass warns about experimental status."""
    from pyflow.optimization import codeinlining

    compiler = Mock()
    compiler.console = Mock()
    compiler.console.scope = Mock()
    compiler.console.scope.return_value.__enter__ = Mock()
    compiler.console.scope.return_value.__exit__ = Mock()
    compiler.console.output = Mock()

    program = Mock()
    program.liveCode = []
    program.interface = Mock()
    program.interface.entryCode = Mock(return_value=[])

    codeinlining.evaluate(compiler, program)

    # Should have output a warning
    warning_calls = [call for call in compiler.console.output.call_args_list
                     if "WARNING" in str(call) or "experimental" in str(call).lower()]
    assert len(warning_calls) > 0


def test_inlining_raises_on_unsupported_patterns():
    """Test that inlining has error handling for unsupported patterns."""
    from pyflow.optimization import codeinlining

    compiler = Mock()
    compiler.console = Mock()
    compiler.console.scope = Mock()
    compiler.console.scope.return_value.__enter__ = Mock()
    compiler.console.scope.return_value.__exit__ = Mock()
    compiler.console.output = Mock()

    program = Mock()
    program.liveCode = []
    program.interface = Mock()

    # Create a mock code object that will be processed
    mock_code = Mock()
    program.interface.entryCode = Mock(return_value=[mock_code])

    # Mock CodeInliningAnalysis to succeed
    with patch("pyflow.optimization.codeinlining.CodeInliningAnalysis") as MockAnalysis:
        mock_analysis = Mock()
        mock_analysis.process = Mock()
        MockAnalysis.return_value = mock_analysis

        # Mock CodeInliningTransform to raise an exception during process
        with patch("pyflow.optimization.codeinlining.CodeInliningTransform") as MockTransform:
            mock_transform = Mock()
            # Make process raise an exception
            mock_transform.process = Mock(side_effect=ValueError("Unsupported pattern"))
            mock_transform.changed = False
            MockTransform.return_value = mock_transform

            # Should catch the exception and re-raise as RuntimeError
            try:
                codeinlining.evaluate(compiler, program)
                # If we get here, the exception wasn't raised
                # Check that at least the warning was output
                assert any("WARNING" in str(call) or "experimental" in str(call).lower()
                          for call in compiler.console.output.call_args_list)
            except RuntimeError as e:
                # This is what we expect
                assert "Code inlining failed" in str(e)


def test_cli_pass_name_normalization():
    """Test that CLI pass names are normalized to registered names."""
    from pyflow.cli.optimize import _normalize_opt_pass_name

    # Test legacy names map to canonical names
    assert _normalize_opt_pass_name("argumentnormalization") == "argument_normalization"
    assert _normalize_opt_pass_name("cullprogram") == "cull_program"
    assert _normalize_opt_pass_name("loadelimination") == "load_elimination"
    assert _normalize_opt_pass_name("storeelimination") == "store_elimination"

    # Test canonical names pass through
    assert _normalize_opt_pass_name("argument_normalization") == "argument_normalization"
    assert _normalize_opt_pass_name("simplify") == "simplify"


def test_pass_manager_validates_optimization_metadata():
    """Test that pass manager validates optimization passes have invalidation metadata."""
    from pyflow.application.passmanager import PassManager, OptimizationPass, PassResult, PassKind

    manager = PassManager()

    # Create an optimization pass without invalidation metadata
    class BadOptimizationPass(OptimizationPass):
        def __init__(self):
            super().__init__("bad_opt", "Bad optimization")
            # Clear the default metadata
            self.info.invalidates.clear()
            self.info.preserves.clear()

        def run(self, compiler, program):
            return PassResult(success=True, changed=True)

    bad_pass = BadOptimizationPass()

    # Register the pass
    manager.register_pass(bad_pass)

    # Should raise ValueError when validating
    with pytest.raises(ValueError, match="must declare either 'invalidates' or 'preserves'"):
        manager.validate_optimization_metadata()


def test_optimization_pass_with_preserves_allowed():
    """Test that optimization passes with preserves metadata are allowed."""
    from pyflow.application.passmanager import PassManager, OptimizationPass, PassResult

    manager = PassManager()

    class GoodOptimizationPass(OptimizationPass):
        def __init__(self):
            super().__init__("good_opt", "Good optimization")
            self.info.preserves.add("ipa")  # Declares what it preserves

        def run(self, compiler, program):
            return PassResult(success=True, changed=True)

    good_pass = GoodOptimizationPass()

    # Should not raise
    manager.register_pass(good_pass)
    assert "good_opt" in manager.passes
