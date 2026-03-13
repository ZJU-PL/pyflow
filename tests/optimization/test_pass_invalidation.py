"""
Tests for pass invalidation correctness.

These tests verify that optimization passes correctly invalidate analysis results
when they transform the program, preventing use of stale analysis data.
"""

import pytest
from unittest.mock import Mock, patch
from pyflow.application.program import Program
from pyflow.application.passmanager import PassManager
from pyflow.application.passes import register_standard_passes


class _Scope:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _compiler():
    compiler = Mock()
    compiler.console = Mock()
    compiler.console.scope = Mock(return_value=_Scope())
    compiler.console.output = Mock()
    return compiler


def test_store_elimination_requires_lifetime_analysis():
    """Test that store_elimination checks for lifetime_analysis attribute."""
    from pyflow.optimization import storeelimination
    from pyflow.language.python import ast

    compiler = _compiler()

    program = Program()
    program.liveCode = set()
    program.lifetime_analysis = None  # Explicitly None

    with pytest.raises(RuntimeError, match="requires lifetime analysis"):
        storeelimination.evaluate(compiler, program)


def test_store_elimination_dependency_on_lifetime():
    """Test that store_elimination declares dependency on lifetime."""
    manager = PassManager()
    register_standard_passes(manager)

    # store_elimination should depend on lifetime
    store_pass = manager.passes["store_elimination"]
    assert "lifetime" in store_pass.info.dependencies
    assert "lifetime" in store_pass.info.requirements


def test_load_elimination_requires_lifetime_analysis():
    """Test that load_elimination checks for lifetime_analysis attribute."""
    from pyflow.optimization import loadelimination

    compiler = _compiler()

    program = Program()
    program.liveCode = set()
    program.lifetime_analysis = None

    with pytest.raises(RuntimeError, match="requires lifetime analysis"):
        loadelimination.evaluate(compiler, program)


def test_load_elimination_dependency_on_lifetime():
    """Test that load_elimination declares dependency on lifetime."""
    manager = PassManager()
    register_standard_passes(manager)

    load_pass = manager.passes["load_elimination"]
    assert "lifetime" in load_pass.info.dependencies
    assert "lifetime" in load_pass.info.requirements


def test_optimization_pass_invalidates_analysis():
    """Test that optimization passes invalidate analysis results."""
    manager = PassManager(enable_caching=True)
    register_standard_passes(manager)

    program = Program()
    program.ipa_analysis = Mock()
    program.cpa_analysis = Mock()
    program.lifetime_analysis = Mock()

    compiler = _compiler()

    # Mock simplify to return changed=True
    with patch("pyflow.application.passes.simplify.evaluate", return_value=True), \
         patch("pyflow.application.passes.ipa.evaluate", return_value=Mock()), \
         patch("pyflow.application.passes.cpa.evaluate", return_value=Mock()):
        manager.run_passes(compiler, program, ["simplify"])

    # Analysis results should be cleared after transformation
    assert program.ipa_analysis is None
    assert program.cpa_analysis is None
    assert program.lifetime_analysis is None


def test_analysis_pass_preserves_results():
    """Test that analysis passes preserve their own results."""
    manager = PassManager(enable_caching=True)
    register_standard_passes(manager)

    program = Program()

    compiler = _compiler()

    mock_ipa_result = Mock()

    with patch("pyflow.application.passes.ipa.evaluate", return_value=mock_ipa_result):
        manager.run_passes(compiler, program, ["ipa"])

    # IPA result should be stored
    assert program.ipa_analysis is mock_ipa_result

    # Running IPA again should use cache
    with patch("pyflow.application.passes.ipa.evaluate") as mock_ipa:
        manager.run_passes(compiler, program, ["ipa"])
        # Should not call evaluate again (cached)
        mock_ipa.assert_not_called()


def test_transformation_clears_cache():
    """Test that transforming passes clear the cache."""
    manager = PassManager(enable_caching=True)
    register_standard_passes(manager)

    program = Program()

    compiler = _compiler()

    # Run analysis and cache it
    with patch("pyflow.application.passes.cpa.evaluate", return_value=Mock()):
        manager.run_passes(compiler, program, ["cpa"])

    # Run transformation
    with patch("pyflow.application.passes.simplify.evaluate", return_value=True):
        manager.run_passes(compiler, program, ["simplify"])

    # Cache should be cleared for the program
    assert len(manager.cache.pass_names(program)) == 0


def test_stale_annotation_detection():
    """Test detection of stale lifetime annotations after transformation."""
    manager = PassManager(enable_caching=False)
    register_standard_passes(manager)

    program = Program()
    program.liveCode = set()

    compiler = _compiler()

    # Run lifetime analysis
    with patch("pyflow.application.passes.lifetimeanalysis.evaluate", return_value=Mock()), \
         patch("pyflow.application.passes.ipa.evaluate", return_value=Mock()), \
         patch("pyflow.application.passes.cpa.evaluate", return_value=Mock()):
        manager.run_passes(compiler, program, ["lifetime"])

    # lifetime_analysis should be set
    assert program.lifetime_analysis is not None

    # Run transformation that invalidates lifetime
    with patch("pyflow.application.passes.simplify.evaluate", return_value=True), \
         patch("pyflow.application.passes.ipa.evaluate", return_value=Mock()), \
         patch("pyflow.application.passes.cpa.evaluate", return_value=Mock()):
        manager.run_passes(compiler, program, ["simplify"])

    # lifetime_analysis should be cleared
    assert program.lifetime_analysis is None


def test_optimization_pass_must_declare_invalidation():
    """Test that optimization passes must declare invalidation metadata."""
    from pyflow.application.passmanager import OptimizationPass, PassResult, PassKind

    class BadOptimizationPass(OptimizationPass):
        def __init__(self):
            super().__init__("bad_opt", "Bad optimization without metadata")
            # Intentionally don't set invalidates or preserves
            self.info.invalidates.clear()
            self.info.preserves.clear()

        def run(self, compiler, program):
            return PassResult(success=True, changed=True)

    manager = PassManager()

    # Register the pass - should succeed
    manager.register_pass(BadOptimizationPass())

    # But validation should fail when we call validate_optimization_metadata
    with pytest.raises(ValueError, match="must declare either 'invalidates' or 'preserves'"):
        manager.validate_optimization_metadata()


def test_two_pass_pipeline_recomputes_analysis():
    """Test that the two-pass pipeline recomputes analysis after transformations."""
    manager = PassManager(enable_caching=False)
    register_standard_passes(manager)

    program = Program()

    compiler = _compiler()

    ipa_call_count = 0

    def mock_ipa_evaluate(compiler, program):
        nonlocal ipa_call_count
        ipa_call_count += 1
        return Mock()

    with patch("pyflow.application.passes.ipa.evaluate", side_effect=mock_ipa_evaluate):
        with patch("pyflow.application.passes.cpa.evaluate", return_value=Mock()):
            with patch("pyflow.application.passes.simplify.evaluate", return_value=True):
                # Run first pass
                manager.run_passes(compiler, program, ["ipa", "cpa", "simplify"])

                # Run ipa_refresh (should recompute)
                manager.run_passes(compiler, program, ["ipa_refresh"])

    # IPA should have been called twice (once for ipa, once for ipa_refresh)
    assert ipa_call_count == 2
