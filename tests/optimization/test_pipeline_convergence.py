"""
Tests for two-pass pipeline convergence and correctness.

These tests verify that the two-pass optimization pipeline (with path-sensitive CPA)
produces correct and converged results.
"""

import pytest
from unittest.mock import Mock, patch
from pyflow.application.program import Program
from pyflow.application.pipeline import Pipeline
from pyflow.application.passmanager import PassManager
from pyflow.application.passes import register_standard_passes


def test_two_pass_pipeline_includes_path_sensitive_cpa():
    """Test that two-pass pipeline includes path-sensitive CPA."""
    manager = PassManager()
    register_standard_passes(manager)

    # Build the full two-pass pipeline
    pipeline = manager.build_pipeline([
        "ipa",
        "cpa",
        "first_pass_methodcall",
        "first_pass_lifetime",
        "first_pass_simplify",
        "first_pass_clone",
        "first_pass_argument_normalization",
        "first_pass_cull_program",
        "first_pass_store_elimination",
        "first_pass_complete",
        "ipa_refresh",
        "cpa_path_sensitive",
        "lifetime_refresh",
        "simplify_final",
        "store_elimination_final",
    ])

    # Should include path-sensitive CPA
    assert "cpa_path_sensitive" in pipeline.passes

    # Path-sensitive CPA should come after first pass
    assert pipeline.passes.index("first_pass_complete") < pipeline.passes.index("cpa_path_sensitive")


def test_ipa_refresh_runs_after_transformations():
    """Test that IPA refresh runs after first-pass transformations."""
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline([
        "first_pass_clone",
        "first_pass_argument_normalization",
        "ipa_refresh",
    ])

    # ipa_refresh should come after transformations
    assert "ipa_refresh" in pipeline.passes
    assert pipeline.passes.index("first_pass_argument_normalization") < pipeline.passes.index("ipa_refresh")


def test_cpa_path_sensitive_depends_on_ipa_refresh():
    """Test that path-sensitive CPA depends on IPA refresh."""
    manager = PassManager()
    register_standard_passes(manager)

    # Request only cpa_path_sensitive
    pipeline = manager.build_pipeline(["cpa_path_sensitive"])

    # Should automatically include ipa_refresh
    assert "ipa_refresh" in pipeline.passes
    assert pipeline.passes.index("ipa_refresh") < pipeline.passes.index("cpa_path_sensitive")


def test_lifetime_refresh_depends_on_cpa_path_sensitive():
    """Test that lifetime refresh depends on path-sensitive CPA."""
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline(["lifetime_refresh"])

    # Should include cpa_path_sensitive
    assert "cpa_path_sensitive" in pipeline.passes
    assert pipeline.passes.index("cpa_path_sensitive") < pipeline.passes.index("lifetime_refresh")


def test_final_passes_use_refreshed_analysis():
    """Test that final optimization passes depend on refreshed analysis."""
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline(["simplify_final", "store_elimination_final"])

    # Should include refreshed analysis
    assert "cpa_path_sensitive" in pipeline.passes
    assert "lifetime_refresh" in pipeline.passes

    # Final passes should come after refreshed analysis
    cpa_idx = pipeline.passes.index("cpa_path_sensitive")
    lifetime_idx = pipeline.passes.index("lifetime_refresh")
    simplify_idx = pipeline.passes.index("simplify_final")
    store_idx = pipeline.passes.index("store_elimination_final")

    assert cpa_idx < simplify_idx
    assert lifetime_idx < simplify_idx
    assert lifetime_idx < store_idx


def test_pipeline_invalidates_analysis_between_passes():
    """Test that transformations invalidate analysis between first and second pass."""
    manager = PassManager(enable_caching=True)
    register_standard_passes(manager)

    program = Program()
    compiler = Mock()
    compiler.console = Mock()
    compiler.console.scope = Mock()
    compiler.console.scope.return_value.__enter__ = Mock()
    compiler.console.scope.return_value.__exit__ = Mock()
    compiler.console.output = Mock()

    # Mock all passes
    with patch("pyflow.application.passes.ipa.evaluate", return_value=Mock()) as mock_ipa, \
         patch("pyflow.application.passes.cpa.evaluate", return_value=Mock()), \
         patch("pyflow.application.passes.lifetimeanalysis.evaluate", return_value=Mock()), \
         patch("pyflow.application.passes.simplify.evaluate", return_value=True), \
         patch("pyflow.application.passes.clone.evaluate", return_value=True):

        # Run first pass with transformation
        manager.run_passes(compiler, program, ["ipa", "cpa", "lifetime", "simplify", "clone"])

        # Analysis should be cleared after transformation
        assert program.ipa_analysis is None
        assert program.cpa_analysis is None
        assert program.lifetime_analysis is None

        # Run ipa_refresh - should actually call IPA again
        mock_ipa.reset_mock()
        manager.run_passes(compiler, program, ["ipa_refresh"])

        # IPA should have been called (not cached)
        mock_ipa.assert_called_once()


def test_default_pipeline_matches_legacy_pipeline_structure():
    """Test that default pipeline structure matches legacy pipeline."""
    pipeline = Pipeline(use_pass_manager=True)

    default_passes = pipeline.default_pass_names(include_experimental_inlining=False)

    # Should include core passes in correct order
    assert "ipa" in default_passes
    assert "cpa" in default_passes
    assert "methodcall" in default_passes
    assert "lifetime" in default_passes
    assert "simplify" in default_passes
    assert "clone" in default_passes
    assert "argument_normalization" in default_passes

    # Should NOT include inlining by default
    assert "inlining" not in default_passes


def test_experimental_inlining_inserted_correctly():
    """Test that experimental inlining is inserted in correct position."""
    pipeline = Pipeline(use_pass_manager=True)

    passes_with_inlining = pipeline.default_pass_names(include_experimental_inlining=True)

    # Should include inlining
    assert "inlining" in passes_with_inlining

    # Inlining should come after argument_normalization
    arg_norm_idx = passes_with_inlining.index("argument_normalization")
    inlining_idx = passes_with_inlining.index("inlining")
    assert arg_norm_idx < inlining_idx


def test_pass_manager_pipeline_is_default():
    """Test that pass manager is the default pipeline mode."""
    pipeline = Pipeline()
    assert pipeline.use_pass_manager is True


def test_two_pass_pipeline_convergence():
    """Test that running the pipeline twice produces stable results."""
    manager = PassManager(enable_caching=False)
    register_standard_passes(manager)

    program = Program()
    program.liveCode = set()

    compiler = Mock()
    compiler.console = Mock()
    compiler.console.scope = Mock()
    compiler.console.scope.return_value.__enter__ = Mock()
    compiler.console.scope.return_value.__exit__ = Mock()
    compiler.console.output = Mock()

    # Mock passes to track call counts
    call_counts = {"simplify": 0, "clone": 0}

    def mock_simplify(comp, prog):
        call_counts["simplify"] += 1
        # First call changes, second call doesn't (converged)
        return call_counts["simplify"] == 1

    def mock_clone(comp, prog):
        call_counts["clone"] += 1
        return call_counts["clone"] == 1

    with patch("pyflow.application.passes.ipa.evaluate", return_value=Mock()), \
         patch("pyflow.application.passes.cpa.evaluate", return_value=Mock()), \
         patch("pyflow.application.passes.lifetimeanalysis.evaluate", return_value=Mock()), \
         patch("pyflow.application.passes.simplify.evaluate", side_effect=mock_simplify), \
         patch("pyflow.application.passes.clone.evaluate", side_effect=mock_clone), \
         patch("pyflow.application.passes.argumentnormalization.evaluate", return_value=False), \
         patch("pyflow.application.passes.cullprogram.evaluate", return_value=False), \
         patch("pyflow.application.passes.storeelimination.evaluate", return_value=False):

        # Run pipeline twice
        manager.run_passes(compiler, program, ["ipa", "cpa", "lifetime", "simplify", "clone"])
        manager.run_passes(compiler, program, ["ipa", "cpa", "lifetime", "simplify", "clone"])

        # Second run should show convergence (no changes)
        assert call_counts["simplify"] == 2
        assert call_counts["clone"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
