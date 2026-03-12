"""
Tests for CLI and pass manager consistency.

These tests verify that the CLI and pass manager use consistent naming
and produce equivalent results.
"""

import pytest
from unittest.mock import Mock, patch
from pyflow.cli.optimize import _normalize_opt_pass_name, OPTIMIZATION_PASSES, OPT_PASS_ALIASES
from pyflow.application.passmanager import PassManager
from pyflow.application.passes import register_standard_passes, PASS_ALIASES


def test_cli_aliases_match_pass_manager():
    """Test that CLI aliases are consistent with pass manager aliases."""
    manager = PassManager()
    register_standard_passes(manager)

    # All CLI aliases should resolve to valid pass names
    for cli_name, canonical_name in OPT_PASS_ALIASES.items():
        # CLI alias should map to a registered pass
        assert canonical_name in manager.passes, f"CLI alias '{cli_name}' maps to unregistered pass '{canonical_name}'"


def test_cli_pass_names_are_registered():
    """Test that all CLI-exposed passes are registered in pass manager."""
    manager = PassManager()
    register_standard_passes(manager)

    for pass_name in OPTIMIZATION_PASSES.keys():
        normalized = _normalize_opt_pass_name(pass_name)
        try:
            resolved = manager.resolve_pass_name(normalized)
            assert resolved in manager.passes
        except ValueError:
            pytest.fail(f"CLI pass '{pass_name}' (normalized: '{normalized}') is not registered")


def test_pass_manager_aliases_are_bidirectional():
    """Test that pass manager aliases work in both directions."""
    manager = PassManager()
    register_standard_passes(manager)

    # Test that both old and new names resolve to the same pass
    for alias, target in PASS_ALIASES.items():
        assert manager.resolve_pass_name(alias) == target
        assert manager.resolve_pass_name(target) == target


def test_cli_normalization_handles_legacy_names():
    """Test that CLI normalization handles legacy names correctly."""
    # Legacy names should map to canonical names
    assert _normalize_opt_pass_name("argumentnormalization") == "argument_normalization"
    assert _normalize_opt_pass_name("cullprogram") == "cull_program"
    assert _normalize_opt_pass_name("loadelimination") == "load_elimination"
    assert _normalize_opt_pass_name("storeelimination") == "store_elimination"

    # Canonical names should pass through unchanged
    assert _normalize_opt_pass_name("argument_normalization") == "argument_normalization"
    assert _normalize_opt_pass_name("cull_program") == "cull_program"


def test_all_optimization_passes_have_descriptions():
    """Test that all optimization passes have descriptions in CLI."""
    for pass_name, description in OPTIMIZATION_PASSES.items():
        assert description, f"Pass '{pass_name}' has no description"
        assert len(description) > 10, f"Pass '{pass_name}' has too short description"


def test_experimental_inlining_has_warning():
    """Test that experimental inlining pass has warning in description."""
    assert "EXPERIMENTAL" in OPTIMIZATION_PASSES["inlining"].upper()


def test_pass_manager_rejects_unknown_passes():
    """Test that pass manager rejects unknown pass names."""
    manager = PassManager()
    register_standard_passes(manager)

    with pytest.raises(ValueError, match="Unknown pass"):
        manager.resolve_pass_name("nonexistent_pass")


def test_cli_and_pass_manager_produce_same_pipeline():
    """Test that CLI and pass manager produce equivalent pipelines."""
    manager = PassManager()
    register_standard_passes(manager)

    # Test a few common pass sequences
    test_sequences = [
        ["simplify"],
        ["cpa", "simplify"],
        ["ipa", "cpa", "lifetime", "simplify"],
    ]

    for sequence in test_sequences:
        # Normalize CLI names
        normalized = [_normalize_opt_pass_name(name) for name in sequence]

        # Build pipeline
        pipeline = manager.build_pipeline(normalized)

        # All requested passes should be in the pipeline
        for pass_name in normalized:
            assert pass_name in pipeline.passes, f"Pass '{pass_name}' missing from pipeline"


def test_pass_dependencies_are_satisfied():
    """Test that pass dependencies are automatically satisfied."""
    manager = PassManager()
    register_standard_passes(manager)

    # store_elimination depends on lifetime, which depends on cpa, which depends on ipa
    pipeline = manager.build_pipeline(["store_elimination"])

    # Should include all dependencies
    assert "ipa" in pipeline.passes
    assert "cpa" in pipeline.passes
    assert "lifetime" in pipeline.passes
    assert "store_elimination" in pipeline.passes

    # Dependencies should come before dependent passes
    assert pipeline.passes.index("ipa") < pipeline.passes.index("cpa")
    assert pipeline.passes.index("cpa") < pipeline.passes.index("lifetime")
    assert pipeline.passes.index("lifetime") < pipeline.passes.index("store_elimination")


def test_pass_ordering_is_deterministic():
    """Test that pass ordering is deterministic across multiple builds."""
    manager = PassManager()
    register_standard_passes(manager)

    # Build the same pipeline multiple times
    pipelines = [
        manager.build_pipeline(["simplify", "clone", "cull_program"])
        for _ in range(5)
    ]

    # All pipelines should have the same order
    first_order = pipelines[0].passes
    for pipeline in pipelines[1:]:
        assert pipeline.passes == first_order


def test_cli_help_text_matches_registered_passes():
    """Test that CLI help text includes all registered passes."""
    manager = PassManager()
    register_standard_passes(manager)

    # Internal passes that are not exposed in CLI
    internal_passes = {
        "first_pass_methodcall", "first_pass_lifetime", "first_pass_simplify",
        "first_pass_clone", "first_pass_argument_normalization",
        "first_pass_cull_program", "first_pass_store_elimination",
        "first_pass_complete", "ipa_refresh", "cpa_path_sensitive",
        "lifetime_refresh", "simplify_final", "store_elimination_final"
    }

    # All registered optimization passes should be in CLI
    for pass_name in manager.passes:
        if pass_name in internal_passes:
            # Internal passes, not exposed in CLI
            continue

        # Should be in OPTIMIZATION_PASSES or have an alias
        normalized = _normalize_opt_pass_name(pass_name)
        assert (
            pass_name in OPTIMIZATION_PASSES or
            normalized in OPTIMIZATION_PASSES or
            pass_name in ["ipa", "cpa", "lifetime"]  # Analysis passes
        ), f"Pass '{pass_name}' not exposed in CLI"


def test_pass_manager_handles_repeated_passes():
    """Test that pass manager handles repeated passes correctly."""
    manager = PassManager()
    register_standard_passes(manager)

    # Request the same pass multiple times
    pipeline = manager.build_pipeline(["simplify", "clone", "simplify"])

    # simplify should appear twice
    simplify_indices = [i for i, p in enumerate(pipeline.passes) if p == "simplify"]
    assert len(simplify_indices) == 2


def test_invalid_cli_pass_name_gives_clear_error():
    """Test that invalid CLI pass names give clear error messages."""
    manager = PassManager()
    register_standard_passes(manager)

    with pytest.raises(ValueError) as exc_info:
        manager.build_pipeline(["invalid_pass_name"])

    assert "invalid_pass_name" in str(exc_info.value)
