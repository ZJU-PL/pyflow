"""
Integration tests for pass ordering constraints.

These tests verify that passes execute in the correct order and that
dependencies are properly enforced.
"""

import pytest
from unittest.mock import Mock, patch
from pyflow.application.program import Program
from pyflow.application.passmanager import PassManager
from pyflow.application.passes import register_standard_passes


def test_lifetime_always_runs_after_cpa():
    """Test that lifetime analysis always runs after CPA."""
    manager = PassManager()
    register_standard_passes(manager)

    # Request lifetime - should automatically include CPA
    pipeline = manager.build_pipeline(["lifetime"])

    assert "cpa" in pipeline.passes
    assert "ipa" in pipeline.passes  # CPA depends on IPA
    assert pipeline.passes.index("ipa") < pipeline.passes.index("cpa")
    assert pipeline.passes.index("cpa") < pipeline.passes.index("lifetime")


def test_store_elimination_runs_after_lifetime():
    """Test that store elimination runs after lifetime analysis."""
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline(["store_elimination"])

    # Should include full dependency chain
    assert "ipa" in pipeline.passes
    assert "cpa" in pipeline.passes
    assert "lifetime" in pipeline.passes
    assert "store_elimination" in pipeline.passes

    # Verify ordering
    ipa_idx = pipeline.passes.index("ipa")
    cpa_idx = pipeline.passes.index("cpa")
    lifetime_idx = pipeline.passes.index("lifetime")
    store_idx = pipeline.passes.index("store_elimination")

    assert ipa_idx < cpa_idx < lifetime_idx < store_idx


def test_load_elimination_runs_after_lifetime():
    """Test that load elimination runs after lifetime analysis."""
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline(["load_elimination"])

    assert "lifetime" in pipeline.passes
    assert pipeline.passes.index("lifetime") < pipeline.passes.index("load_elimination")


def test_optimizations_run_after_cpa():
    """Test that all optimization passes run after CPA."""
    manager = PassManager()
    register_standard_passes(manager)

    optimization_passes = [
        "methodcall",
        "simplify",
        "clone",
        "argument_normalization",
        "cull_program",
    ]

    for opt_pass in optimization_passes:
        pipeline = manager.build_pipeline([opt_pass])

        assert "cpa" in pipeline.passes, f"{opt_pass} should depend on CPA"
        assert pipeline.passes.index("cpa") < pipeline.passes.index(opt_pass)


def test_simplify_runs_before_dependent_optimizations():
    """Test that simplify runs before optimizations that depend on it."""
    manager = PassManager()
    register_standard_passes(manager)

    dependent_passes = [
        "clone",
        "argument_normalization",
        "cull_program",
        "load_elimination",
        "store_elimination",
    ]

    for dep_pass in dependent_passes:
        pipeline = manager.build_pipeline([dep_pass])

        assert "simplify" in pipeline.passes, f"{dep_pass} should depend on simplify"
        assert pipeline.passes.index("simplify") < pipeline.passes.index(dep_pass)


def test_circular_dependency_detection():
    """Test that circular dependencies are detected."""
    manager = PassManager()

    # Create passes with circular dependency
    from pyflow.application.passmanager import AnalysisPass, PassResult

    class PassA(AnalysisPass):
        def __init__(self):
            super().__init__("pass_a", "Test pass A")

        def run(self, compiler, program):
            return PassResult(success=True, changed=False)

    class PassB(AnalysisPass):
        def __init__(self):
            super().__init__("pass_b", "Test pass B")

        def run(self, compiler, program):
            return PassResult(success=True, changed=False)

    # Register passes first
    pass_a = PassA()
    pass_b = PassB()
    manager.register_pass(pass_a)
    manager.register_pass(pass_b)

    # Now add circular dependencies
    pass_a.info.dependencies.add("pass_b")
    pass_b.info.dependencies.add("pass_a")

    # Should detect circular dependency when building pipeline
    with pytest.raises(ValueError, match="Circular dependency"):
        manager.build_pipeline(["pass_a"])


def test_missing_dependency_detection():
    """Test that missing dependencies are detected."""
    manager = PassManager()

    from pyflow.application.passmanager import AnalysisPass, PassResult

    class PassWithMissingDep(AnalysisPass):
        def __init__(self):
            super().__init__("test_pass", "Test pass")
            self.info.dependencies.add("nonexistent_pass")

        def run(self, compiler, program):
            return PassResult(success=True, changed=False)

    manager.register_pass(PassWithMissingDep())

    # Should detect missing dependency
    with pytest.raises(ValueError, match="depends on unknown pass"):
        manager.build_pipeline(["test_pass"])


def test_pass_execution_order_matches_pipeline():
    """Test that passes execute in the order specified by the pipeline."""
    manager = PassManager(enable_caching=False)
    register_standard_passes(manager)

    program = Program()
    compiler = Mock()
    compiler.console = Mock()
    compiler.console.scope = Mock()
    compiler.console.scope.return_value.__enter__ = Mock()
    compiler.console.scope.return_value.__exit__ = Mock()
    compiler.console.output = Mock()

    execution_order = []

    def make_tracker(pass_name):
        def tracker(*args, **kwargs):
            execution_order.append(pass_name)
            return Mock()
        return tracker

    with patch("pyflow.application.passes.ipa.evaluate", side_effect=make_tracker("ipa")), \
         patch("pyflow.application.passes.cpa.evaluate", side_effect=make_tracker("cpa")), \
         patch("pyflow.application.passes.lifetimeanalysis.evaluate", side_effect=make_tracker("lifetime")):

        manager.run_passes(compiler, program, ["ipa", "cpa", "lifetime"])

    # Execution order should match requested order
    assert execution_order == ["ipa", "cpa", "lifetime"]


def test_pass_failure_stops_pipeline():
    """Test that pipeline stops after first pass failure."""
    manager = PassManager(enable_caching=False)
    register_standard_passes(manager)

    program = Program()
    compiler = Mock()
    compiler.console = Mock()
    compiler.console.scope = Mock()
    compiler.console.scope.return_value.__enter__ = Mock()
    compiler.console.scope.return_value.__exit__ = Mock()
    compiler.console.output = Mock()

    execution_order = []

    def ipa_success(*args, **kwargs):
        execution_order.append("ipa")
        return Mock()

    def cpa_failure(*args, **kwargs):
        execution_order.append("cpa")
        raise RuntimeError("CPA failed")

    def lifetime_should_not_run(*args, **kwargs):
        execution_order.append("lifetime")
        return Mock()

    with patch("pyflow.application.passes.ipa.evaluate", side_effect=ipa_success), \
         patch("pyflow.application.passes.cpa.evaluate", side_effect=cpa_failure), \
         patch("pyflow.application.passes.lifetimeanalysis.evaluate", side_effect=lifetime_should_not_run):

        results = manager.run_passes(compiler, program, ["ipa", "cpa", "lifetime"])

    # IPA should succeed, CPA should fail, lifetime should not run
    assert "ipa" in results
    assert results["ipa"].success
    assert "cpa" in results
    assert not results["cpa"].success
    assert "lifetime" not in results

    # Execution order should stop at CPA
    assert execution_order == ["ipa", "cpa"]


def test_requirements_vs_dependencies():
    """Test that requirements are enforced differently from dependencies."""
    manager = PassManager()
    register_standard_passes(manager)

    # store_elimination has both dependencies and requirements for lifetime
    store_pass = manager.passes["store_elimination"]

    assert "lifetime" in store_pass.info.dependencies
    assert "lifetime" in store_pass.info.requirements


def test_pass_can_be_explicitly_rerun():
    """Test that passes can be explicitly requested multiple times."""
    manager = PassManager()
    register_standard_passes(manager)

    # Request CPA twice
    pipeline = manager.build_pipeline(["cpa", "simplify", "cpa"])

    # CPA should appear twice
    cpa_indices = [i for i, p in enumerate(pipeline.passes) if p == "cpa"]
    assert len(cpa_indices) == 2

    # Second CPA should come after simplify
    simplify_idx = pipeline.passes.index("simplify")
    assert cpa_indices[1] > simplify_idx
