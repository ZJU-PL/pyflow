from unittest.mock import patch

from pyflow.application.program import Program
from pyflow.application.passmanager import PassManager
from pyflow.application.passes import (
    CPAAnalysisPass,
    MethodCallOptimizationPass,
    SimplifyOptimizationPass,
    register_standard_passes,
)


def test_store_elimination_dependencies_registered():
    manager = PassManager()
    register_standard_passes(manager)

    deps = manager.passes["store_elimination"].info.dependencies
    assert "cpa" in deps
    assert "lifetime" in deps
    assert "simplify" in deps


def test_store_elimination_pipeline_includes_lifetime_before_execution():
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline(["store_elimination"])

    assert "lifetime" in pipeline.passes
    assert pipeline.passes.index("cpa") < pipeline.passes.index("lifetime")
    assert pipeline.passes.index("lifetime") < pipeline.passes.index(
        "store_elimination"
    )


def test_methodcall_pass_reports_changed_from_optimizer_result():
    p = MethodCallOptimizationPass()
    with patch("pyflow.application.passes.methodcall.evaluate", return_value=False):
        result = p.run(None, None)
    assert result.success is True
    assert result.changed is False

    with patch("pyflow.application.passes.methodcall.evaluate", return_value=True):
        result = p.run(None, None)
    assert result.success is True
    assert result.changed is True


def test_simplify_pass_reports_changed_from_optimizer_result():
    p = SimplifyOptimizationPass()
    with patch("pyflow.application.passes.simplify.evaluate", return_value=False):
        result = p.run(None, None)
    assert result.success is True
    assert result.changed is False

    with patch("pyflow.application.passes.simplify.evaluate", return_value=True):
        result = p.run(None, None)
    assert result.success is True
    assert result.changed is True


def test_cpa_analysis_pass_is_cacheable_for_same_program():
    manager = PassManager(enable_caching=True)
    manager.register_pass(CPAAnalysisPass())
    program = Program()

    with patch("pyflow.application.passes.cpa.evaluate", return_value=object()) as mocked:
        manager.run_passes(None, program, ["cpa"])
        manager.run_passes(None, program, ["cpa"])

    assert mocked.call_count == 1
