from unittest.mock import patch

from pyflow.application.passmanager import PassManager
from pyflow.application.passes import (
    MethodCallOptimizationPass,
    SimplifyOptimizationPass,
    register_standard_passes,
)


def test_store_elimination_dependencies_registered():
    manager = PassManager()
    register_standard_passes(manager)

    deps = manager.passes["store_elimination"].info.dependencies
    assert "cpa" in deps
    assert "simplify" in deps


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
