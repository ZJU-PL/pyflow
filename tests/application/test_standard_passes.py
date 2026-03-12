from unittest.mock import patch

from pyflow.application.program import Program
from pyflow.application.pipeline import Pipeline
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


def test_standard_pass_aliases_resolve_to_registered_passes():
    manager = PassManager()
    register_standard_passes(manager)

    assert manager.resolve_pass_name("argumentnormalization") == "argument_normalization"
    assert manager.resolve_pass_name("cullprogram") == "cull_program"
    assert manager.resolve_pass_name("loadelimination") == "load_elimination"
    assert manager.resolve_pass_name("storeelimination") == "store_elimination"


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


def test_path_sensitive_cpa_pass_uses_legacy_second_pass_settings():
    manager = PassManager(enable_caching=False)
    register_standard_passes(manager)
    program = Program()

    with patch("pyflow.application.passes.ipa.evaluate", return_value=object()), patch(
        "pyflow.application.passes.cpa.evaluate", return_value=object()
    ) as mocked, patch(
        "pyflow.application.passes.methodcall.evaluate", return_value=False
    ), patch(
        "pyflow.application.passes.simplify.evaluate", return_value=False
    ), patch(
        "pyflow.application.passes.clone.evaluate", return_value=False
    ), patch(
        "pyflow.application.passes.argumentnormalization.evaluate", return_value=False
    ), patch(
        "pyflow.application.passes.cullprogram.evaluate", return_value=False
    ), patch(
        "pyflow.application.passes.storeelimination.evaluate", return_value=False
    ), patch(
        "pyflow.application.passes.lifetimeanalysis.evaluate", return_value=object()
    ):
        manager.run_passes(None, program, ["cpa_path_sensitive"])

    assert mocked.call_count == 2
    assert mocked.call_args_list[-1].args == (None, program, 3)
    assert mocked.call_args_list[-1].kwargs == {"firstPass": False}


def test_path_sensitive_cpa_pipeline_requires_first_pass_conditioning():
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline(["cpa_path_sensitive"])

    assert pipeline.passes.index("methodcall") < pipeline.passes.index(
        "cpa_path_sensitive"
    )
    assert pipeline.passes.index("clone") < pipeline.passes.index("cpa_path_sensitive")
    assert pipeline.passes.index("argument_normalization") < pipeline.passes.index(
        "cpa_path_sensitive"
    )
    assert pipeline.passes.index("cull_program") < pipeline.passes.index(
        "cpa_path_sensitive"
    )
    assert pipeline.passes.index("store_elimination") < pipeline.passes.index(
        "cpa_path_sensitive"
    )


def test_path_sensitive_pipeline_preserves_legacy_first_pass_stage_order():
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline(["cpa_path_sensitive"])

    assert pipeline.passes.index("methodcall") < pipeline.passes.index("first_pass_methodcall")
    assert pipeline.passes.index("first_pass_methodcall") < pipeline.passes.index("lifetime")
    assert pipeline.passes.index("lifetime") < pipeline.passes.index("first_pass_lifetime")
    assert pipeline.passes.index("first_pass_lifetime") < pipeline.passes.index("simplify")
    assert pipeline.passes.index("simplify") < pipeline.passes.index("first_pass_simplify")
    assert pipeline.passes.index("first_pass_simplify") < pipeline.passes.index("clone")
    assert pipeline.passes.index("clone") < pipeline.passes.index("first_pass_clone")
    assert pipeline.passes.index("first_pass_clone") < pipeline.passes.index(
        "argument_normalization"
    )
    assert pipeline.passes.index("argument_normalization") < pipeline.passes.index(
        "first_pass_argument_normalization"
    )
    assert pipeline.passes.index("first_pass_argument_normalization") < pipeline.passes.index(
        "cull_program"
    )
    assert pipeline.passes.index("cull_program") < pipeline.passes.index(
        "first_pass_cull_program"
    )
    assert pipeline.passes.index("first_pass_cull_program") < pipeline.passes.index(
        "store_elimination"
    )
    assert pipeline.passes.index("store_elimination") < pipeline.passes.index(
        "first_pass_store_elimination"
    )
    assert pipeline.passes.index("first_pass_store_elimination") < pipeline.passes.index(
        "first_pass_complete"
    )
    assert pipeline.passes.index("first_pass_complete") < pipeline.passes.index(
        "ipa_refresh"
    )
    assert pipeline.passes.index("ipa_refresh") < pipeline.passes.index("cpa_path_sensitive")


def test_dce_pipeline_does_not_force_simplify():
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline(["dce"])

    assert "simplify" not in pipeline.passes
    assert pipeline.passes == ["ipa", "cpa", "dce"]


def test_inlining_pipeline_requires_argument_normalization():
    manager = PassManager()
    register_standard_passes(manager)

    pipeline = manager.build_pipeline(["inlining"])

    assert "argument_normalization" in pipeline.passes
    assert pipeline.passes.index("argument_normalization") < pipeline.passes.index(
        "inlining"
    )


def test_default_pipeline_keeps_methodcall_before_lifetime(monkeypatch):
    pipeline = Pipeline(use_pass_manager=True)
    program = Program()
    captured = {}

    def fake_run_pipeline(_compiler, _program, pass_pipeline):
        captured["passes"] = list(pass_pipeline.passes)
        return {}

    monkeypatch.setattr(pipeline.pass_manager, "run_pipeline", fake_run_pipeline)

    class _Compiler:
        class _Console:
            def output(self, _message):
                return None

        console = _Console()

    pipeline.run(program, compiler=_Compiler())

    assert captured["passes"].index("methodcall") < captured["passes"].index("lifetime")
    assert captured["passes"] == [
        "ipa",
        "cpa",
        "methodcall",
        "lifetime",
        "simplify",
        "clone",
        "argument_normalization",
        "cull_program",
        "store_elimination",
        "ipa_refresh",
        "first_pass_methodcall",
        "first_pass_lifetime",
        "first_pass_simplify",
        "first_pass_clone",
        "first_pass_argument_normalization",
        "first_pass_cull_program",
        "first_pass_store_elimination",
        "first_pass_complete",
        "cpa_path_sensitive",
        "lifetime_refresh",
        "simplify_final",
        "store_elimination_final",
    ]


def test_default_pipeline_splices_inlining_before_cull_program(monkeypatch):
    pipeline = Pipeline(use_pass_manager=True)
    program = Program()
    captured = {}

    def fake_run_pipeline(_compiler, _program, pass_pipeline):
        captured["passes"] = list(pass_pipeline.passes)
        return {}

    monkeypatch.setattr(pipeline.pass_manager, "run_pipeline", fake_run_pipeline)

    class _Compiler:
        class _Console:
            def output(self, _message):
                return None

        console = _Console()

    pipeline.run(program, compiler=_Compiler(), include_experimental_inlining=True)

    assert captured["passes"].index("argument_normalization") < captured["passes"].index(
        "inlining"
    )
    assert captured["passes"].index("inlining") < captured["passes"].index(
        "cull_program"
    )
