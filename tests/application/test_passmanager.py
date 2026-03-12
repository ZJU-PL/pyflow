from __future__ import annotations

from pyflow.application.program import Program
from pyflow.application.passmanager import AnalysisPass, PassManager, PassResult


class _DummyPass(AnalysisPass):
    def __init__(self, name: str, *, depends_on=(), boom: Exception | None = None):
        super().__init__(name, f"dummy:{name}")
        self.info.dependencies.update(depends_on)
        self.boom = boom
        self.calls = 0

    def run(self, compiler, program) -> PassResult:
        self.calls += 1
        if self.boom is not None:
            raise self.boom
        return PassResult(success=True, changed=False, data=self.name)


class _ChangingPass(_DummyPass):
    def run(self, compiler, program) -> PassResult:
        self.calls += 1
        return PassResult(success=True, changed=True, data=self.name)


def test_build_pipeline_includes_dependencies():
    manager = PassManager()
    dep = _DummyPass("dep")
    main = _DummyPass("main", depends_on=("dep",))
    manager.register_pass(main)
    manager.register_pass(dep)

    pipeline = manager.build_pipeline(["main"])

    assert pipeline.passes == ["dep", "main"]


def test_build_pipeline_rejects_unknown_passes():
    manager = PassManager()
    manager.register_pass(_DummyPass("known"))

    try:
        manager.build_pipeline(["unknown"])
    except ValueError as exc:
        assert "Unknown pass 'unknown'" in str(exc)
    else:
        raise AssertionError("expected unknown-pass lookup to fail")


def test_build_pipeline_preserves_requested_reruns_after_transform():
    manager = PassManager()
    analysis = _DummyPass("analysis")
    changing = _ChangingPass("changing")
    changing.info.dependencies.add("analysis")
    manager.register_pass(analysis)
    manager.register_pass(changing)

    pipeline = manager.build_pipeline(["analysis", "changing", "analysis"])

    assert pipeline.passes == ["analysis", "changing", "analysis"]


def test_build_pipeline_includes_analysis_requirements():
    manager = PassManager()
    analysis = _DummyPass("analysis")
    main = _DummyPass("main")
    main.info.requirements.add("analysis")
    manager.register_pass(main)
    manager.register_pass(analysis)

    pipeline = manager.build_pipeline(["main"])

    assert pipeline.passes == ["analysis", "main"]


def test_build_pipeline_rejects_unknown_prerequisites():
    manager = PassManager()
    main = _DummyPass("main")
    main.info.dependencies.add("missing")
    manager.register_pass(main)

    try:
        manager.build_pipeline(["main"])
    except ValueError as exc:
        assert "depends on unknown pass 'missing'" in str(exc)
    else:
        raise AssertionError("expected unknown dependency lookup to fail")


def test_run_pipeline_records_execution_time_and_uses_cache():
    manager = PassManager(enable_caching=True)
    cached = _DummyPass("cached")
    manager.register_pass(cached)

    first = manager.run_passes(None, object(), ["cached"])
    second = manager.run_passes(None, object(), ["cached"])

    assert first["cached"].success is True
    assert first["cached"].time is not None
    assert first["cached"].time >= 0
    assert second["cached"].success is True
    assert cached.calls == 2

    program = Program()
    cached.calls = 0
    manager.run_passes(None, program, ["cached"])
    manager.run_passes(None, program, ["cached"])
    assert cached.calls == 1


def test_run_pipeline_wraps_exception_type_in_result_and_log():
    manager = PassManager(enable_caching=False)
    failing = _DummyPass("explode", boom=RuntimeError("boom"))
    manager.register_pass(failing)

    result = manager.run_passes(None, object(), ["explode"])["explode"]
    log_entry = manager.get_execution_log()[-1]

    assert result.success is False
    assert result.exception_type == "RuntimeError"
    assert result.error == "RuntimeError: boom"
    assert result.time is not None
    assert log_entry["exception_type"] == "RuntimeError"
    assert log_entry["error"] == "RuntimeError: boom"


def test_run_pipeline_stops_after_first_failure():
    manager = PassManager(enable_caching=False)
    failing = _DummyPass("explode", boom=RuntimeError("boom"))
    skipped = _DummyPass("skipped", depends_on=("explode",))
    manager.register_pass(failing)
    manager.register_pass(skipped)

    results = manager.run_passes(None, object(), ["skipped"])

    assert list(results) == ["explode"]
    assert skipped.calls == 0


def test_changed_pass_does_not_reuse_cache_for_same_program():
    manager = PassManager(enable_caching=True)
    changing = _ChangingPass("changing")
    manager.register_pass(changing)

    program = Program()
    manager.run_passes(None, program, ["changing"])
    manager.run_passes(None, program, ["changing"])

    assert changing.calls == 2


def test_changed_pass_can_preserve_analysis_cache_via_metadata():
    manager = PassManager(enable_caching=True)
    analysis = _DummyPass("analysis")
    changing = _ChangingPass("changing")
    changing.info.preserves.add("analysis")
    manager.register_pass(analysis)
    manager.register_pass(changing)

    program = Program()
    manager.run_passes(None, program, ["analysis", "changing", "analysis"])

    assert analysis.calls == 1
