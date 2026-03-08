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


def test_build_pipeline_includes_dependencies():
    manager = PassManager()
    dep = _DummyPass("dep")
    main = _DummyPass("main", depends_on=("dep",))
    manager.register_pass(main)
    manager.register_pass(dep)

    pipeline = manager.build_pipeline(["main"])

    assert pipeline.passes == ["dep", "main"]


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
