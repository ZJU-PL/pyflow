from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
import argparse
import json

from pyflow.cli import optimize
from pyflow.application.program import Program


class _Console:
    @contextmanager
    def scope(self, _name):
        yield

    def output(self, _message):
        return None


class _Compiler:
    def __init__(self):
        self.console = _Console()


def test_run_optimization_passes_always_skips_public_inlining(monkeypatch, capsys):
    compiler = _Compiler()
    program = object()
    args = SimpleNamespace(experimental_inlining=False)
    calls = []

    class _Pipeline:
        def __init__(self, *, use_pass_manager):
            assert use_pass_manager is True

        def run_custom_pipeline(self, _compiler, _program, pass_names):
            calls.append(tuple(pass_names))
            return {}

    monkeypatch.setattr(optimize, "Pipeline", _Pipeline)

    optimize.run_optimization_passes(compiler, program, ["inlining"], args)

    assert calls == []
    assert "currently disabled in the public optimization pipeline" in capsys.readouterr().out


def test_run_optimization_passes_skips_inlining_even_with_experimental_flag(
    monkeypatch, capsys
):
    compiler = _Compiler()
    program = object()
    args = SimpleNamespace(experimental_inlining=True)
    calls = []

    class _Pipeline:
        def __init__(self, *, use_pass_manager):
            assert use_pass_manager is True

        def run_custom_pipeline(self, _compiler, _program, pass_names):
            calls.append(tuple(pass_names))
            return {}

    monkeypatch.setattr(optimize, "Pipeline", _Pipeline)

    optimize.run_optimization_passes(compiler, program, ["inlining"], args)

    assert calls == []
    assert "currently disabled in the public optimization pipeline" in capsys.readouterr().out


def test_run_optimization_passes_all_expands_to_default_pipeline(monkeypatch):
    compiler = _Compiler()
    program = object()
    args = SimpleNamespace(experimental_inlining=False)
    seen = {"default": [], "custom": []}

    monkeypatch.setattr(
        optimize,
        "_run_default_pipeline",
        lambda *_args, **kwargs: seen["default"].append(kwargs),
    )

    class _Pipeline:
        def __init__(self, *, use_pass_manager):
            assert use_pass_manager is True

        def run_custom_pipeline(self, _compiler, _program, pass_names):
            seen["custom"].append(tuple(pass_names))
            return {}

    monkeypatch.setattr(optimize, "Pipeline", _Pipeline)

    optimize.run_optimization_passes(compiler, program, ["all"], args)

    assert seen["default"] == [{"include_experimental_inlining": False}]
    assert seen["custom"] == []


def test_run_optimization_passes_all_includes_experimental_inlining(monkeypatch):
    compiler = _Compiler()
    program = object()
    args = SimpleNamespace(experimental_inlining=True)
    seen = {"default": [], "custom": []}

    monkeypatch.setattr(
        optimize,
        "_run_default_pipeline",
        lambda *_args, **kwargs: seen["default"].append(kwargs),
    )

    class _Pipeline:
        def __init__(self, *, use_pass_manager):
            assert use_pass_manager is True

        def run_custom_pipeline(self, _compiler, _program, pass_names):
            seen["custom"].append(tuple(pass_names))
            return {}

    monkeypatch.setattr(optimize, "Pipeline", _Pipeline)

    optimize.run_optimization_passes(compiler, program, ["all"], args)

    assert seen["default"] == [{"include_experimental_inlining": True}]
    assert seen["custom"] == []


def test_optimize_parser_rejects_conflicting_mode_flags():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    optimize.add_optimize_parser(subparsers)

    try:
        parser.parse_args(
            ["optimize", "sample.py", "--suggest-only", "--apply-optimizations"]
        )
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected mutually exclusive optimize mode flags to fail")


def test_optimize_parser_accepts_explicit_optimized_source_destination():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    optimize.add_optimize_parser(subparsers)

    args = parser.parse_args(
        ["optimize", "sample.py", "--emit-optimized", "optimized.py"]
    )

    assert args.emit_optimized == "optimized.py"


def test_optimize_parser_accepts_source_level_and_json_report():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    optimize.add_optimize_parser(subparsers)

    args = parser.parse_args(
        [
            "optimize",
            "sample.py",
            "--emit-optimized",
            "optimized.py",
            "--opt-level",
            "2",
            "--report-optimizations",
            "report.json",
        ]
    )

    assert args.opt_level == 2
    assert args.report_optimizations == "report.json"


def test_run_analysis_emits_source_even_when_no_entry_point(monkeypatch, tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("answer = 6 * 7\n", encoding="utf-8")
    optimized = tmp_path / "optimized.py"
    compiler = _Compiler()
    program = SimpleNamespace(interface=SimpleNamespace(func=[]))

    monkeypatch.setattr(
        optimize,
        "_build_analysis_state",
        lambda _python_files, _args: (compiler, program),
    )

    args = SimpleNamespace(emit_optimized=str(optimized))
    optimize.run_analysis(sample, args)

    assert optimized.read_text(encoding="utf-8") == "answer = 42\n"


def test_run_analysis_writes_machine_readable_optimization_report(monkeypatch, tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("answer = 6 * 7\n", encoding="utf-8")
    optimized = tmp_path / "optimized.py"
    report = tmp_path / "report.json"
    compiler = _Compiler()
    program = SimpleNamespace(interface=SimpleNamespace(func=[]))

    monkeypatch.setattr(
        optimize,
        "_build_analysis_state",
        lambda _python_files, _args: (compiler, program),
    )

    args = SimpleNamespace(
        emit_optimized=str(optimized),
        opt_level=2,
        report_optimizations=str(report),
    )
    optimize.run_analysis(sample, args)

    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["optimization_level"] == 2
    assert data["totals"]["constant_folds"] == 1
    assert data["legacy_passes"] == []


def test_run_analysis_honors_explicit_apply_mode(monkeypatch, tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("def f():\n    return 1\n", encoding="utf-8")

    compiler = _Compiler()
    program = SimpleNamespace(interface=SimpleNamespace(func=[object()]))
    calls = {"default": 0}

    monkeypatch.setattr(
        optimize,
        "_build_analysis_state",
        lambda _python_files, _args: (compiler, program),
    )
    monkeypatch.setattr(
        optimize,
        "_run_default_pipeline",
        lambda *_args, **_kwargs: calls.__setitem__("default", calls["default"] + 1),
    )

    args = SimpleNamespace(
        verbose=False,
        analysis="all",
        no_opt_passes=False,
        suggest_only=False,
        apply_optimizations=True,
        opt_passes=None,
        dump=False,
        dump_ipa=False,
        dump_shape=False,
        output=None,
        recursive=False,
        include=["*.py"],
        exclude=[],
        dependency_strategy="auto",
    )

    optimize.run_analysis(sample, args)

    assert calls["default"] == 1


def test_run_analysis_threads_experimental_inlining_into_default_pipeline(
    monkeypatch, tmp_path
):
    sample = tmp_path / "sample.py"
    sample.write_text("def f():\n    return 1\n", encoding="utf-8")

    compiler = _Compiler()
    program = SimpleNamespace(interface=SimpleNamespace(func=[object()]))
    seen = []

    monkeypatch.setattr(
        optimize,
        "_build_analysis_state",
        lambda _python_files, _args: (compiler, program),
    )
    monkeypatch.setattr(
        optimize,
        "_run_default_pipeline",
        lambda *_args, **kwargs: seen.append(kwargs),
    )

    args = SimpleNamespace(
        verbose=False,
        analysis="all",
        no_opt_passes=False,
        suggest_only=False,
        apply_optimizations=False,
        experimental_inlining=True,
        opt_passes=None,
        dump=False,
        dump_ipa=False,
        dump_shape=False,
        output=None,
        recursive=False,
        include=["*.py"],
        exclude=[],
        dependency_strategy="auto",
    )

    optimize.run_analysis(sample, args)

    assert seen == [{"include_experimental_inlining": True}]


def test_run_suggestions_uses_pipeline_and_refreshes_ipa(monkeypatch, capsys):
    from pyflow.analysis import ipa as ipa_module

    compiler = _Compiler()
    initial_ipa = SimpleNamespace(contexts={"a": object()})
    refreshed_ipa = SimpleNamespace(contexts={"a": object(), "b": object()})
    program = Program()
    program.set_analysis_result(
        "cpa", SimpleNamespace(unresolved=["call1", "call2"])
    )
    seen = []

    class _Pipeline:
        def __init__(self, *, use_pass_manager):
            assert use_pass_manager is True

        def default_pass_names(self):
            return ["ipa", "cpa", "simplify"]

        def run_custom_pipeline(self, _compiler, _program, pass_names):
            seen.append(tuple(pass_names))
            return {}

    monkeypatch.setattr(
        ipa_module,
        "evaluate",
        lambda _compiler, _program: initial_ipa
        if _program.get_analysis_result("ipa") is None
        else refreshed_ipa,
    )
    monkeypatch.setattr(optimize, "Pipeline", _Pipeline)

    optimize.run_suggestions(compiler, program)

    output = capsys.readouterr().out
    assert seen == [("ipa", "cpa", "simplify")]
    assert program.get_analysis_result("ipa") is refreshed_ipa
    assert "2 unresolved calls" in output


def test_dump_ipa_results_refreshes_missing_analysis(monkeypatch, tmp_path, capsys):
    compiler = _Compiler()
    analysis = SimpleNamespace(contexts={"ctx": object()}, root=object())
    program = Program()
    dumped = []

    class _Dumper:
        def __init__(self, path):
            dumped.append(("init", path))

        def index(self, contexts, root):
            dumped.append(("index", list(contexts), root))

        def dumpContext(self, context):
            dumped.append(("context", context))

    monkeypatch.setattr(
        "pyflow.analysis.ipa.evaluate",
        lambda _compiler, _program: analysis,
    )
    monkeypatch.setattr("pyflow.analysis.ipa.dump.Dumper", _Dumper)

    optimize.dump_ipa_results(compiler, program, tmp_path / "sample.py", None)

    assert program.get_analysis_result("ipa") is analysis
    assert dumped[0][0] == "init"
    assert dumped[1][0] == "index"
    assert "IPA analysis results dumped to:" in capsys.readouterr().out
