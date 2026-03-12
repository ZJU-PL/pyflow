from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
import argparse

from pyflow.cli import optimize


class _Console:
    @contextmanager
    def scope(self, _name):
        yield

    def output(self, _message):
        return None


class _Compiler:
    def __init__(self):
        self.console = _Console()


def test_run_optimization_passes_skips_inlining_without_experimental_flag(
    monkeypatch, capsys
):
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
    assert "Skipping 'inlining' pass" in capsys.readouterr().out


def test_run_optimization_passes_allows_inlining_with_experimental_flag(monkeypatch):
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

    assert calls == [("inlining",)]


def test_run_optimization_passes_all_expands_to_default_pipeline(monkeypatch):
    compiler = _Compiler()
    program = object()
    args = SimpleNamespace(experimental_inlining=False)
    seen = {"default": 0, "custom": []}

    monkeypatch.setattr(
        optimize,
        "_run_default_pipeline",
        lambda *_args: seen.__setitem__("default", seen["default"] + 1),
    )

    class _Pipeline:
        def __init__(self, *, use_pass_manager):
            assert use_pass_manager is True

        def run_custom_pipeline(self, _compiler, _program, pass_names):
            seen["custom"].append(tuple(pass_names))
            return {}

    monkeypatch.setattr(optimize, "Pipeline", _Pipeline)

    optimize.run_optimization_passes(compiler, program, ["all"], args)

    assert seen["default"] == 1
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
        lambda *_args: calls.__setitem__("default", calls["default"] + 1),
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
