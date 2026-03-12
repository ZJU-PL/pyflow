from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

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
