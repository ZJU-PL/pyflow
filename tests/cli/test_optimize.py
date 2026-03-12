from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

from pyflow.cli import optimize
from pyflow.analysis import cpa, lifetimeanalysis
from pyflow.optimization import codeinlining


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

    called = {"inlining": 0}

    monkeypatch.setattr(cpa, "evaluate", lambda *_: None)
    monkeypatch.setattr(lifetimeanalysis, "evaluate", lambda *_: None)
    monkeypatch.setattr(
        codeinlining,
        "evaluate",
        lambda *_: called.__setitem__("inlining", called["inlining"] + 1),
    )

    optimize.run_optimization_passes(compiler, program, ["inlining"], args)

    assert called["inlining"] == 0
    assert "Skipping 'inlining' pass" in capsys.readouterr().out


def test_run_optimization_passes_allows_inlining_with_experimental_flag(monkeypatch):
    compiler = _Compiler()
    program = object()
    args = SimpleNamespace(experimental_inlining=True)

    called = {"inlining": 0}

    monkeypatch.setattr(cpa, "evaluate", lambda *_: None)
    monkeypatch.setattr(lifetimeanalysis, "evaluate", lambda *_: None)
    monkeypatch.setattr(
        codeinlining,
        "evaluate",
        lambda *_: called.__setitem__("inlining", called["inlining"] + 1),
    )

    optimize.run_optimization_passes(compiler, program, ["inlining"], args)

    assert called["inlining"] == 1
