from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

import pyflow.cli.security as security_cli
from pyflow.checker.formatters import json as json_formatter
from pyflow.checker.formatters import text as text_formatter
from pyflow.checker.pattern.core import constants as b_constants


def _totals() -> dict[str, int]:
    totals = {
        "loc": 0,
        "nosec": 0,
        "skipped_tests": 0,
    }
    for criteria, _ in b_constants.CRITERIA:
        for rank in b_constants.RANKING:
            totals[f"{criteria}.{rank}"] = 0
    return totals


class _FormatterManager:
    quiet = False
    verbose = False
    files_list: list[str] = []
    scores: list[object] = []
    excluded_files: list[str] = []
    metrics = SimpleNamespace(data={"_totals": _totals()})

    def results_count(self, *_args, **_kwargs):
        return 0

    def get_issue_list(self, *_args, **_kwargs):
        return []

    def get_skipped(self):
        return []


@pytest.mark.parametrize(
    "formatter",
    [text_formatter.report, json_formatter.report],
)
def test_formatters_keep_caller_owned_stream_open(formatter):
    buffer = io.StringIO()

    formatter(_FormatterManager(), buffer, b_constants.LOW, b_constants.LOW)

    buffer.write("still-open")
    assert "still-open" in buffer.getvalue()


def test_security_cli_threads_pattern_excludes_into_discover_files(
    monkeypatch,
):
    captured = {}

    class FakePatternManager:
        def __init__(self, *args, **kwargs):
            pass

        def discover_files(self, targets, recursive=False, excluded_paths=""):
            captured["targets"] = list(targets)
            captured["recursive"] = recursive
            captured["excluded_paths"] = excluded_paths

        def run_tests(self):
            captured["run_tests"] = True

        def get_issue_list(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(security_cli, "SecurityManager", FakePatternManager)
    monkeypatch.setattr(
        security_cli.text_formatter, "report", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        security_cli.json_formatter, "report", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        security_cli.sarif_formatter, "report", lambda *args, **kwargs: None
    )

    args = SimpleNamespace(
        recursive=True,
        verbose=False,
        debug=False,
        exclude=" foo.py , bar.py ",
        engine="pattern",
        taint_engine="ast",
        micro_bench=None,
        format="text",
        output=None,
    )

    exit_code = security_cli.run_security_analysis(["sample.py"], args)

    assert exit_code == 0
    assert captured["targets"] == ["sample.py"]
    assert captured["recursive"] is True
    assert captured["excluded_paths"] == "foo.py,bar.py"
    assert captured["run_tests"] is True


def test_security_cli_threads_semantic_excludes_into_config(monkeypatch):
    captured = {}

    class FakeSemanticManager:
        def __init__(self, config, debug=False, verbose=False, quiet=False):
            captured["exclude"] = config.exclude
            captured["taint_engine"] = config.taint_engine

        def analyze(self, targets):
            captured["targets"] = list(targets)

        def get_issue_list(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(security_cli, "SemanticManager", FakeSemanticManager)
    monkeypatch.setattr(
        security_cli.text_formatter, "report", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        security_cli.json_formatter, "report", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        security_cli.sarif_formatter, "report", lambda *args, **kwargs: None
    )

    args = SimpleNamespace(
        recursive=False,
        verbose=False,
        debug=False,
        exclude=" foo.py , bar.py ",
        engine="semantic",
        taint_engine="both",
        micro_bench=None,
        format="text",
        output=None,
    )

    exit_code = security_cli.run_security_analysis(["sample.py"], args)

    assert exit_code == 0
    assert captured["targets"] == ["sample.py"]
    assert captured["exclude"] == ("foo.py", "bar.py")
    assert captured["taint_engine"] == "ast"
