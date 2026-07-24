from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

import pyflow.cli.security.command as security_cli
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

        verbose = False
        quiet = False
        files_list = []
        scores = []
        excluded_files = []

        class _Metrics:
            data = {
                "_totals": {
                    "loc": 0, "nosec": 0, "skipped_tests": 0,
                    "SEVERITY.UNDEFINED": 0, "SEVERITY.LOW": 0,
                    "SEVERITY.MEDIUM": 0, "SEVERITY.HIGH": 0,
                    "CONFIDENCE.UNDEFINED": 0, "CONFIDENCE.LOW": 0,
                    "CONFIDENCE.MEDIUM": 0, "CONFIDENCE.HIGH": 0,
                }
            }

        metrics = _Metrics()

        def results_count(self, sev_level, conf_level):
            return 0

        def get_skipped(self):
            return []

        def discover_files(self, targets, recursive=False, excluded_paths=""):
            captured["targets"] = list(targets)
            captured["recursive"] = recursive
            captured["excluded_paths"] = excluded_paths

        def run_tests(self):
            captured["run_tests"] = True

        def get_issue_list(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(security_cli, "SecurityManager", FakePatternManager)

    args = SimpleNamespace(
        recursive=True,
        verbose=False,
        debug=False,
        exclude=" foo.py , bar.py ",
        engine="ast-scanner",
        taint_engine="ast",
        micro_bench=None,
        format="text",
        output=None,
        targets=["sample.py"],
    )

    exit_code = security_cli.run_security(args)

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
            captured["sources"] = config.sources
            captured["sinks"] = config.sinks
            self.verbose = verbose
            self.quiet = quiet

        files_list = []
        scores = []
        excluded_files = []

        class _Metrics:
            data = {
                "_totals": {
                    "loc": 0, "nosec": 0, "skipped_tests": 0,
                    "SEVERITY.UNDEFINED": 0, "SEVERITY.LOW": 0,
                    "SEVERITY.MEDIUM": 0, "SEVERITY.HIGH": 0,
                    "CONFIDENCE.UNDEFINED": 0, "CONFIDENCE.LOW": 0,
                    "CONFIDENCE.MEDIUM": 0, "CONFIDENCE.HIGH": 0,
                }
            }

        metrics = _Metrics()

        def results_count(self, sev_level, conf_level):
            return 0

        def get_skipped(self):
            return []

        def analyze(self, targets):
            captured["targets"] = list(targets)

        def get_issue_list(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(security_cli, "SemanticManager", FakeSemanticManager)

    args = SimpleNamespace(
        recursive=False,
        verbose=False,
        debug=False,
        exclude=" foo.py , bar.py ",
        engine="cpa",
        sources=["input"],
        sinks=["eval"],
        taint_engine="ast",
        micro_bench=None,
        format="text",
        output=None,
        targets=["sample.py"],
    )

    exit_code = security_cli.run_security(args)

    assert exit_code == 0
    assert captured["targets"] == ["sample.py"]
    assert captured["exclude"] == ("foo.py", "bar.py")
    assert captured["taint_engine"] == "ast"
    assert captured["sources"] == ("input",)
    assert captured["sinks"] == ("eval",)


def test_security_cli_cpa_completes_on_semantic_taint_file(tmp_path, capsys):
    sample = tmp_path / "cpa_taint.py"
    sample.write_text(
        """
import os


def command_from_input():
    cmd = input("cmd> ")
    os.system(cmd)


def eval_from_input():
    expr = input("expr> ")
    return eval(expr)
""",
        encoding="utf-8",
    )

    args = SimpleNamespace(
        recursive=False,
        verbose=False,
        debug=False,
        exclude="",
        engine="cpa",
        taint_engine="ast",
        format="text",
        output=None,
        targets=[str(sample)],
    )

    exit_code = security_cli.run_security(args)

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "Untrusted data can reach sink 'os.system'" in out
    assert "Untrusted data can reach sink 'eval'" in out
    assert "Traceback" not in out


def test_security_cli_cpg_reports_nested_source_to_sink_flow(tmp_path):
    sample = tmp_path / "cpg_flow.py"
    sample.write_text(
        """
import os


class Box:
    def __init__(self):
        self.value = None


def source():
    return input("cmd> ")


def passthrough(value):
    return value


def run_from_field():
    box = Box()
    box.value = passthrough(source())
    os.system(box.value)


def run_from_dict():
    payload = {"cmd": source()}
    cmd = f"{payload['cmd']}"
    eval(cmd)
""",
        encoding="utf-8",
    )

    args = SimpleNamespace(
        recursive=False,
        sources=["source", "input"],
        sinks=["os.system", "eval"],
        sanitizers=[],
        framework=[],
    )

    findings = security_cli._run_cpg([str(sample)], args)

    sink_labels = {finding["sink_label"] for finding in findings}
    assert "os.system" in sink_labels
    assert "eval" in sink_labels


def test_security_cli_cpg_reports_flask_framework_flow(tmp_path):
    sample = tmp_path / "cpg_flask.py"
    sample.write_text(
        """
import os
from flask import request


def route_handler():
    cmd = request.args.get("cmd")
    os.system(cmd)
""",
        encoding="utf-8",
    )

    args = SimpleNamespace(
        recursive=False,
        sources=[],
        sinks=[],
        sanitizers=[],
        framework=["flask"],
    )

    findings = security_cli._run_cpg([str(sample)], args)

    assert any(finding["sink_label"] == "os.system" for finding in findings)
