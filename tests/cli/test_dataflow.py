from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import pyflow.analysis.ifds.api as ifds_api
import pyflow.cli.taint as dataflow_cli


class _DummyCode:
    def codeName(self):
        return "sinkproc"


class _DummyResult:
    def __init__(self, tainted_arguments, tainted_argument_labels):
        self.findings = (
            SimpleNamespace(
                sink_name="sink",
                sink=SimpleNamespace(
                    kind="call",
                    procedure=SimpleNamespace(code=_DummyCode()),
                ),
                tainted_arguments=tainted_arguments,
                tainted_argument_labels=tainted_argument_labels,
            ),
        )
        self.statistics = SimpleNamespace(
            processed_path_edges=1,
            propagated_path_edges=2,
            normal_flow_steps=3,
            call_flow_steps=4,
            return_flow_steps=5,
            call_to_return_steps=6,
            incoming_records=7,
            summary_updates=8,
        )

    def fact_for_local(self, *_args, **_kwargs):
        return object()

    def explain_fact(self, *_args, **_kwargs):
        return {}


class _EmptyResult:
    findings = ()
    statistics = SimpleNamespace(
        processed_path_edges=1,
        propagated_path_edges=2,
        normal_flow_steps=3,
        call_flow_steps=4,
        return_flow_steps=5,
        call_to_return_steps=6,
        incoming_records=7,
        summary_updates=8,
    )


def _make_args(output_format: str) -> SimpleNamespace:
    return SimpleNamespace(
        function="main",
        analysis="taint",
        engine="ifds",
        targets=None,
        sources=["source"],
        sinks=["sink"],
        sanitizers=["sanitize"],
        format=output_format,
        recursive=False,
        dependency_strategy="auto",
        verbose=False,
    )


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_dataflow_cli_uses_single_taint_result_path(
    monkeypatch, tmp_path, capsys, output_format
):
    target = tmp_path / "sample.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def main():
    sink(source())
""",
        encoding="utf-8",
    )

    calls = []
    fake_result = _DummyResult((SimpleNamespace(name="b"),), ())

    def fake_run_taint_analysis(*_args, **_kwargs):
        calls.append(True)
        session = SimpleNamespace(
            compiler=object(),
            diagnostics=(),
            program=SimpleNamespace(
                get_queries=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    AssertionError("CLI should not call back into query service")
                )
            ),
        )
        return session, fake_result, None

    monkeypatch.setattr(ifds_api, "run_taint_analysis", fake_run_taint_analysis)

    args = _make_args(output_format)
    args.targets = [target]
    exit_code = dataflow_cli.run_taint(args)
    out = capsys.readouterr().out

    assert exit_code == 1
    assert calls == [True]
    if output_format == "json":
        payload = json.loads(out)
        assert payload["function"] == "main"
        assert payload["diagnostics"] == []
        assert payload["findings"][0]["tainted_arguments"] == ["b"]
    else:
        assert "Function: main" in out
        assert "Diagnostics:" not in out
        assert "sink=sink procedure=sinkproc args=[b]" in out


def test_dataflow_cli_falls_back_to_tainted_argument_labels(
    monkeypatch, tmp_path, capsys
):
    target = tmp_path / "sample.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def main():
    sink(source())
""",
        encoding="utf-8",
    )

    fake_result = _DummyResult((), ("source()",))

    def fake_run_taint_analysis(*_args, **_kwargs):
        session = SimpleNamespace(
            compiler=object(),
            diagnostics=(),
            program=SimpleNamespace(
                get_queries=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    AssertionError("CLI should not call back into query service")
                )
            ),
        )
        return session, fake_result, None

    monkeypatch.setattr(ifds_api, "run_taint_analysis", fake_run_taint_analysis)

    args = _make_args("json")
    args.targets = [target]
    exit_code = dataflow_cli.run_taint(args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["diagnostics"] == []
    assert payload["findings"][0]["tainted_arguments"] == ["source()"]


def test_dataflow_cli_forwards_dynamic_model_options(monkeypatch, tmp_path, capsys):
    target = tmp_path / "sample.py"
    target.write_text("def main():\n    return 0\n", encoding="utf-8")

    captured = {}
    fake_result = _EmptyResult()

    def fake_run_taint_analysis(*_args, **kwargs):
        captured.update(kwargs)
        session = SimpleNamespace(compiler=object(), diagnostics=())
        return session, fake_result, None

    monkeypatch.setattr(ifds_api, "run_taint_analysis", fake_run_taint_analysis)

    args = _make_args("json")
    args.collection_mutators = ["append_safe"]
    args.collection_accessors = ["fetch"]
    args.conservative_unresolved_calls = True

    args.targets = [target]
    exit_code = dataflow_cli.run_taint(args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["findings"] == []
    assert captured["collection_mutator_names"] == ["append_safe"]
    assert captured["collection_accessor_names"] == ["fetch"]
    assert captured["conservative_unresolved_call_side_effects"] is True


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_dataflow_cli_emits_session_diagnostics(
    monkeypatch, tmp_path, capsys, output_format
):
    target = tmp_path / "sample.py"
    target.write_text("def main():\n    return 0\n", encoding="utf-8")

    fake_result = _DummyResult((), ("source()",))

    def fake_run_taint_analysis(*_args, **_kwargs):
        session = SimpleNamespace(
            compiler=object(),
            diagnostics=("IFDS session fell back to best-effort mode",),
            program=SimpleNamespace(
                get_queries=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    AssertionError("CLI should not call back into query service")
                )
            ),
        )
        return session, fake_result, None

    monkeypatch.setattr(ifds_api, "run_taint_analysis", fake_run_taint_analysis)

    args = _make_args(output_format)
    args.targets = [target]
    exit_code = dataflow_cli.run_taint(args)
    out = capsys.readouterr().out

    assert exit_code == 1
    if output_format == "json":
        payload = json.loads(out)
        assert payload["diagnostics"] == ["IFDS session fell back to best-effort mode"]
    else:
        assert "Diagnostics:" in out
        assert "IFDS session fell back to best-effort mode" in out
