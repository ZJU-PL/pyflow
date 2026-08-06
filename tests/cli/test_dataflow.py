from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import pyflow.analysis.ifds.api as ifds_api
import pyflow.cli.security as security_cli


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
        entry=None,
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
def test_security_cli_uses_single_taint_result_path(
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
    exit_code = security_cli.run_security(args)
    out = capsys.readouterr().out

    assert exit_code == 1
    assert calls == [True]
    if output_format == "json":
        payload = json.loads(out)
        assert payload["entry"] == str(target)
        assert payload["diagnostics"] == []
        assert payload["findings"][0]["tainted_arguments"] == ["b"]
    else:
        assert f"Entry: {target}" in out
        assert "Diagnostics:" not in out
        assert "sink=sink procedure=sinkproc args=[b]" in out


def test_security_cli_falls_back_to_tainted_argument_labels(
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
    exit_code = security_cli.run_security(args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["diagnostics"] == []
    assert payload["findings"][0]["tainted_arguments"] == ["source()"]


def test_security_cli_forwards_dynamic_model_options(monkeypatch, tmp_path, capsys):
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
    args.ifds_unknown_call_policy = "havoc"
    args.conservative_unresolved_calls = True

    args.targets = [target]
    exit_code = security_cli.run_security(args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["findings"] == []
    assert captured["collection_mutator_names"] == ["append_safe"]
    assert captured["collection_accessor_names"] == ["fetch"]
    assert captured["unknown_call_policy"] == "havoc"
    assert captured["conservative_unresolved_call_side_effects"] is True


def test_security_cli_defaults_to_dropping_unknown_call_results(
    monkeypatch, tmp_path, capsys
):
    target = tmp_path / "sample.py"
    target.write_text("def main():\n    return 0\n", encoding="utf-8")
    captured = {}

    def fake_run_taint_analysis(*_args, **kwargs):
        captured.update(kwargs)
        session = SimpleNamespace(compiler=object(), diagnostics=())
        return session, _EmptyResult(), None

    monkeypatch.setattr(ifds_api, "run_taint_analysis", fake_run_taint_analysis)
    args = _make_args("json")
    args.targets = [target]

    assert security_cli.run_security(args) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []
    assert captured["unknown_call_policy"] == "drop"


def test_security_cli_auto_detects_directory_entry(monkeypatch, tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    entry = project / "main.py"
    entry.write_text("print('main')\n", encoding="utf-8")

    captured = {}

    def fake_run_taint_analysis(*_args, **kwargs):
        captured.update(kwargs)
        session = SimpleNamespace(compiler=object(), diagnostics=())
        return session, _EmptyResult(), None

    monkeypatch.setattr(ifds_api, "run_taint_analysis", fake_run_taint_analysis)

    args = _make_args("json")
    args.targets = [project]

    assert security_cli.run_security(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["entry"] == "main.py"
    assert captured["entry_file"] == entry.resolve()


def test_security_cli_accepts_explicit_directory_entry(monkeypatch, tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    entry = project / "train.py"
    entry.write_text("print('train')\n", encoding="utf-8")

    captured = {}

    def fake_run_taint_analysis(*_args, **kwargs):
        captured.update(kwargs)
        session = SimpleNamespace(compiler=object(), diagnostics=())
        return session, _EmptyResult(), None

    monkeypatch.setattr(ifds_api, "run_taint_analysis", fake_run_taint_analysis)

    args = _make_args("json")
    args.targets = [project]
    args.entry = "train.py"

    assert security_cli.run_security(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["entry"] == "train.py"
    assert captured["entry_file"] == entry.resolve()


def test_security_cli_forwards_typestate_protocol_options(
    monkeypatch, tmp_path, capsys
):
    target = tmp_path / "sample.py"
    target.write_text("def main():\n    return 0\n", encoding="utf-8")

    captured = {}
    fake_finding = SimpleNamespace(
        kind="lock_leak",
        operation_name="main",
        resource_label="lock",
        protocol="lock",
        state="locked",
        node=SimpleNamespace(
            kind="exit",
            procedure=SimpleNamespace(code=SimpleNamespace(name="main")),
        ),
    )
    fake_result = SimpleNamespace(
        findings=(fake_finding,),
        statistics=SimpleNamespace(processed_path_edges=1),
    )

    def fake_run_typestate_analysis(*_args, **kwargs):
        captured.update(kwargs)
        session = SimpleNamespace(compiler=object(), diagnostics=())
        return session, fake_result

    monkeypatch.setattr(ifds_api, "run_typestate_analysis", fake_run_typestate_analysis)

    args = _make_args("json")
    args.analysis = "typestate"
    args.typestate_protocol = ["python-builtins", "lock"]
    args.framework = ["network"]
    args.collection_mutators = ["append_safe"]
    args.collection_accessors = ["fetch"]

    args.targets = [target]
    exit_code = security_cli.run_security(args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["analysis"] == "typestate"
    assert payload["findings"][0]["protocol"] == "lock"
    assert captured["enabled_protocols"] == ["python-builtins", "lock"]
    assert captured["registry_frameworks"] == ["network"]
    assert captured["collection_mutator_names"] == ["append_safe"]
    assert captured["collection_accessor_names"] == ["fetch"]


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_security_cli_emits_session_diagnostics(
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
    exit_code = security_cli.run_security(args)
    out = capsys.readouterr().out

    assert exit_code == 1
    if output_format == "json":
        payload = json.loads(out)
        assert payload["diagnostics"] == ["IFDS session fell back to best-effort mode"]
    else:
        assert "Diagnostics:" in out
        assert "IFDS session fell back to best-effort mode" in out
