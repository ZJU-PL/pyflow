"""Threat-model arguments used by the synthetic benchmark."""

from types import SimpleNamespace

import pytest

from evaluation.pysastbench import bench_micro


@pytest.mark.parametrize("engine", ["ast-scanner", "ast-dataflow", "cpg", "ifds"])
def test_public_parameter_source_is_passed_to_dataflow_engines(monkeypatch, tmp_path, engine):
    commands = []

    def run(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(bench_micro.subprocess, "run", run)
    bench_micro._run_one(engine, tmp_path / "case.py", tmp_path, tmp_path / "pyflow", 45)

    command = commands[0]
    assert ("--entry-source-kind" in command) == (engine in {"ast-dataflow", "ifds"})
    if "--entry-source-kind" in command:
        assert command[command.index("--entry-source-kind") + 1] == "user_input"


def test_public_parameter_source_can_be_disabled(monkeypatch, tmp_path):
    commands = []

    def run(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(bench_micro.subprocess, "run", run)
    bench_micro._run_one("ifds", tmp_path / "case.py", tmp_path, tmp_path / "pyflow", 45, "none")

    assert "--entry-source-kind" not in commands[0]
