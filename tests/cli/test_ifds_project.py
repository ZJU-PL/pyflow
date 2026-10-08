"""Project defaults, entry selection and aggregate completeness regressions."""

import argparse
import json

import pytest

from pyflow.cli.security import command
from pyflow.cli.security.parser import add_security_parser


def parse(*argv):
    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    return parser.parse_args(["security", *map(str, argv)])


def project(tmp_path):
    for name in ("main.py", "app.py"):
        (tmp_path / name).write_text("print('entry')\n")
    return tmp_path


def test_project_analyzes_all_discovered_entries(tmp_path, monkeypatch):
    root = project(tmp_path)
    calls = []

    def run(targets, args):
        calls.append(args.entry)
        return {
            "entry": args.entry.name,
            "status": "complete",
            "findings": [],
            "diagnostics": [],
            "termination_reason": None,
        }

    monkeypatch.setattr(command, "_run_ifds_entry", run)
    report = command._run_ifds([str(root)], parse(root, "--engine", "ifds"))
    assert calls == [root / "main.py", root / "app.py"]
    assert report["entries"] == ["main.py", "app.py"]
    assert report["status"] == "complete"


@pytest.mark.parametrize("status", ["partial", "failed", "invalid"])
def test_project_preserves_incomplete_entries(tmp_path, monkeypatch, status):
    root = project(tmp_path)

    def run(targets, args):
        return {
            "entry": args.entry.name,
            "status": status if args.entry.name == "app.py" else "complete",
            "findings": [{"sink_name": "sink"}],
            "diagnostics": ["note"],
            "termination_reason": "limit" if args.entry.name == "app.py" else None,
        }

    monkeypatch.setattr(command, "_run_ifds_entry", run)
    report = command._run_ifds([str(root)], parse(root, "--engine", "ifds"))
    assert report["status"] == status
    assert report["termination_reason"] == "app.py: limit"
    assert len(report["findings"]) == 1
    assert len(report["entry_results"]) == 2


def test_repeatable_entries_override_discovery_and_deduplicate(tmp_path):
    root = project(tmp_path)
    args = parse(root, "--entry", "app.py", "--entry", "app.py")
    assert command._resolve_ifds_entry_files([root], args.entry) == (root / "app.py",)
    with pytest.raises(ValueError, match="outside project root"):
        command._resolve_ifds_entry_files([root], ["../outside.py"])


def test_project_config_and_cli_precedence(tmp_path):
    root = project(tmp_path)
    (root / "pyflow.json").write_text(
        json.dumps(
            {
                "entry": ["app.py"],
                "analysis": "nullness",
                "sources": ["input"],
                "solver_options": {
                    "max_seconds": 9,
                    "max_path_edges": 50,
                    "max_call_string_depth": 2,
                },
            }
        )
    )
    args = parse(root, "--engine", "ifds", "--analysis", "taint", "--ifds-max-seconds", "3")
    command._apply_ifds_config(args)
    assert args.analysis == "taint"
    assert args.entry == ["app.py"]
    assert args.sources == ["input"]
    options = command._ifds_solver_options(args)
    assert options.max_seconds == 3
    assert options.max_propagated_path_edges == 50
    assert options.max_call_string_depth == 2


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"entry": 7},
        {"sources": "input"},
        {"analysis": "unknown"},
        {"solver_options": []},
        {"solver_options": {"max_seconds": -1}},
    ],
)
def test_invalid_project_config_is_usage_error(tmp_path, data):
    (tmp_path / "pyflow.json").write_text(json.dumps(data))
    args = parse(tmp_path, "--engine", "ifds")
    with pytest.raises(SystemExit) as error:
        command._apply_ifds_config(args)
    assert error.value.code == 2


def test_other_engines_do_not_load_ifds_project_config(tmp_path):
    (tmp_path / "pyflow.json").write_text("invalid")
    command._apply_ifds_config(parse(tmp_path))


@pytest.mark.parametrize("output_format", ["json", "sarif"])
def test_real_project_report(tmp_path, capsys, output_format):
    for name in ("main.py", "app.py"):
        (tmp_path / name).write_text(
            "def source():\n    return 'value'\n"
            "def sink(value):\n    return value\n"
            "sink(source())\n"
        )
    (tmp_path / "pyflow.json").write_text(
        json.dumps(
            {
                "sources": ["source"],
                "sinks": ["sink"],
            }
        )
    )
    args = parse(tmp_path, "--engine", "ifds", "--format", output_format)
    assert command.run_security(args) == 1
    report = json.loads(capsys.readouterr().out)
    if output_format == "json":
        assert report["entries"] == ["main.py", "app.py"]
        assert len(report["findings"]) == 2
        assert report["status"] == "complete"
    else:
        assert report["version"] == "2.1.0"
        assert len(report["runs"][0]["results"]) == 2


def test_packaging_entries_take_precedence_and_deduplicate_files(tmp_path):
    project(tmp_path)
    (tmp_path / "pyproject.toml").write_text(
        '[project.scripts]\nfirst = "app:first"\n' 'second = "app:second"\nthird = "other:run"\n'
    )
    (tmp_path / "other.py").write_text("pass\n")
    assert command._resolve_ifds_entry_files([tmp_path], None) == (
        tmp_path / "app.py",
        tmp_path / "other.py",
    )


def test_explicit_config_replaces_defaults_and_resolves_rule_paths(tmp_path):
    root = project(tmp_path)
    (root / "pyflow.json").write_text(json.dumps({"analysis": "nullness"}))
    configs = root / "configs"
    configs.mkdir()
    config = configs / "custom.json"
    config.write_text(json.dumps({"analysis": "typestate", "registry_path": ["rules.json"]}))
    args = parse(root, "--engine", "ifds", "--config", config)
    command._apply_ifds_config(args)
    assert args.analysis == "typestate"
    assert args.registry_path == [str(configs / "rules.json")]
