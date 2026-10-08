from __future__ import annotations

import json
from argparse import ArgumentParser, Namespace

import pytest

from pyflow.cli.capabilities import add_capabilities_parser, run_capabilities


def test_capabilities_cli_json(tmp_path, capsys) -> None:
    target = tmp_path / "main.py"
    target.write_text(
        "import subprocess\nsubprocess.run(['id'])\n",
        encoding="utf-8",
    )
    args = Namespace(
        input_path=str(target),
        entry=None,
        context_depth=1,
        import_depth=-1,
        format="json",
        output=None,
    )

    assert run_capabilities(args) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "complete"
    direct = next(finding for finding in payload["findings"] if finding["report_kind"] == "direct")
    assert direct["capability"] == "process.execute"
    assert direct["location"]["line"] == 2


def test_capabilities_cli_sarif(tmp_path, capsys) -> None:
    target = tmp_path / "main.py"
    target.write_text("eval('1 + 1')\n", encoding="utf-8")
    args = Namespace(
        input_path=str(target),
        entry=None,
        context_depth=1,
        import_depth=-1,
        format="sarif",
        output=None,
    )

    assert run_capabilities(args) == 1
    payload = json.loads(capsys.readouterr().out)
    result = payload["runs"][0]["results"][0]
    assert result["ruleId"] == "code.execute"
    assert result["properties"]["reportKind"] == "runtime_guarded"


def test_capabilities_cli_extends_project_model(tmp_path, capsys) -> None:
    target = tmp_path / "main.py"
    target.write_text("import acme\nacme.audit()\n", encoding="utf-8")
    model = tmp_path / "model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "patterns": [
                    {
                        "capability": "company.audit",
                        "category": "company",
                        "operation": "call",
                        "access_paths": ["acme.audit"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    args = Namespace(
        input_path=str(target),
        entry=None,
        context_depth=1,
        context_policy=None,
        import_depth=-1,
        format="json",
        output=None,
        capability_model=[model],
        no_public_exports=False,
    )

    assert run_capabilities(args) == 1
    payload = json.loads(capsys.readouterr().out)
    assert any(finding["capability"] == "company.audit" for finding in payload["findings"])


def test_capabilities_cli_applies_external_effect_model(tmp_path, capsys) -> None:
    target = tmp_path / "main.py"
    target.write_text(
        "import vendor\n"
        "from subprocess import run\n"
        "callback = vendor.identity(run)\n"
        "callback(['id'])\n",
        encoding="utf-8",
    )
    model = tmp_path / "effects.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "patterns": [],
                "effects": [
                    {
                        "kind": "return_argument",
                        "arguments": [0],
                        "access_paths": ["vendor.identity"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    args = Namespace(
        input_path=str(target),
        entry=None,
        context_depth=1,
        context_policy=None,
        import_depth=-1,
        format="json",
        output=None,
        capability_model=[model],
        no_public_exports=False,
    )

    assert run_capabilities(args) == 1
    payload = json.loads(capsys.readouterr().out)
    assert any(
        finding["capability"] == "process.execute"
        and finding["report_kind"] == "direct"
        and finding["location"]["line"] == 4
        for finding in payload["findings"]
    )


@pytest.mark.parametrize("include_boundaries", [False, True])
def test_callable_boundary_reports_are_opt_in(tmp_path, capsys, include_boundaries) -> None:
    target = tmp_path / "main.py"
    target.write_text(
        "from subprocess import run\n"
        "def factory():\n"
        "    return run\n"
        "_callback = factory()\n",
        encoding="utf-8",
    )
    parser = ArgumentParser()
    add_capabilities_parser(parser.add_subparsers(dest="command"))
    argv = ["capabilities", str(target), "--format", "json", "--no-public-exports"]
    if include_boundaries:
        argv.append("--report-callable-boundaries")

    assert run_capabilities(parser.parse_args(argv)) == int(include_boundaries)
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "complete"
    assert any(finding["escape_kind"] == "return" for finding in payload["findings"]) == (
        include_boundaries
    )


def test_indirect_sarif_reports_potential_transfer_as_note(tmp_path, capsys) -> None:
    target = tmp_path / "main.py"
    target.write_text(
        "from subprocess import run\nimport plugin_api\nplugin_api.register(run)\n",
        encoding="utf-8",
    )
    parser = ArgumentParser()
    add_capabilities_parser(parser.add_subparsers(dest="command"))
    args = parser.parse_args(["capabilities", str(target), "--format", "sarif"])
    assert run_capabilities(args) == 1
    payload = json.loads(capsys.readouterr().out)
    indirect = [
        result
        for result in payload["runs"][0]["results"]
        if result["properties"]["reportKind"] == "indirect"
    ]
    assert indirect
    assert all(result["level"] == "note" for result in indirect)
    assert all("potential capability transfer" in result["message"]["text"] for result in indirect)
