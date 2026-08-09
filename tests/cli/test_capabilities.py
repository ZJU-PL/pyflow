from __future__ import annotations

import json
from argparse import Namespace

from pyflow.cli.capabilities import run_capabilities


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
    direct = next(
        finding
        for finding in payload["findings"]
        if finding["report_kind"] == "direct"
    )
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
