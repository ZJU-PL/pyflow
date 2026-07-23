from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

from pyflow.cli.supply_chain import run_supply_chain


def test_supply_chain_sbom_outputs_cyclonedx(tmp_path, capsys):
    dist_info = tmp_path / "demo-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: demo\nVersion: 1.0.0\n", encoding="utf-8"
    )
    (dist_info / "RECORD").write_text("", encoding="utf-8")

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="sbom",
            targets=[str(tmp_path)],
            recursive=True,
            exclude="",
            output=None,
            format="cyclonedx-json",
        )
    )

    out = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert out["bomFormat"] == "CycloneDX"
    assert out["components"][0]["purl"] == "pkg:pypi/demo@1.0.0"


def test_supply_chain_audit_returns_nonzero_for_findings(tmp_path, capsys):
    dist_info = tmp_path / "demo-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: demo\nVersion: 1.0.0\n", encoding="utf-8"
    )

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="audit",
            targets=[str(tmp_path)],
            recursive=True,
            exclude="",
            output=None,
            format="json",
        )
    )

    out = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert out["results"][0]["kind"] == "missing-record"


def test_supply_chain_sbom_writes_to_output_file(tmp_path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n", encoding="utf-8")
    output = tmp_path / "sbom.json"

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="sbom",
            targets=[str(req)],
            recursive=False,
            exclude="",
            output=output,
            format="cyclonedx-json",
        )
    )

    assert exit_code == 0
    assert capsys.readouterr().out == ""
    assert json.loads(output.read_text(encoding="utf-8"))["components"][0]["purl"] == (
        "pkg:pypi/requests@2.31.0"
    )


def test_sbom_format_requirements_outputs_pins(tmp_path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n", encoding="utf-8")

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="sbom",
            targets=[str(req)],
            recursive=False,
            exclude="",
            output=None,
            format="requirements",
        )
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "requests==2.31.0" in out


def test_sbom_format_spdx_json_outputs_valid(tmp_path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n", encoding="utf-8")

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="sbom",
            targets=[str(req)],
            recursive=False,
            exclude="",
            output=None,
            format="spdx-json",
        )
    )

    out = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert out["spdxVersion"] == "SPDX-2.2"
    assert len(out["packages"]) == 1
    assert out["packages"][0]["name"] == "requests"


def test_audit_with_license_policy_adds_findings(tmp_path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n", encoding="utf-8")

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="audit",
            targets=[str(req)],
            recursive=False,
            exclude="",
            output=None,
            format="json",
            license_policy=None,
        )
    )

    out = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    kinds = {r["kind"] for r in out["results"]}
    assert "license-not-declared" in kinds


def test_audit_with_custom_license_policy_file(tmp_path, capsys):
    dist_info = tmp_path / "pkg-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: pkg\nVersion: 1.0.0\nLicense: MIT\n", encoding="utf-8"
    )
    (dist_info / "RECORD").write_text("", encoding="utf-8")

    policy = tmp_path / "policy.json"
    policy.write_text('["MIT"]\n', encoding="utf-8")

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="audit",
            targets=[str(tmp_path)],
            recursive=True,
            exclude="",
            output=None,
            format="json",
            license_policy=policy,
        )
    )

    out = json.loads(capsys.readouterr().out)
    # Exit code 1 from structural findings (empty RECORD); license policy should pass
    assert exit_code == 1
    kinds = {r["kind"] for r in out["results"]}
    assert "license-not-allowed" not in kinds
