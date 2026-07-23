from __future__ import annotations

import json
import zipfile
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
    assert out["spdxVersion"] == "SPDX-2.3"
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
            fail_on="low",
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
            fail_on="low",
        )
    )

    out = json.loads(capsys.readouterr().out)
    # Exit code 1 from structural findings (empty RECORD); license policy should pass
    assert exit_code == 1
    kinds = {r["kind"] for r in out["results"]}
    assert "license-not-allowed" not in kinds


def test_audit_fail_threshold_and_json_summary(tmp_path, capsys):
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
            skip_license_audit=True,
            osv_database=[],
            fail_on="high",
        )
    )

    out = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert out["summary"]["components"] == 1
    assert out["summary"]["severity"]["LOW"] == 1
    assert out["results"][0]["id"]


def test_audit_uses_local_osv_database(tmp_path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("demo==1.0\n", encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text(
        json.dumps(
            {
                "id": "PYSEC-CLI-1",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "demo"},
                        "versions": ["1.0"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="audit",
            targets=[str(req)],
            recursive=False,
            exclude="",
            output=None,
            format="json",
            license_policy=None,
            skip_license_audit=True,
            osv_database=[osv],
            fail_on="high",
        )
    )

    out = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert any(item["kind"] == "known-vulnerability" for item in out["results"])


def test_sbom_missing_target_is_reported_as_incomplete(tmp_path, capsys):
    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="sbom",
            targets=[str(tmp_path / "missing")],
            recursive=False,
            exclude="",
            output=None,
            format="cyclonedx-json",
        )
    )

    document = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert document["components"] == []


def test_deterministic_sbom_cli_is_reproducible(tmp_path, capsys, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "42")
    args = SimpleNamespace(
        supply_chain_command="sbom",
        targets=[str(requirements)],
        recursive=False,
        exclude="",
        output=None,
        format="cyclonedx-json",
        deterministic=True,
    )

    assert run_supply_chain(args) == 0
    first = capsys.readouterr().out
    assert run_supply_chain(args) == 0
    second = capsys.readouterr().out

    assert first == second


def test_audit_baseline_suppresses_reviewed_findings(tmp_path, capsys):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    common = {
        "supply_chain_command": "audit",
        "targets": [str(requirements)],
        "recursive": False,
        "exclude": "",
        "output": None,
        "format": "json",
        "license_policy": None,
        "fail_on": "low",
    }

    first_exit = run_supply_chain(SimpleNamespace(**common, write_baseline=baseline))
    capsys.readouterr()
    second_exit = run_supply_chain(SimpleNamespace(**common, baseline=baseline))
    result = json.loads(capsys.readouterr().out)

    assert first_exit == 1
    assert second_exit == 0
    assert result["summary"]["findings"] == 0
    assert result["summary"]["suppressed"] >= 1


def test_audit_sarif_and_atomic_output_failure(tmp_path, capsys):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    sarif_exit = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="audit",
            targets=[str(requirements)],
            recursive=False,
            exclude="",
            output=None,
            format="sarif",
            license_policy=None,
            fail_on="none",
        )
    )
    sarif = json.loads(capsys.readouterr().out)

    output = tmp_path / "sbom.json"
    output.write_text("preserve-me\n", encoding="utf-8")
    schema_exit = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="sbom",
            targets=[str(requirements)],
            recursive=False,
            exclude="",
            output=output,
            format="cyclonedx-json",
            schema=tmp_path / "schema.json",
        )
    )

    assert sarif_exit == 0
    assert sarif["version"] == "2.1.0"
    assert schema_exit == 2
    assert output.read_text(encoding="utf-8") == "preserve-me\n"


def test_directory_audit_requires_provenance_for_discovered_archives(tmp_path, capsys):
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo-1.0.dist-info/METADATA", "Name: demo\nVersion: 1.0\n")
        archive.writestr("demo-1.0.dist-info/RECORD", "")

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="audit",
            targets=[str(tmp_path)],
            recursive=True,
            exclude="",
            output=None,
            format="json",
            skip_license_audit=True,
            require_provenance=True,
            fail_on="high",
        )
    )
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert any(item["kind"] == "missing-provenance" for item in result["results"])
