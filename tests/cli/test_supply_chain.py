from __future__ import annotations

import json
import os
import stat
import zipfile
from types import SimpleNamespace

from pyflow.cli.supply_chain import run_supply_chain


def test_sbom_incomplete_inventory_explains_exit_code_without_corrupting_json(tmp_path, capsys):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("demo>=1\n")
    args = SimpleNamespace(
        supply_chain_command="sbom",
        targets=[str(manifest)],
        recursive=False,
        exclude="",
        output=None,
        format="cyclonedx-json",
        allow_incomplete=False,
        exit_code_policy="strict",
    )
    assert run_supply_chain(args) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["bomFormat"] == "CycloneDX"
    assert "--allow-incomplete" in captured.err
    assert "exit code 2" in captured.err
    args.allow_incomplete = True
    assert run_supply_chain(args) == 2
    assert "mutually exclusive" in capsys.readouterr().err

    args.exit_code_policy = "report"
    assert run_supply_chain(args) == 0
    assert capsys.readouterr().err == ""


def test_supply_chain_sbom_outputs_cyclonedx(tmp_path, capsys):
    dist_info = tmp_path / "demo-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: demo\nVersion: 1.0.0\n", encoding="utf-8")
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


def test_unpinned_sbom_is_successful_report_with_completeness_disclosed(tmp_path, capsys):
    from argparse import ArgumentParser
    from pyflow.cli.supply_chain import add_supply_chain_parser

    manifest = tmp_path / "requirements.txt"
    manifest.write_text("demo>=1\n")
    parser = ArgumentParser()
    add_supply_chain_parser(parser.add_subparsers())
    args = parser.parse_args(["supply-chain", "sbom", str(manifest)])
    assert args.exit_code_policy == "report"
    assert run_supply_chain(args) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert {"name": "pyflow:inventory-complete", "value": "false"} in document["metadata"][
        "properties"
    ]
    assert "--require-complete" in captured.err
    for option in (["--require-complete"], ["--exit-code-policy", "strict"]):
        args = parser.parse_args(["supply-chain", "sbom", str(manifest), *option])
        assert run_supply_chain(args) == 2
        json.loads(capsys.readouterr().out)


def test_supply_chain_can_require_external_schema_validation(tmp_path, capsys):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\n", encoding="utf-8")

    exit_code = run_supply_chain(
        SimpleNamespace(
            supply_chain_command="sbom",
            targets=[str(requirements)],
            recursive=False,
            exclude="",
            output=None,
            format="cyclonedx-json",
            deterministic=True,
            schema=None,
            require_schema_validation=True,
            allow_incomplete=True,
        )
    )

    assert exit_code == 2
    assert "requires --schema" in capsys.readouterr().err


def test_supply_chain_audit_returns_nonzero_for_findings(tmp_path, capsys):
    dist_info = tmp_path / "demo-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: demo\nVersion: 1.0.0\n", encoding="utf-8")

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


def test_audit_does_not_infer_missing_licenses_from_requirements(tmp_path, capsys):
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
    assert exit_code == 1  # The independently valid missing-artifact-hash warning remains.
    kinds = {r["kind"] for r in out["results"]}
    assert "license-not-declared" not in kinds
    assert "requirement-missing-hash" in kinds


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


def test_vex_and_reachability_warn_without_osv_database(tmp_path, capsys):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    common = {
        "supply_chain_command": "audit",
        "targets": [str(requirements)],
        "recursive": False,
        "exclude": "",
        "output": None,
        "format": "json",
        "license_policy": None,
        "fail_on": "none",
    }

    assert run_supply_chain(SimpleNamespace(**common, vex=[tmp_path / "nope.json"])) == 0
    assert "--vex has no effect without --osv-database" in capsys.readouterr().err

    assert run_supply_chain(SimpleNamespace(**common, reachability=True)) == 0
    assert "--reachability has no effect without --osv-database" in capsys.readouterr().err


def test_cli_keeps_declared_markers_unless_environment_is_explicit(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text(
        'old==1; python_version < "3.8"\nnew==1; python_version >= "3.8"\n',
        encoding="utf-8",
    )
    args = SimpleNamespace(
        supply_chain_command="sbom",
        targets=[str(tmp_path)],
        recursive=True,
        exclude="",
        output=None,
        format="requirements",
        allow_incomplete=False,
        exit_code_policy="report",
    )

    assert run_supply_chain(args) == 0
    output = capsys.readouterr().out
    assert "new==1" in output
    assert "old==1" in output

    args.python_version = "3.10"
    assert run_supply_chain(args) == 0
    output = capsys.readouterr().out
    assert "new==1" in output
    assert "old==1" not in output


def test_cli_can_disable_default_excludes(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "requirements.txt").write_text("hidden==1\n", encoding="utf-8")
    output = tmp_path / "sbom.json"
    args = SimpleNamespace(
        supply_chain_command="sbom",
        targets=[str(tmp_path)],
        recursive=True,
        exclude="",
        output=output,
        format="cyclonedx-json",
        allow_incomplete=False,
        exit_code_policy="report",
        no_default_excludes=True,
    )

    assert run_supply_chain(args) == 0
    assert "hidden" in output.read_text(encoding="utf-8")


def test_cli_writes_to_dev_null_without_replacing_the_device(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    args = SimpleNamespace(
        supply_chain_command="sbom",
        targets=[str(tmp_path)],
        recursive=True,
        exclude="",
        output="/dev/null",
        format="cyclonedx-json",
        allow_incomplete=True,
        exit_code_policy="report",
    )

    assert run_supply_chain(args) == 0
    assert os.path.exists("/dev/null")
    assert stat.S_ISCHR(os.stat("/dev/null").st_mode)


def test_cli_require_provenance_without_archives_fails(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    args = SimpleNamespace(
        supply_chain_command="audit",
        targets=[str(empty)],
        recursive=True,
        exclude="",
        output=None,
        format="text",
        fail_on="high",
        require_provenance=True,
    )

    assert run_supply_chain(args) == 1
    assert "missing-provenance" in capsys.readouterr().out
