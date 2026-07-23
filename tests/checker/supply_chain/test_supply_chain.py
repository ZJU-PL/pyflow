from __future__ import annotations

import csv
import hashlib
import json
import stat
import zipfile
from base64 import urlsafe_b64encode

from pyflow.checker.supply_chain import (
    ScanLimits,
    audit_license_policy,
    audit_vulnerabilities,
    build_cyclonedx_document,
    build_requirements_text,
    build_spdx_document,
    scan_targets,
)


def test_sbom_from_dist_info_metadata(tmp_path):
    dist_info = tmp_path / "Demo_Pkg-1.2.3.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: Demo_Pkg\nVersion: 1.2.3\nSummary: Demo package\nLicense: MIT\n",
        encoding="utf-8",
    )
    _write_record(dist_info, [dist_info / "METADATA"])

    scan = scan_targets([tmp_path], recursive=True)
    doc = build_cyclonedx_document(scan)

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert doc["components"] == [
        {
            "type": "library",
            "name": "demo-pkg",
            "purl": "pkg:pypi/demo-pkg@1.2.3",
            "bom-ref": "pkg:pypi/demo-pkg@1.2.3",
            "version": "1.2.3",
            "description": "Demo package",
            "licenses": [{"license": {"id": "MIT"}}],
        }
    ]


def test_sbom_from_requirements_and_pyproject(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=3\nhttps://example.invalid/pkg.whl\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
dependencies = ["Django==5.0.1"]

[project.optional-dependencies]
dev = ["pytest"]
""",
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path], recursive=True)

    purls = {component["purl"] for component in scan.components}
    assert "pkg:pypi/requests@2.31.0" in purls
    assert "pkg:pypi/flask" in purls
    assert "pkg:pypi/django@5.0.1" in purls
    assert "pkg:pypi/pytest" in purls
    assert any(finding.kind == "remote-requirement" for finding in scan.findings)


def test_archive_metadata_and_suspicious_entries_are_scanned(tmp_path):
    wheel = tmp_path / "demo-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "demo-1.0.0.dist-info/METADATA",
            "Name: demo\nVersion: 1.0.0\n",
        )
        archive.writestr("demo-1.0.0.dist-info/RECORD", "")
        archive.writestr("../escape.py", "x = 1\n")

    scan = scan_targets([wheel], recursive=True)

    assert any(
        component["purl"] == "pkg:pypi/demo@1.0.0" for component in scan.components
    )
    assert any(finding.kind == "archive-parent-reference" for finding in scan.findings)
    assert all(
        "pyflow_supply_chain_" not in finding.location for finding in scan.findings
    )
    assert any(
        "!/demo-1.0.0.dist-info/" in finding.location for finding in scan.findings
    )


def test_record_audit_reports_invalid_hash(tmp_path):
    dist_info = tmp_path / "demo-1.0.0.dist-info"
    dist_info.mkdir()
    metadata = dist_info / "METADATA"
    metadata.write_text("Name: demo\nVersion: 1.0.0\n", encoding="utf-8")
    (dist_info / "RECORD").write_text(
        "demo-1.0.0.dist-info/METADATA,sha256=not-real,1\n",
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path], recursive=True)

    assert any(finding.kind == "record-invalid-hash" for finding in scan.findings)


def test_build_requirements_text_formats_components(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=3\n", encoding="utf-8"
    )
    scan = scan_targets([tmp_path], recursive=True)
    text = build_requirements_text(scan)
    assert "requests==2.31.0" in text
    assert "flask" in text
    assert "\n" in text


def test_build_spdx_document_outputs_valid_structure(tmp_path):
    dist_info = tmp_path / "Demo_Pkg-1.2.3.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: Demo_Pkg\nVersion: 1.2.3\nLicense: MIT\n",
        encoding="utf-8",
    )
    _write_record(dist_info, [dist_info / "METADATA"])

    scan = scan_targets([tmp_path], recursive=True)
    doc = build_spdx_document(scan)

    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["documentNamespace"].startswith("https://pyflow.dev/spdx/")
    assert len(doc["packages"]) == 1
    pkg = doc["packages"][0]
    assert pkg["name"] == "demo-pkg"
    assert pkg["versionInfo"] == "1.2.3"
    assert pkg["licenseDeclared"] == "MIT"
    assert pkg["SPDXID"].startswith("SPDXRef-")


def test_audit_license_policy_reports_unlicensed_and_disallowed(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=3\n", encoding="utf-8"
    )
    scan = scan_targets([tmp_path], recursive=True)
    findings = audit_license_policy(scan)

    kinds = {f.kind for f in findings}
    assert "license-not-declared" in kinds
    assert all(f.location.startswith("pkg:pypi/") for f in findings)


def test_audit_license_policy_allows_custom_list(tmp_path):
    dist_info = tmp_path / "pkg-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: pkg\nVersion: 1.0.0\nLicense: MIT\n",
        encoding="utf-8",
    )
    _write_record(dist_info, [dist_info / "METADATA"])

    scan = scan_targets([tmp_path], recursive=True)
    findings = audit_license_policy(scan, allowed_licenses=["MIT"])
    assert not findings


def test_audit_license_policy_flags_disallowed_license(tmp_path):
    dist_info = tmp_path / "pkg-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: pkg\nVersion: 1.0.0\nLicense: Proprietary\n",
        encoding="utf-8",
    )
    _write_record(dist_info, [dist_info / "METADATA"])

    scan = scan_targets([tmp_path], recursive=True)
    findings = audit_license_policy(scan, allowed_licenses=["MIT"])
    assert any(f.kind == "license-not-allowed" for f in findings)


def test_non_recursive_scan_does_not_descend(tmp_path):
    (tmp_path / "requirements.txt").write_text("top==1\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "requirements.txt").write_text("hidden==2\n", encoding="utf-8")

    shallow = scan_targets([tmp_path], recursive=False)
    recursive = scan_targets([tmp_path], recursive=True)

    assert {item["name"] for item in shallow.components} == {"top"}
    assert {item["name"] for item in recursive.components} == {"hidden", "top"}


def test_requirements_includes_hashes_and_index_risks(tmp_path):
    digest = "a" * 64
    (tmp_path / "base.in").write_text(
        "safe==1.0 \\\n    --hash=sha256:" + digest + "\n",
        encoding="utf-8",
    )
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "-r base.in\n"
        "--extra-index-url http://packages.example/simple\n"
        "floating>=2\n",
        encoding="utf-8",
    )

    scan = scan_targets([requirements])

    safe = next(item for item in scan.components if item["name"] == "safe")
    assert safe["hashes"] == [{"alg": "SHA-256", "content": digest}]
    kinds = {finding.kind for finding in scan.findings}
    assert "multiple-package-indexes" in kinds
    assert "insecure-package-index" in kinds
    assert "unpinned-requirement" in kinds
    assert "requirement-missing-hash" not in {
        finding.kind
        for finding in scan.findings
        if finding.details.get("requirement", "").startswith("safe")
    }


def test_archive_limits_backslashes_and_zip_symlinks(tmp_path):
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("..\\escape.py", "bad")
        link = zipfile.ZipInfo("linked.py")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target.py")
        archive.writestr("third.txt", "x")

    limited = scan_targets([wheel], limits=ScanLimits(max_archive_members=2))
    full = scan_targets([wheel])

    assert any(f.kind == "archive-member-limit" for f in limited.findings)
    assert any(f.kind == "archive-parent-reference" for f in full.findings)
    assert any(f.kind == "archive-link-entry" for f in full.findings)


def test_record_audit_checks_size_without_claiming_other_distributions(tmp_path):
    first = tmp_path / "first-1.0.dist-info"
    second = tmp_path / "second-1.0.dist-info"
    first.mkdir()
    second.mkdir()
    first_metadata = first / "METADATA"
    second_metadata = second / "METADATA"
    first_metadata.write_text("Name: first\nVersion: 1.0\n", encoding="utf-8")
    second_metadata.write_text("Name: second\nVersion: 1.0\n", encoding="utf-8")
    _write_record(first, [first_metadata])
    _write_record(second, [second_metadata])
    rows = list(csv.reader((first / "RECORD").read_text().splitlines()))
    rows[0][2] = "999"
    with (first / "RECORD").open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows(rows)

    scan = scan_targets([tmp_path], recursive=True)

    assert any(f.kind == "record-size-mismatch" for f in scan.findings)
    assert not any(
        f.kind == "record-unlisted-file" and "second-1.0.dist-info" in f.location
        for f in scan.findings
    )


def test_pyproject_builds_dependency_graph_and_normalizes_poetry_constraints(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo-app"
version = "1.0"
dependencies = ["requests==2.31.0"]

[build-system]
requires = ["setuptools>=70"]

[tool.poetry.dependencies]
click = "^8.1"
""",
        encoding="utf-8",
    )

    scan = scan_targets([pyproject])
    document = build_cyclonedx_document(scan)

    assert {item["name"] for item in scan.components} == {
        "click",
        "demo-app",
        "requests",
        "setuptools",
    }
    assert any(item["ref"] == "pkg:pypi/demo-app@1.0" for item in scan.dependencies)
    assert document["dependencies"] == list(scan.dependencies)
    click = next(item for item in scan.components if item["name"] == "click")
    property_values = {prop["value"] for prop in click["properties"]}
    assert "runtime" in property_values
    assert any(">=8.1" in value and "<9.0.0" in value for value in property_values)


def test_pylock_and_local_osv_database(tmp_path):
    lock = tmp_path / "pylock.toml"
    lock.write_text(
        """
lock-version = "1.0"

[[packages]]
name = "demo"
version = "1.5"

[packages.archive]
url = "https://files.example/demo-1.5.tar.gz"

[packages.archive.hashes]
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
        encoding="utf-8",
    )
    osv = tmp_path / "osv.json"
    osv.write_text(
        json.dumps(
            {
                "id": "PYSEC-TEST-1",
                "summary": "Demo vulnerability",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "demo"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "2.0"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    scan = scan_targets([lock])
    findings = audit_vulnerabilities(scan, [osv])

    assert scan.components[0]["purl"] == "pkg:pypi/demo@1.5"
    assert len(findings) == 1
    assert findings[0].kind == "known-vulnerability"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].details["fixed_versions"] == ["2.0"]


def test_setup_script_reports_install_time_execution(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text(
        "import subprocess\n"
        "subprocess.run(['curl', 'https://example.invalid'])\n"
        "setup(install_requires=['requests'])\n",
        encoding="utf-8",
    )

    scan = scan_targets([setup])

    assert any(
        finding.kind == "install-script-dangerous-behavior"
        and finding.severity == "HIGH"
        for finding in scan.findings
    )
    assert any(component["name"] == "requests" for component in scan.components)


def _write_record(dist_info, files):
    record = dist_info / "RECORD"
    rows = []
    for path in files:
        digest = urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest())
        rows.append(
            [
                str(path.relative_to(dist_info.parent)),
                f"sha256={digest.decode('ascii').rstrip('=')}",
                str(path.stat().st_size),
            ]
        )
    rows.append([str(record.relative_to(dist_info.parent)), "", ""])
    with record.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows(rows)
