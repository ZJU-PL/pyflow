from __future__ import annotations

from pyflow.checker.supply_chain import audit_license_policy, scan_targets

from ._helpers import write_record as _write_record


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


def test_license_policy_evaluates_spdx_boolean_and_exception_semantics():
    scan = type("Scan", (), {})()
    scan.components = (
        {
            "name": "choice",
            "purl": "pkg:pypi/choice@1",
            "licenses": [{"expression": "MIT OR GPL-3.0-only"}],
        },
        {
            "name": "combined",
            "purl": "pkg:pypi/combined@1",
            "licenses": [{"expression": "MIT AND GPL-3.0-only"}],
        },
        {
            "name": "exception",
            "purl": "pkg:pypi/exception@1",
            "licenses": [{"expression": "Apache-2.0 WITH LLVM-exception"}],
        },
    )

    findings = audit_license_policy(
        scan,
        allowed_licenses=["MIT", "Apache-2.0"],
        allowed_exceptions=["LLVM-exception"],
    )

    assert [finding.location for finding in findings] == ["pkg:pypi/combined@1"]
    assert findings[0].details["licenses"] == ["GPL-3.0-only"]


def test_license_policy_reports_invalid_spdx_expression():
    scan = type("Scan", (), {})()
    scan.components = (
        {
            "name": "broken",
            "purl": "pkg:pypi/broken@1",
            "licenses": [{"expression": "MIT OR (GPL-3.0-only"}],
        },
    )

    findings = audit_license_policy(scan, allowed_licenses=["MIT"])

    assert findings[0].kind == "invalid-license-expression"
