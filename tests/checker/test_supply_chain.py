from __future__ import annotations

import csv
import hashlib
import json
import zipfile
from base64 import urlsafe_b64encode

from pyflow.checker.supply_chain import build_cyclonedx_document, scan_targets


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
    assert doc["components"] == [
        {
            "type": "library",
            "name": "demo-pkg",
            "purl": "pkg:pypi/demo-pkg@1.2.3",
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
