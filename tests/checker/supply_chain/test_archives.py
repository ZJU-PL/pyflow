from __future__ import annotations

import csv
import random
import stat
import tarfile
import zipfile

from pyflow.checker.supply_chain import ScanLimits, scan_targets

from ._helpers import write_record as _write_record


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


def test_wheel_without_distribution_metadata_is_rejected(tmp_path):
    wheel = tmp_path / "demo-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "")

    scan = scan_targets([wheel])

    assert any(
        finding.kind == "archive-missing-package-metadata" for finding in scan.findings
    )


def test_malformed_archive_inputs_fail_closed_without_crashing(tmp_path):
    generator = random.Random(0)
    for index in range(20):
        archive_path = tmp_path / f"malformed-{index}.zip"
        archive_path.write_bytes(generator.randbytes(index * 17 + 1))
        scan = scan_targets([archive_path])
        assert any(
            finding.kind == "archive-unrecognized-format" for finding in scan.findings
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


def test_tar_scanning_enforces_streaming_member_limit(tmp_path):
    archive_path = tmp_path / "demo.tar"
    source = tmp_path / "source.txt"
    source.write_text("x", encoding="utf-8")
    with tarfile.open(archive_path, "w") as archive:
        archive.add(source, arcname="one.txt")
        archive.add(source, arcname="two.txt")

    scan = scan_targets([archive_path], limits=ScanLimits(max_archive_members=1))

    assert any(finding.kind == "archive-member-limit" for finding in scan.findings)


def test_compressed_tar_enforces_ratio_limit(tmp_path):
    archive_path = tmp_path / "demo.tar.gz"
    source = tmp_path / "zeros.bin"
    source.write_bytes(b"\0" * (1024 * 1024))
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(source, arcname="zeros.bin")

    scan = scan_targets([archive_path], limits=ScanLimits(max_compression_ratio=2.0))

    assert any(
        finding.kind == "archive-suspicious-compression-ratio"
        for finding in scan.findings
    )


def test_manifest_size_and_requirement_include_symlink_are_bounded(tmp_path):
    oversized = tmp_path / "requirements.txt"
    oversized.write_text("demo==1\n" * 20, encoding="utf-8")
    limited = scan_targets([oversized], limits=ScanLimits(max_manifest_size=10))
    assert any(finding.kind == "manifest-size-limit" for finding in limited.findings)

    target = tmp_path / "target.txt"
    target.write_text("demo==1\n", encoding="utf-8")
    link = tmp_path / "linked.txt"
    link.symlink_to(target)
    root = tmp_path / "requirements-root.txt"
    root.write_text("-r linked.txt\n", encoding="utf-8")
    linked = scan_targets([root])
    assert any(
        finding.kind == "requirement-include-symlink" for finding in linked.findings
    )


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


def test_record_audit_reports_duplicate_external_and_missing_entries(tmp_path):
    dist_info = tmp_path / "demo-1.0.dist-info"
    dist_info.mkdir()
    metadata = dist_info / "METADATA"
    metadata.write_text("Name: demo\nVersion: 1.0\n", encoding="utf-8")
    (dist_info / "RECORD").write_text(
        "../outside.py,,\n" "missing.py,,\n" "missing.py,,\n" "broken-row\n",
        encoding="utf-8",
    )

    kinds = {
        finding.kind for finding in scan_targets([tmp_path], recursive=True).findings
    }

    assert {
        "record-external-path",
        "record-missing-file",
        "duplicate-record-entry",
        "invalid-record-entry",
    } <= kinds
