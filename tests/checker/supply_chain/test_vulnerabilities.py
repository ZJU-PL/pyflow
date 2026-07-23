from __future__ import annotations

import json
import os
import time
import hashlib

import pyflow.checker.supply_chain.vulnerabilities as vulnerability_module
from pyflow.checker.supply_chain import (
    analyze_reachability,
    audit_vulnerabilities,
    scan_targets,
)


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


def test_osv_disjoint_ranges_do_not_erase_an_earlier_match(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==0.5\n", encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text(
        json.dumps(
            {
                "id": "PYSEC-RANGES-1",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "demo"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "1.0"},
                                    {"introduced": "2.0"},
                                    {"fixed": "3.0"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    findings = audit_vulnerabilities(scan_targets([requirements]), [osv])

    assert any(finding.kind == "known-vulnerability" for finding in findings)


def test_osv_matching_is_indexed_by_package(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    records = [
        {
            "id": f"CVE-OTHER-{index}",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": f"other-{index}"},
                    "versions": ["1.0"],
                }
            ],
        }
        for index in range(1000)
    ]
    records.append(
        {
            "id": "CVE-DEMO",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "demo"},
                    "versions": ["1.0"],
                }
            ],
        }
    )
    osv = tmp_path / "osv.json"
    osv.write_text(json.dumps(records), encoding="utf-8")
    calls = 0
    original = vulnerability_module._affected_version

    def counted(version_text, affected):
        nonlocal calls
        calls += 1
        return original(version_text, affected)

    monkeypatch.setattr(vulnerability_module, "_affected_version", counted)

    findings = audit_vulnerabilities(scan_targets([requirements]), [osv])

    assert any(finding.kind == "known-vulnerability" for finding in findings)
    assert calls == 1


def test_osv_database_freshness_and_checksum_are_audited(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text("[]\n", encoding="utf-8")
    checksum = tmp_path / "osv.json.sha256"
    checksum.write_text("0" * 64 + "  osv.json\n", encoding="utf-8")
    old = time.time() - 10 * 86400
    os.utime(osv, (old, old))

    findings = audit_vulnerabilities(
        scan_targets([requirements]),
        [osv],
        max_database_age_days=2,
        require_hashes=True,
    )

    kinds = {finding.kind for finding in findings}
    assert "stale-vulnerability-database" in kinds
    assert "vulnerability-database-checksum-mismatch" in kinds


def test_osv_database_can_be_pinned_to_an_external_trusted_digest(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text("[]\n", encoding="utf-8")
    digest = hashlib.sha256(osv.read_bytes()).hexdigest()

    accepted = audit_vulnerabilities(
        scan_targets([requirements]), [osv], trusted_hashes={str(osv): digest}
    )
    rejected = audit_vulnerabilities(
        scan_targets([requirements]), [osv], trusted_hashes={str(osv): "0" * 64}
    )

    assert not any("trusted-digest" in finding.kind for finding in accepted)
    assert any(
        finding.kind == "vulnerability-database-trusted-digest-mismatch"
        for finding in rejected
    )


def test_vex_not_affected_suppresses_vulnerability(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text(
        json.dumps(
            {
                "id": "CVE-TEST-1",
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
    vex = tmp_path / "vex.json"
    vex.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "CVE-TEST-1",
                        "affects": [{"ref": "pkg:pypi/demo@1.0"}],
                        "analysis": {
                            "state": "not_affected",
                            "justification": "code_not_reachable",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = audit_vulnerabilities(
        scan_targets([requirements]), [osv], vex_documents=[vex]
    )

    assert not any(finding.kind == "known-vulnerability" for finding in findings)
    assert any(
        finding.kind == "vulnerability-suppressed-by-vex" for finding in findings
    )


def test_vex_requires_justification_before_suppressing(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text(
        json.dumps(
            {
                "id": "CVE-TEST-2",
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
    vex = tmp_path / "vex.json"
    vex.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "CVE-TEST-2",
                        "affects": [{"ref": "pkg:pypi/demo@1.0"}],
                        "analysis": {"state": "not_affected"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = audit_vulnerabilities(
        scan_targets([requirements]), [osv], vex_documents=[vex]
    )
    kinds = {finding.kind for finding in findings}

    assert "vex-missing-justification" in kinds
    assert "known-vulnerability" in kinds


def test_vex_product_substring_cannot_suppress_another_component(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==1.0\n", encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text(
        json.dumps(
            {
                "id": "CVE-TEST-SUBSTRING",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "requests"},
                        "versions": ["1.0"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    vex = tmp_path / "vex.json"
    vex.write_text(
        json.dumps(
            {
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-TEST-SUBSTRING"},
                        "products": [{"@id": "pkg:pypi/notrequests@1.0"}],
                        "status": "not_affected",
                        "justification": "component_not_present",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = audit_vulnerabilities(
        scan_targets([requirements]), [osv], vex_documents=[vex]
    )

    assert any(finding.kind == "known-vulnerability" for finding in findings)
    assert not any(
        finding.kind == "vulnerability-suppressed-by-vex" for finding in findings
    )


def test_reachability_adds_non_conclusive_vulnerability_evidence(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==1.0\nunrelated==1.0\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("import requests\n", encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text(
        json.dumps(
            [
                {
                    "id": "CVE-REQUESTS",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "requests"},
                            "versions": ["1.0"],
                        }
                    ],
                },
                {
                    "id": "CVE-UNRELATED",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "unrelated"},
                            "versions": ["1.0"],
                        }
                    ],
                },
            ]
        ),
        encoding="utf-8",
    )
    scan = scan_targets([requirements])
    reachable, reachability_findings = analyze_reachability(scan, [tmp_path])
    findings = audit_vulnerabilities(scan, [osv], reachable_refs=reachable)

    assert not reachability_findings
    evidence = {
        finding.details["vulnerability"]: finding.details["reachability"]
        for finding in findings
        if finding.kind == "known-vulnerability"
    }
    assert evidence == {
        "CVE-REQUESTS": "observed",
        "CVE-UNRELATED": "not-observed",
    }
    assert all(
        finding.details["reachability_is_conclusive"] is False
        for finding in findings
        if finding.kind == "known-vulnerability"
    )


def test_reachability_uses_distribution_top_level_metadata(tmp_path):
    dist_info = tmp_path / "beautifulsoup4-4.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: beautifulsoup4\nVersion: 4.0\n", encoding="utf-8"
    )
    (dist_info / "top_level.txt").write_text("bs4\n", encoding="utf-8")
    (dist_info / "RECORD").write_text("", encoding="utf-8")
    (tmp_path / "app.py").write_text("import bs4\n", encoding="utf-8")

    scan = scan_targets([tmp_path], recursive=True)
    reachable, findings = analyze_reachability(scan, [tmp_path])

    assert not findings
    assert "pkg:pypi/beautifulsoup4@4.0" in reachable
