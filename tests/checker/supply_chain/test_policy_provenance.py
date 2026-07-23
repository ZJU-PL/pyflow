from __future__ import annotations

import base64
import hashlib
import json

import pyflow.checker.supply_chain.provenance as provenance_module
from pyflow.checker.supply_chain import (
    FindingPolicy,
    SupplyChainFinding,
    SupplyChainScan,
    apply_finding_policy,
    audit_package_names,
    audit_provenance,
    audit_sigstore_bundles,
    write_baseline,
)


def test_policy_baseline_expiry_and_typosquatting(tmp_path):
    finding = SupplyChainFinding(
        kind="known-vulnerability",
        message="demo",
        location="pkg:pypi/demo@1",
        severity="HIGH",
        details={"vulnerability": "CVE-1", "component": "demo"},
    )
    baseline = tmp_path / "baseline.json"
    write_baseline(baseline, [finding])
    policy = FindingPolicy(
        exceptions=(
            {
                "kind": "known-vulnerability",
                "expires": "2000-01-01",
                "reason": "temporary",
            },
        )
    )
    kept, suppressed = apply_finding_policy([finding], policy)
    typo_findings = audit_package_names(
        SupplyChainScan(
            components=({"name": "requsets", "purl": "pkg:pypi/requsets@1"},),
            findings=(),
        ),
        ["requests"],
    )

    assert not suppressed
    assert {item.kind for item in kept} == {
        "known-vulnerability",
        "policy-exception-expired",
    }
    assert typo_findings[0].kind == "possible-typosquatting"
    assert json.loads(baseline.read_text(encoding="utf-8"))["finding_ids"]


def test_provenance_verifies_subject_digest_and_builder(tmp_path):
    artifact = tmp_path / "demo.whl"
    artifact.write_bytes(b"artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    attestation = tmp_path / "provenance.json"
    attestation.write_text(
        json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": artifact.name, "digest": {"sha256": digest}}],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"builder": {"id": "https://builder.example/ci"}},
            }
        ),
        encoding="utf-8",
    )

    findings = audit_provenance(
        [artifact],
        [attestation],
        trusted_builders=["https://builder.example/ci"],
        require_provenance=True,
        authenticated_attestations=[attestation],
    )

    assert not findings


def test_provenance_policy_and_sigstore_failure_paths(tmp_path, monkeypatch):
    artifact = tmp_path / "demo.whl"
    artifact.write_bytes(b"artifact")
    attestation = tmp_path / "provenance.json"
    attestation.write_text(
        json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": artifact.name,
                        "digest": {"sha256": hashlib.sha256(b"artifact").hexdigest()},
                    }
                ],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"builder": {"id": "untrusted"}},
            }
        ),
        encoding="utf-8",
    )
    findings = audit_provenance(
        [artifact],
        [attestation],
        trusted_builders=["trusted"],
        require_provenance=True,
        require_dsse=True,
    )
    assert {finding.kind for finding in findings} == {
        "untrusted-provenance-builder",
        "provenance-not-dsse",
        "provenance-authenticity-unverified",
        "untrusted-provenance",
    }

    bundle = tmp_path / "demo.sigstore.json"
    bundle.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(provenance_module.shutil, "which", lambda _name: None)
    unavailable = audit_sigstore_bundles(
        [f"{artifact}={bundle}"],
        certificate_identity="release@example.com",
        certificate_oidc_issuer="https://issuer.example",
    )
    assert unavailable[0].kind == "sigstore-verifier-unavailable"


def test_dsse_and_sigstore_success_paths(tmp_path, monkeypatch):
    artifact = tmp_path / "demo.whl"
    artifact.write_bytes(b"artifact")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": artifact.name,
                "digest": {"sha256": hashlib.sha256(b"artifact").hexdigest()},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"builder": {"id": "trusted"}},
    }
    envelope = tmp_path / "provenance.dsse.json"
    envelope.write_text(
        json.dumps(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
                "signatures": [{"keyid": "test", "sig": "signed-externally"}],
            }
        ),
        encoding="utf-8",
    )
    assert not audit_provenance(
        [artifact],
        [envelope],
        trusted_builders=["trusted"],
        require_provenance=True,
        require_dsse=True,
        authenticated_attestations=[envelope],
    )

    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}", encoding="utf-8")
    captured = []

    class Completed:
        returncode = 0
        stderr = ""

    monkeypatch.setattr(provenance_module.shutil, "which", lambda _name: "/sigstore")

    def run(command, **kwargs):
        captured.append((command, kwargs))
        return Completed()

    monkeypatch.setattr(provenance_module.subprocess, "run", run)
    assert not audit_sigstore_bundles(
        [f"{artifact}={bundle}"],
        certificate_identity="release@example.com",
        certificate_oidc_issuer="https://issuer.example",
    )
    assert captured[0][0][:3] == ["/sigstore", "verify", "identity"]
    assert captured[0][1]["timeout"] == 30.0


def test_unsigned_or_empty_dsse_provenance_never_establishes_trust(tmp_path):
    artifact = tmp_path / "demo.whl"
    artifact.write_bytes(b"artifact")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": artifact.name,
                "digest": {"sha256": hashlib.sha256(b"artifact").hexdigest()},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"builder": {"id": "trusted"}},
    }
    unsigned = tmp_path / "unsigned.json"
    unsigned.write_text(json.dumps(statement), encoding="utf-8")
    empty_dsse = tmp_path / "empty.dsse.json"
    empty_dsse.write_text(
        json.dumps(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
                "signatures": [],
            }
        ),
        encoding="utf-8",
    )

    unsigned_findings = audit_provenance(
        [artifact], [unsigned], trusted_builders=["trusted"], require_provenance=True
    )
    empty_findings = audit_provenance(
        [artifact],
        [empty_dsse],
        trusted_builders=["trusted"],
        require_provenance=True,
        require_dsse=True,
        authenticated_attestations=[empty_dsse],
    )

    assert "provenance-authenticity-unverified" in {
        finding.kind for finding in unsigned_findings
    }
    assert "untrusted-provenance" in {finding.kind for finding in unsigned_findings}
    assert "provenance-dsse-signature-missing" in {
        finding.kind for finding in empty_findings
    }
    assert "untrusted-provenance" in {finding.kind for finding in empty_findings}
