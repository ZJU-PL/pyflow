"""Artifact provenance and optional Sigstore bundle verification."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .input_safety import load_json_file
from .models import SupplyChainFinding


def audit_provenance(
    artifacts: Iterable[str | Path],
    attestations: Iterable[str | Path],
    *,
    trusted_builders: Iterable[str] = (),
    require_provenance: bool = False,
    require_dsse: bool = False,
) -> tuple[SupplyChainFinding, ...]:
    """Verify in-toto subject digests and builder policy for local artifacts."""

    findings: list[SupplyChainFinding] = []
    statements: list[tuple[dict[str, Any], Path, bool]] = []
    for value in attestations:
        path = Path(value)
        try:
            document = load_json_file(path)
            statement, is_dsse = _unwrap_statement(document)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-provenance",
                    message="Could not parse in-toto provenance",
                    location=str(path),
                    severity="HIGH",
                    details={"error": str(exc)},
                )
            )
            continue
        statements.append((statement, path, is_dsse))

    builders = {str(builder) for builder in trusted_builders if str(builder)}
    for value in artifacts:
        artifact = Path(value)
        if not artifact.is_file():
            continue
        digest = _sha256_file(artifact)
        matched = False
        for statement, source, is_dsse in statements:
            subject = _matching_subject(statement, artifact, digest)
            if subject is None:
                continue
            matched = True
            predicate_type = str(statement.get("predicateType", ""))
            if not predicate_type:
                findings.append(
                    SupplyChainFinding(
                        kind="provenance-missing-predicate-type",
                        message="Provenance does not identify its predicate type",
                        location=str(source),
                        severity="HIGH",
                    )
                )
            builder = _builder_id(statement)
            if builders and builder not in builders:
                findings.append(
                    SupplyChainFinding(
                        kind="untrusted-provenance-builder",
                        message="Artifact provenance names an untrusted builder",
                        location=str(artifact),
                        severity="HIGH",
                        details={"builder": builder, "attestation": str(source)},
                    )
                )
            if require_dsse and not is_dsse:
                findings.append(
                    SupplyChainFinding(
                        kind="provenance-not-dsse",
                        message="Artifact provenance is not wrapped in a DSSE envelope",
                        location=str(source),
                        severity="HIGH",
                    )
                )
        if require_provenance and not matched:
            findings.append(
                SupplyChainFinding(
                    kind="missing-provenance",
                    message="Artifact has no matching digest-bound provenance",
                    location=str(artifact),
                    severity="HIGH",
                    details={"sha256": digest},
                )
            )
    return tuple(findings)


def audit_sigstore_bundles(
    artifact_bundle_pairs: Iterable[str],
    *,
    certificate_identity: str,
    certificate_oidc_issuer: str,
    timeout_seconds: float = 30.0,
) -> tuple[SupplyChainFinding, ...]:
    """Verify local Sigstore bundles through the official ``sigstore`` CLI."""

    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be finite and greater than zero")
    findings: list[SupplyChainFinding] = []
    executable = shutil.which("sigstore")
    pairs = list(artifact_bundle_pairs)
    if pairs and executable is None:
        return (
            SupplyChainFinding(
                kind="sigstore-verifier-unavailable",
                message="Sigstore verification was requested but the sigstore CLI is unavailable",
                location="sigstore",
                severity="HIGH",
            ),
        )
    for pair in pairs:
        artifact_text, separator, bundle_text = pair.partition("=")
        if not separator:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-sigstore-bundle-argument",
                    message="Sigstore bundle must use ARTIFACT=BUNDLE syntax",
                    location=pair,
                    severity="HIGH",
                )
            )
            continue
        artifact = Path(artifact_text)
        bundle = Path(bundle_text)
        if not artifact.is_file() or not bundle.is_file():
            findings.append(
                SupplyChainFinding(
                    kind="missing-sigstore-input",
                    message="Sigstore artifact or bundle does not exist",
                    location=pair,
                    severity="HIGH",
                )
            )
            continue
        command = [
            str(executable),
            "verify",
            "identity",
            "--bundle",
            str(bundle),
            "--cert-identity",
            certificate_identity,
            "--cert-oidc-issuer",
            certificate_oidc_issuer,
            str(artifact),
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            findings.append(
                SupplyChainFinding(
                    kind="sigstore-verification-error",
                    message="Sigstore verification could not complete",
                    location=str(artifact),
                    severity="HIGH",
                    details={"error": str(exc)},
                )
            )
            continue
        if completed.returncode != 0:
            findings.append(
                SupplyChainFinding(
                    kind="sigstore-verification-failed",
                    message="Artifact failed Sigstore identity verification",
                    location=str(artifact),
                    severity="CRITICAL",
                    details={"error": completed.stderr.strip()[:1000]},
                )
            )
    return tuple(findings)


def _unwrap_statement(document: Any) -> tuple[dict[str, Any], bool]:
    if not isinstance(document, dict):
        raise ValueError("provenance document must be an object")
    if document.get("payloadType") and document.get("payload"):
        try:
            payload = base64.b64decode(str(document["payload"]), validate=True)
            statement = json.loads(payload)
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError("invalid DSSE payload") from exc
        if not isinstance(statement, dict):
            raise ValueError("DSSE payload is not an in-toto statement")
        return statement, True
    return document, False


def _matching_subject(
    statement: dict[str, Any], artifact: Path, digest: str
) -> dict[str, Any] | None:
    for subject in statement.get("subject", ()) or ():
        if not isinstance(subject, dict):
            continue
        subject_digest = subject.get("digest", {}) or {}
        if str(subject_digest.get("sha256", "")).lower() != digest:
            continue
        name = str(subject.get("name", ""))
        if not name or Path(name).name == artifact.name or name == str(artifact):
            return subject
    return None


def _builder_id(statement: dict[str, Any]) -> str:
    predicate = statement.get("predicate", {}) or {}
    builder = predicate.get("builder", {}) or {}
    return str(builder.get("id", ""))


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
