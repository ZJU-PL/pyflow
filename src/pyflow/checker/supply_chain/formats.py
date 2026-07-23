"""SBOM and findings output format builders."""

from __future__ import annotations

import datetime as _datetime
import hashlib
import json
import os
import uuid
from copy import deepcopy
from typing import Any

from pyflow import __version__

from .models import SupplyChainScan
from .validation import validate_cyclonedx_document, validate_spdx_document


def build_cyclonedx_document(
    scan: SupplyChainScan, *, deterministic: bool = False
) -> dict[str, Any]:
    """Build a CycloneDX 1.7 JSON document from a local scan."""

    components: list[dict[str, Any]] = []
    for scanned_component in _complete_component_set(scan):
        component = deepcopy(scanned_component)
        component.setdefault(
            "bom-ref", component.get("purl") or _component_ref(component)
        )
        components.append(component)

    identity = _document_identity(scan)
    document: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{_document_uuid(identity, deterministic)}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(deterministic),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pyflow",
                        "version": __version__,
                    }
                ]
            },
            "properties": [
                {
                    "name": "pyflow:inventory-complete",
                    "value": str(
                        bool(scan.metadata.get("inventoryComplete", True))
                    ).lower(),
                }
            ]
            + [
                {"name": "pyflow:inventory-limitation", "value": str(value)}
                for value in scan.metadata.get("inventoryLimitations", ())
            ],
        },
        "components": components,
    }
    if scan.dependencies:
        document["dependencies"] = [deepcopy(item) for item in scan.dependencies]
    validate_cyclonedx_document(document)
    return document


def build_spdx_document(
    scan: SupplyChainScan, *, deterministic: bool = False
) -> dict[str, Any]:
    """Build an SPDX 2.3 JSON document from a local scan."""

    packages: list[dict[str, Any]] = []
    spdx_by_ref: dict[str, str] = {}
    for i, comp in enumerate(_complete_component_set(scan)):
        name = comp.get("name", "")
        version = comp.get("version")
        purl = comp.get("purl", f"pkg:pypi/{name}")

        spdx_id = _spdx_id(name, i)
        spdx_by_ref[str(purl)] = spdx_id
        package: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _spdx_license(comp),
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ],
        }
        checksums = _spdx_checksums(comp)
        if checksums:
            package["checksums"] = checksums
        if comp.get("description"):
            package["description"] = comp["description"]
        sources = sorted(
            str(item.get("value"))
            for item in comp.get("properties", ())
            if isinstance(item, dict)
            and item.get("name") == "pyflow:source-file"
            and item.get("value")
        )
        if sources:
            package["sourceInfo"] = "Discovered from: " + ", ".join(sources)
        packages.append(package)

    relationships: list[dict[str, str]] = []
    for dependency in scan.dependencies:
        source = spdx_by_ref.get(str(dependency.get("ref", "")))
        if source is None:
            continue
        for target_ref in dependency.get("dependsOn", ()):
            target = spdx_by_ref.get(str(target_ref))
            if target is not None:
                relationships.append(
                    {
                        "spdxElementId": source,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": target,
                    }
                )

    document_id = _document_uuid(_document_identity(scan), deterministic)
    document: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"pyflow-sbom-{document_id}",
        "documentNamespace": f"https://pyflow.dev/spdx/{document_id}",
        "creationInfo": {
            "created": _timestamp(deterministic),
            "creators": [f"Tool: pyflow-{__version__}"],
        },
        "comment": (
            "PyFlow inventory complete: "
            f"{str(bool(scan.metadata.get('inventoryComplete', True))).lower()}"
            + (
                "; limitations: "
                + ", ".join(scan.metadata.get("inventoryLimitations", ()))
                if scan.metadata.get("inventoryLimitations")
                else ""
            )
        ),
        "packages": packages,
    }
    if packages:
        document["documentDescribes"] = [package["SPDXID"] for package in packages]
    if relationships:
        document["relationships"] = relationships
    validate_spdx_document(document)
    return document


def build_sarif_document(scan: SupplyChainScan) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document for supply-chain findings."""

    kinds = sorted({finding.kind for finding in scan.findings})
    rules = [
        {
            "id": kind,
            "name": kind.replace("-", "_"),
            "shortDescription": {"text": kind.replace("-", " ").title()},
        }
        for kind in kinds
    ]
    results: list[dict[str, Any]] = []
    for finding in scan.findings:
        result: dict[str, Any] = {
            "ruleId": finding.kind,
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.message},
            "partialFingerprints": {"pyflowFindingId": finding.to_dict()["id"]},
            "properties": {
                "severity": finding.severity,
                "details": finding.details,
            },
        }
        if finding.location:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": finding.location}}}
            ]
        results.append(result)
    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/"
            "sarif-spec/main/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pyflow-supply-chain",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def build_requirements_text(scan: SupplyChainScan) -> str:
    """Format components without discarding markers, extras, or artifact hashes."""

    lines: list[str] = []
    for comp in scan.components:
        if comp.get("type") == "application":
            continue
        name = comp.get("name", "")
        version = comp.get("version")
        if not name:
            continue
        properties = {
            str(item.get("name")): str(item.get("value"))
            for item in comp.get("properties", ())
            if isinstance(item, dict) and item.get("name")
        }
        extras = properties.get("pyflow:extras", "")
        requirement = f"{name}[{extras}]" if extras else str(name)
        if version:
            requirement += f"=={version}"
        elif properties.get("pyflow:specifier"):
            requirement += properties["pyflow:specifier"]
        if properties.get("pyflow:marker"):
            requirement += f" ; {properties['pyflow:marker']}"
        hashes = []
        for item in comp.get("hashes", ()):
            algorithm = _requirement_hash_name(str(item.get("alg", "")))
            content = item.get("content")
            if algorithm and content:
                hashes.append(f"--hash={algorithm}:{content}")
        if hashes:
            requirement += " " + " ".join(sorted(hashes))
        lines.append(requirement)
    return "\n".join(lines) + "\n" if lines else ""


def format_findings_text(scan: SupplyChainScan) -> str:
    """Render local supply-chain findings for humans."""

    if not scan.findings:
        return "No supply-chain findings."
    lines = [f"Found {len(scan.findings)} supply-chain finding(s):", ""]
    for finding in scan.findings:
        lines.append(f"[{finding.severity}] {finding.kind}: {finding.message}")
        lines.append(f"  location: {finding.location}")
        if finding.details:
            lines.append(f"  details: {json.dumps(finding.details, sort_keys=True)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _spdx_id(name: str, index: int) -> str:
    """Build a safe SPDXRef identifier from a package name."""
    clean = "".join(c if c.isalnum() else "-" for c in name).strip("-")
    return f"SPDXRef-{clean or 'pkg'}-{index}"


def _component_ref(component: dict[str, Any]) -> str:
    canonical = json.dumps(component, sort_keys=True, separators=(",", ":"))
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, canonical)}"


def _spdx_license(component: dict[str, Any]) -> str:
    for choice in component.get("licenses", ()):
        if choice.get("expression"):
            return str(choice["expression"])
        inner = choice.get("license", {})
        identifier = inner.get("id") or inner.get("name")
        if identifier:
            return str(identifier)
    return "NOASSERTION"


def _spdx_checksums(component: dict[str, Any]) -> list[dict[str, str]]:
    algorithm_names = {
        "MD5": "MD5",
        "SHA-1": "SHA1",
        "SHA-256": "SHA256",
        "SHA-384": "SHA384",
        "SHA-512": "SHA512",
        "SHA3-256": "SHA3-256",
        "SHA3-384": "SHA3-384",
        "SHA3-512": "SHA3-512",
    }
    checksums: list[dict[str, str]] = []
    for item in component.get("hashes", ()):
        algorithm = algorithm_names.get(str(item.get("alg", "")))
        content = item.get("content")
        if algorithm and content:
            checksums.append({"algorithm": algorithm, "checksumValue": str(content)})
    return checksums


def _document_identity(scan: SupplyChainScan) -> str:
    content = json.dumps(
        {
            "components": scan.components,
            "dependencies": scan.dependencies,
            "metadata": scan.metadata,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _document_uuid(identity: str, deterministic: bool) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, identity) if deterministic else uuid.uuid4()


def _timestamp(deterministic: bool) -> str:
    if deterministic:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
        value = _datetime.datetime.fromtimestamp(epoch, _datetime.timezone.utc)
    else:
        value = _datetime.datetime.now(_datetime.timezone.utc)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sarif_level(severity: str) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get(severity.upper(), "warning")


def _requirement_hash_name(algorithm: str) -> str | None:
    return {
        "MD5": "md5",
        "SHA-1": "sha1",
        "SHA-256": "sha256",
        "SHA-384": "sha384",
        "SHA-512": "sha512",
        "SHA3-256": "sha3_256",
        "SHA3-384": "sha3_384",
        "SHA3-512": "sha3_512",
    }.get(algorithm)


def _complete_component_set(scan: SupplyChainScan) -> list[dict[str, Any]]:
    components = [deepcopy(component) for component in scan.components]
    refs = {
        str(component.get("purl") or component.get("bom-ref") or "")
        for component in components
    }
    dependency_refs = {
        str(reference)
        for dependency in scan.dependencies
        for reference in (
            dependency.get("ref", ""),
            *(dependency.get("dependsOn", ()) or ()),
        )
        if reference
    }
    for reference in sorted(dependency_refs - refs):
        name = reference.removeprefix("pkg:pypi/").split("@", 1)[0]
        components.append(
            {
                "type": "library",
                "name": name or reference,
                "purl": reference if reference.startswith("pkg:") else None,
                "bom-ref": reference,
                "properties": [
                    {"name": "pyflow:inventory-status", "value": "unresolved"}
                ],
            }
        )
    for component in components:
        if component.get("purl") is None:
            component.pop("purl", None)
    return components
