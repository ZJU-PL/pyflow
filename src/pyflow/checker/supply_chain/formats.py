"""SBOM and findings output format builders."""

from __future__ import annotations

import datetime as _datetime
import json
import uuid
from copy import deepcopy
from typing import Any

from pyflow import __version__

from .models import SupplyChainScan


def build_cyclonedx_document(scan: SupplyChainScan) -> dict[str, Any]:
    """Build a CycloneDX 1.7 JSON document from a local scan."""

    components: list[dict[str, Any]] = []
    for scanned_component in scan.components:
        component = deepcopy(scanned_component)
        component.setdefault(
            "bom-ref", component.get("purl") or _component_ref(component)
        )
        components.append(component)

    document: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _datetime.datetime.now(_datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pyflow",
                        "version": __version__,
                    }
                ]
            },
        },
        "components": components,
    }
    if scan.dependencies:
        document["dependencies"] = [deepcopy(item) for item in scan.dependencies]
    return document


def build_spdx_document(scan: SupplyChainScan) -> dict[str, Any]:
    """Build an SPDX 2.3 JSON document from a local scan."""

    packages: list[dict[str, Any]] = []
    spdx_by_ref: dict[str, str] = {}
    for i, comp in enumerate(scan.components):
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

    document_id = uuid.uuid4()
    document: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"pyflow-sbom-{document_id}",
        "documentNamespace": f"https://pyflow.dev/spdx/{document_id}",
        "creationInfo": {
            "created": _datetime.datetime.now(_datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "creators": [f"Tool: pyflow-{__version__}"],
        },
        "packages": packages,
    }
    if packages:
        document["documentDescribes"] = [package["SPDXID"] for package in packages]
    if relationships:
        document["relationships"] = relationships
    return document


def build_requirements_text(scan: SupplyChainScan) -> str:
    """Format scanned components as requirements.txt lines (name==version)."""

    lines: list[str] = []
    for comp in scan.components:
        name = comp.get("name", "")
        version = comp.get("version")
        if name and version:
            lines.append(f"{name}=={version}")
        elif name:
            lines.append(name)
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
