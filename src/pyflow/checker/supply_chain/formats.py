"""SBOM and findings output format builders."""

from __future__ import annotations

import datetime as _datetime
import json
import uuid
from typing import Any

from .scanner import SupplyChainScan


def build_cyclonedx_document(scan: SupplyChainScan) -> dict[str, Any]:
    """Build a CycloneDX 1.3 JSON document from a local scan."""

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.3",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _datetime.datetime.now(_datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "tools": [{"vendor": "PyFlow", "name": "pyflow", "version": "0.1.0"}],
        },
        "components": list(scan.components),
    }


def build_spdx_document(scan: SupplyChainScan) -> dict[str, Any]:
    """Build an SPDX 2.2 JSON document from a local scan."""

    packages: list[dict[str, Any]] = []
    for i, comp in enumerate(scan.components):
        name = comp.get("name", "")
        version = comp.get("version")
        purl = comp.get("purl", f"pkg:pypi/{name}")

        license_declared: str = "NOASSERTION"
        licenses = comp.get("licenses", [])
        if licenses:
            for lic in licenses:
                inner = lic.get("license", {})
                lid = inner.get("id") or inner.get("name")
                if lid:
                    license_declared = lid
                    break

        packages.append({
            "SPDXID": _spdx_id(name, i),
            "name": name,
            "versionInfo": version or "NOASSERTION",
            "packageFileName": purl,
            "licenseDeclared": license_declared,
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
        })

    return {
        "spdxVersion": "SPDX-2.2",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"pyflow-sbom-{uuid.uuid4()}",
        "creationInfo": {
            "created": _datetime.datetime.now(_datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "creators": ["Tool: pyflow-0.1.0"],
        },
        "packages": packages,
    }


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
