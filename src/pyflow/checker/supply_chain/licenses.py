"""License metadata normalization and allowlist policy checks."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from .models import SupplyChainFinding, SupplyChainScan


DEFAULT_ALLOWED_LICENSES: frozenset[str] = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Python-2.0",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
        "Unlicense",
        "CC0-1.0",
        "ISC",
        "Zlib",
        "PSF-2.0",
        "PostgreSQL",
    }
)

_SPDX_OPERATORS = frozenset({"AND", "OR", "WITH"})


def audit_license_policy(
    scan: SupplyChainScan,
    *,
    allowed_licenses: Iterable[str] | None = None,
) -> tuple[SupplyChainFinding, ...]:
    """Check scanned components against a license allowlist."""

    allowed = (
        frozenset(allowed_licenses)
        if allowed_licenses is not None
        else DEFAULT_ALLOWED_LICENSES
    )
    findings: list[SupplyChainFinding] = []

    for component in scan.components:
        name = component.get("name", "")
        purl = component.get("purl", name)
        licenses = component.get("licenses", [])
        if not licenses:
            findings.append(
                SupplyChainFinding(
                    kind="license-not-declared",
                    message=f"Component {name} has no declared license",
                    location=purl,
                    severity="LOW",
                )
            )
            continue

        declared: list[str] = []
        for license_choice in licenses:
            expression = license_choice.get("expression")
            if expression:
                declared.extend(_license_expression_identifiers(str(expression)))
                continue
            inner = license_choice.get("license", {})
            identifier = inner.get("id") or inner.get("name")
            if identifier:
                declared.append(str(identifier))

        for identifier in sorted(set(declared)):
            if identifier not in allowed:
                findings.append(
                    SupplyChainFinding(
                        kind="license-not-allowed",
                        message=(
                            f"License {identifier} for {name} is not in the allowed list"
                        ),
                        location=purl,
                        severity="MEDIUM",
                        details={"license": identifier, "component": name},
                    )
                )

    return tuple(findings)


def licenses_from_metadata(data: Any) -> list[dict[str, Any]]:
    expression = data.get("License-Expression")
    if expression:
        return [{"expression": str(expression).strip()}]

    licenses: list[dict[str, Any]] = []
    if license_text := data.get("License"):
        licenses.append(license_entry(license_text))
    for classifier in data.get_all("Classifier", []) or []:
        if classifier.startswith("License ::"):
            classifier_text = classifier.strip()
            mapped = _TROVE_LICENSES.get(classifier_text)
            licenses.append(
                license_entry(mapped or classifier.rsplit("::", 1)[-1].strip())
            )
    unique: dict[str, dict[str, Any]] = {}
    for item in licenses:
        key = json.dumps(item, sort_keys=True)
        unique[key] = item
    return list(unique.values())


def license_entry(value: str) -> dict[str, dict[str, str]]:
    value = _LICENSE_ALIASES.get(value.strip().casefold(), value.strip())
    if value and " " not in value and len(value) <= 64:
        return {"license": {"id": value}}
    return {"license": {"name": value}}


def _license_expression_identifiers(expression: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expression)
    return [token for token in tokens if token.upper() not in _SPDX_OPERATORS]


_TROVE_LICENSES = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
}

_LICENSE_ALIASES = {
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "isc license": "ISC",
    "mit license": "MIT",
    "mozilla public license 2.0": "MPL-2.0",
    "python software foundation license": "PSF-2.0",
}
