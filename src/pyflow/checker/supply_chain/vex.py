"""Local CycloneDX and OpenVEX status ingestion."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .input_safety import load_json_file
from .models import SupplyChainFinding

VexStatuses = dict[tuple[str, str], dict[str, Any]]


def load_vex(
    paths: Iterable[str | os.PathLike[str]], findings: list[SupplyChainFinding]
) -> VexStatuses:
    statuses: VexStatuses = {}
    for value in paths:
        path = Path(value)
        try:
            data = load_json_file(path)
        except (OSError, ValueError) as exc:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-vex-document",
                    message="Could not read local VEX document",
                    location=str(path),
                    severity="HIGH",
                    details={"error": str(exc)},
                )
            )
            continue
        if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
            _load_cyclonedx_vex(data, statuses)
        elif isinstance(data, dict) and isinstance(data.get("statements"), list):
            _load_openvex(data, statuses)
        else:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-vex-document",
                    message="Document is neither CycloneDX VEX nor OpenVEX",
                    location=str(path),
                    severity="HIGH",
                )
            )
    return statuses


def _load_cyclonedx_vex(data: dict[str, Any], statuses: VexStatuses) -> None:
    for vulnerability in data.get("vulnerabilities", ()):
        if not isinstance(vulnerability, dict):
            continue
        identifier = str(vulnerability.get("id", ""))
        analysis = vulnerability.get("analysis", {}) or {}
        if not isinstance(analysis, dict):
            analysis = {}
        status = str(analysis.get("state", "")).lower().replace("_", "-")
        justification = str(analysis.get("justification", ""))
        detail = str(analysis.get("detail", ""))
        for affect in vulnerability.get("affects", ()) or ():
            if not (isinstance(affect, dict) and affect.get("ref")):
                continue
            entry: dict[str, Any] = {
                "status": status,
                "justification": justification or detail,
            }
            versions: list[str] = []
            ranges: list[str] = []
            for version_entry in affect.get("versions", ()) or ():
                if not isinstance(version_entry, dict):
                    continue
                if version_entry.get("version"):
                    versions.append(str(version_entry["version"]))
                if version_entry.get("range"):
                    ranges.append(str(version_entry["range"]))
            if versions:
                entry["versions"] = versions
            if ranges:
                entry["ranges"] = ranges
            statuses[(identifier, str(affect["ref"]))] = entry


def _load_openvex(data: dict[str, Any], statuses: VexStatuses) -> None:
    for statement in data.get("statements", ()):
        if not isinstance(statement, dict):
            continue
        vulnerability = statement.get("vulnerability", {}) or {}
        identifier = str(vulnerability.get("name") or vulnerability.get("id") or "")
        status = str(statement.get("status", "")).lower().replace("_", "-")
        justification = str(
            statement.get("justification") or statement.get("impact_statement") or ""
        )
        for product in statement.get("products", ()) or ():
            if not isinstance(product, dict):
                continue
            product_id = str(product.get("@id") or product.get("id") or "")
            statuses[(identifier, product_id)] = {
                "status": status,
                "justification": justification,
            }
            name = (
                product.get("identifiers", {}).get("purl")
                if isinstance(product.get("identifiers"), dict)
                else None
            )
            if name:
                statuses[(identifier, str(name))] = {
                    "status": status,
                    "justification": justification,
                }


def vex_status_for(
    statuses: VexStatuses,
    identifier: str,
    purl: str,
    component_name: str,
    *,
    aliases: Iterable[str] = (),
    version: str = "",
) -> dict[str, Any] | None:
    identifiers = {identifier, *(str(alias) for alias in aliases if str(alias))}
    for candidate in identifiers:
        direct = statuses.get((candidate, purl))
        if direct is not None and _version_applies(direct, version):
            return direct
    canonical = canonicalize_name(component_name)
    for (vulnerability, product), status in statuses.items():
        if vulnerability not in identifiers:
            continue
        product_name = _exact_product_name(product)
        if canonical and product_name == canonical and _version_applies(status, version):
            return status
    return None


def _version_applies(status: dict[str, Any], version: str) -> bool:
    """Check optional CycloneDX version/range constraints on an affect entry."""

    if not version:
        return True
    versions = status.get("versions")
    ranges = status.get("ranges")
    if not versions and not ranges:
        return True
    if isinstance(versions, list) and any(_same_version(str(item), version) for item in versions):
        return True
    if isinstance(ranges, list):
        return any(_range_matches(str(item), version) for item in ranges)
    return False


def _same_version(left: str, right: str) -> bool:
    try:
        return Version(left) == Version(right)
    except InvalidVersion:
        return left == right


def _range_matches(range_text: str, version: str) -> bool:
    text = range_text.split("/", 1)[-1]
    specifiers: list[str] = []
    for part in text.split("|"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("=") and not part.startswith("=="):
            part = "=" + part
        elif not part.startswith((">", "<", "!", "=", "~")):
            part = "==" + part
        specifiers.append(part)
    if not specifiers:
        return False
    try:
        return Version(version) in SpecifierSet(",".join(specifiers))
    except (InvalidSpecifier, InvalidVersion):
        return False


def _exact_product_name(product: str) -> str | None:
    """Extract only exact package identities; never use substring matching."""

    value = product.strip()
    if value.startswith("pkg:pypi/"):
        value = value[len("pkg:pypi/") :].split("?", 1)[0].split("#", 1)[0]
        value = value.split("@", 1)[0]
        return str(canonicalize_name(value)) if value else None
    if not value or any(character in value for character in "/:@?#"):
        return None
    return str(canonicalize_name(value))
