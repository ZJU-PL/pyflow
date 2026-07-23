"""Local CycloneDX and OpenVEX status ingestion."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable

from packaging.utils import canonicalize_name

from .input_safety import load_json_file
from .models import SupplyChainFinding


VexStatuses = dict[tuple[str, str], dict[str, str]]


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
        status = str(analysis.get("state", "")).lower().replace("_", "-")
        justification = str(analysis.get("justification", ""))
        detail = str(analysis.get("detail", ""))
        for affect in vulnerability.get("affects", ()) or ():
            if isinstance(affect, dict) and affect.get("ref"):
                statuses[(identifier, str(affect["ref"]))] = {
                    "status": status,
                    "justification": justification or detail,
                }


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
    statuses: VexStatuses, identifier: str, purl: str, component_name: str
) -> dict[str, str] | None:
    direct = statuses.get((identifier, purl))
    if direct is not None:
        return direct
    canonical = canonicalize_name(component_name)
    for (vulnerability, product), status in statuses.items():
        if vulnerability != identifier:
            continue
        if canonical and canonical in canonicalize_name(product):
            return status
    return None
