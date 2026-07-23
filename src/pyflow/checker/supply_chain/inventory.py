"""Component normalization, merging, and dependency graph helpers."""

from __future__ import annotations

import json
from typing import Any, Iterable
from urllib.parse import quote

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from .models import SEVERITY_RANK, SupplyChainFinding


def component(name: str, *, version: str | None = None) -> dict[str, Any]:
    canonical = canonicalize_name(name)
    purl = f"pkg:pypi/{quote(canonical, safe='.-_~')}"
    if version:
        purl += f"@{quote(str(version), safe='.-_~')}"
    data: dict[str, Any] = {
        "type": "library",
        "name": canonical,
        "purl": purl,
    }
    if version:
        data["version"] = version
    return data


def exact_version(requirement: Requirement) -> str | None:
    for specifier in requirement.specifier:
        if specifier.operator in {"==", "==="} and "*" not in specifier.version:
            return specifier.version
    return None


def add_property(component_data: dict[str, Any], name: str, value: str) -> None:
    properties = component_data.setdefault("properties", [])
    candidate = {"name": name, "value": value}
    if candidate not in properties:
        properties.append(candidate)


def string_or_none(value: Any) -> str | None:
    return str(value) if value is not None and str(value) else None


def cyclonedx_hash_name(algorithm: str) -> str | None:
    return {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha256": "SHA-256",
        "sha384": "SHA-384",
        "sha512": "SHA-512",
        "sha3_256": "SHA3-256",
        "sha3_384": "SHA3-384",
        "sha3_512": "SHA3-512",
    }.get(algorithm)


def dedupe_hashes(hashes: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    unique = {(item["alg"], item["content"]): item for item in hashes}
    return [unique[key] for key in sorted(unique)]


def best_dependency_ref(name: str, refs_by_name: dict[str, list[str]]) -> str:
    canonical = canonicalize_name(name)
    refs = sorted(set(refs_by_name.get(canonical, ())))
    if refs:
        return refs[0]
    return f"pkg:pypi/{canonical}"


def dedupe_components(
    components: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str | None], dict[str, Any]] = {}
    for component_data in components:
        key = (
            str(component_data.get("purl") or component_data.get("name")),
            component_data.get("version"),
        )
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = component_data
        else:
            _merge_component(existing, component_data)
    return [deduped[key] for key in sorted(deduped)]


def _merge_component(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if key not in target or not target[key]:
            target[key] = value
            continue
        if key in {"hashes", "licenses", "properties", "externalReferences"}:
            existing = target.setdefault(key, [])
            for item in value:
                if item not in existing:
                    existing.append(item)


def dedupe_findings(
    findings: Iterable[SupplyChainFinding],
) -> list[SupplyChainFinding]:
    unique: dict[str, SupplyChainFinding] = {}
    for finding in findings:
        key = json.dumps(finding.to_dict(), sort_keys=True, default=str)
        unique.setdefault(key, finding)
    return sorted(
        unique.values(),
        key=lambda item: (
            item.location,
            -SEVERITY_RANK.get(item.severity.upper(), 0),
            item.kind,
            item.message,
        ),
    )


def dedupe_dependencies(
    dependencies: Iterable[tuple[str, str]],
) -> list[dict[str, Any]]:
    grouped: dict[str, set[str]] = {}
    for source, target in dependencies:
        if source and target and source != target:
            grouped.setdefault(source, set()).add(target)
    all_targets = {target for targets in grouped.values() for target in targets}
    for target in all_targets:
        grouped.setdefault(target, set())
    return [
        {"ref": source, "dependsOn": sorted(targets)}
        for source, targets in sorted(grouped.items())
    ]
