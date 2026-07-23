"""Resolve marker-qualified inventory entries for a target Python runtime."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable, Mapping

from packaging.markers import InvalidMarker, Marker, default_environment

from .models import SupplyChainFinding, SupplyChainScan


def resolve_environment(
    scan: SupplyChainScan,
    *,
    environment: Mapping[str, str] | None = None,
    extras: Iterable[str] = (),
) -> SupplyChainScan:
    """Filter components whose PEP 508 markers cannot match the target runtime."""

    target: dict[str, str] = dict(default_environment())
    if environment:
        target.update({key: str(value) for key, value in environment.items()})
    selected_extras = tuple(sorted({str(extra) for extra in extras if str(extra)}))
    findings = list(scan.findings)
    components: list[dict[str, Any]] = []
    removed_refs: set[str] = set()

    for component in scan.components:
        markers = _property_values(component, "pyflow:marker")
        if not markers:
            components.append(component)
            continue
        matched = False
        for marker_text in markers:
            try:
                marker = Marker(marker_text)
            except InvalidMarker as exc:
                findings.append(
                    SupplyChainFinding(
                        kind="invalid-environment-marker",
                        message="Dependency marker cannot be evaluated",
                        location=str(
                            component.get("purl") or component.get("name", "")
                        ),
                        severity="MEDIUM",
                        details={"marker": marker_text, "error": str(exc)},
                    )
                )
                matched = True
                break
            candidate_extras = selected_extras or ("",)
            if any(
                marker.evaluate({**target, "extra": extra})
                for extra in candidate_extras
            ):
                matched = True
                break
        if matched:
            components.append(component)
        else:
            removed_refs.add(str(component.get("purl") or ""))

    dependencies: list[dict[str, Any]] = []
    for dependency in scan.dependencies:
        source = str(dependency.get("ref", ""))
        if source in removed_refs:
            continue
        targets = [
            str(target_ref)
            for target_ref in dependency.get("dependsOn", ())
            if str(target_ref) not in removed_refs
        ]
        dependencies.append({"ref": source, "dependsOn": targets})

    metadata = dict(scan.metadata)
    metadata["environment"] = target
    metadata["extras"] = list(selected_extras)
    return replace(
        scan,
        components=tuple(components),
        findings=tuple(findings),
        dependencies=tuple(dependencies),
        metadata=metadata,
    )


def _property_values(component: Mapping[str, Any], name: str) -> list[str]:
    return [
        str(item.get("value"))
        for item in component.get("properties", ())
        if isinstance(item, dict) and item.get("name") == name
    ]
