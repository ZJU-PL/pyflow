"""Resolve marker-qualified inventory entries for a target Python runtime."""

from __future__ import annotations

import re
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
    installed_tree = bool(scan.metadata.get("installed", False))
    declared_only = environment is None and not installed_tree
    findings = list(scan.findings)
    components: list[dict[str, Any]] = []
    removed_refs: set[str] = set()

    for component in scan.components:
        properties = [prop for prop in component.get("properties", ()) if isinstance(prop, dict)]
        installed_root = any(
            prop.get("name") == "pyflow:metadata-source"
            and str(prop.get("value", "")).lower() == "true"
            for prop in properties
        )
        if installed_root:
            # An installed distribution is present regardless of which extras
            # some other package's Requires-Dist mentions.  Its own metadata
            # component must never be filtered by merged dependency markers.
            components.append(component)
            continue
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
                        location=str(component.get("purl") or component.get("name", "")),
                        severity="MEDIUM",
                        details={"marker": marker_text, "error": str(exc)},
                    )
                )
                matched = True
                break
            if declared_only:
                # A source SBOM describes declared dependencies across
                # platforms and Python versions.  Do not silently drop
                # Windows-only or older-Python dependencies just because the
                # scanner is running on a different host.
                mentioned = set(_mentioned_extras(marker_text))
                if not mentioned or not selected_extras or mentioned & set(selected_extras):
                    matched = True
                    break
                continue
            candidate_extras: tuple[str, ...]
            if installed_tree and not selected_extras:
                candidate_extras = ("",)
            else:
                candidate_extras = selected_extras or tuple(
                    dict.fromkeys(("", *_mentioned_extras(marker_text)))
                )
            if any(marker.evaluate({**target, "extra": extra}) for extra in candidate_extras):
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
    metadata["declaredOnly"] = declared_only
    return replace(
        scan,
        components=tuple(components),
        findings=tuple(findings),
        dependencies=tuple(dependencies),
        metadata=metadata,
    )


_EXTRA_MARKER_RE = re.compile(r"""extra\s*(?:==|!=|in|not\s+in)\s*['"]([^'"]+)['"]""")


def _mentioned_extras(marker_text: str) -> tuple[str, ...]:
    """Extract extras named by a marker without selecting them implicitly.

    Optional and development dependencies carry ``extra == "name"`` markers.
    When the caller did not select extras, those entries are still part of the
    declared inventory; platform and Python-version conditions are evaluated
    normally while the extra clause is satisfied by its own declared name.
    """

    return tuple(dict.fromkeys(_EXTRA_MARKER_RE.findall(marker_text)))


def _property_values(component: Mapping[str, Any], name: str) -> list[str]:
    return [
        str(item.get("value"))
        for item in component.get("properties", ())
        if isinstance(item, dict) and item.get("name") == name
    ]
