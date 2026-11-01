"""Component normalization, merging, and dependency graph helpers."""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping
from urllib.parse import quote, unquote

from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

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
            return str(specifier.version)
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


def best_dependency_ref(
    name: str,
    refs_by_name: dict[str, list[str]],
    constraint: str | None = None,
) -> str:
    canonical = canonicalize_name(name)
    refs = sorted(set(refs_by_name.get(canonical, ())))
    if constraint and len(refs) > 1:
        try:
            specifier = SpecifierSet(constraint)
        except InvalidSpecifier:
            specifier = None
        if specifier is not None:
            matching = [
                reference for reference in refs if _purl_version_matches(reference, specifier)
            ]
            if len(matching) == 1:
                return matching[0]
    if refs:
        return refs[0]
    return f"pkg:pypi/{canonical}"


def _purl_version_matches(reference: str, specifier: SpecifierSet) -> bool:
    _prefix, separator, version_text = reference.rpartition("@")
    if not separator:
        return False
    version_text = unquote(version_text.split("?", 1)[0].split("#", 1)[0])
    try:
        return Version(version_text) in specifier
    except InvalidVersion:
        return False


def dedupe_components(
    components: Iterable[dict[str, Any]],
    *,
    ref_map: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    components = list(components)
    applications = {item["name"]: item for item in components if item.get("type") == "application"}
    # A lockfile can supply a dynamic root version absent from pyproject.toml.
    # Carry the root's license/type into that local project entry before merge.
    for item in components:
        root = applications.get(item.get("name"))
        same_version = False
        if root is not None:
            try:
                same_version = Version(str(root.get("version"))) == Version(
                    str(item.get("version"))
                )
            except InvalidVersion:
                same_version = root.get("version") == item.get("version")
        if root is not None and root is not item and (not root.get("version") or same_version):
            item["type"] = "application"
            if root.get("licenses") and not item.get("licenses"):
                item["licenses"] = list(root["licenses"])
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

    by_name: dict[str, list[dict[str, Any]]] = {}
    for comp in deduped.values():
        cname = canonicalize_name(str(comp.get("name", "")))
        by_name.setdefault(cname, []).append(comp)

    final_components: list[dict[str, Any]] = []
    for group_name, group in by_name.items():
        unversioned = [item for item in group if not item.get("version")]
        versioned = [item for item in group if item.get("version")]
        if unversioned and versioned:
            target = versioned[0]
            if len(versioned) > 1:
                app_versioned = [item for item in versioned if item.get("type") == "application"]
                if app_versioned:
                    target = app_versioned[0]
                else:
                    # Multiple locked versions exist (monorepos, resolution
                    # groups).  Do not guess which one an unversioned range
                    # means; keep both rather than pinning to the lowest.
                    final_components.extend(unversioned)
                    final_components.extend(versioned)
                    continue
            for unv in unversioned:
                _merge_component(target, unv)
                target_ref = str(target.get("purl") or target.get("name"))
                if ref_map is not None:
                    if unv.get("purl"):
                        ref_map[str(unv["purl"])] = target_ref
                    if unv.get("name"):
                        ref_map[str(unv["name"])] = target_ref
            final_components.extend(versioned)
        else:
            final_components.extend(group)

    result = sorted(
        final_components,
        key=lambda item: (
            str(item.get("purl") or item.get("name")),
            str(item.get("version") or ""),
        ),
    )
    for component_data in result:
        for field in {"hashes", "licenses", "properties", "externalReferences"}:
            values = component_data.get(field)
            if isinstance(values, list):
                values.sort(
                    key=lambda item: json.dumps(
                        item, sort_keys=True, separators=(",", ":"), default=str
                    )
                )
    return result


def _merge_component(target: dict[str, Any], source: dict[str, Any]) -> None:
    if source.get("type") == "application":
        target["type"] = "application"
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
    *,
    ref_map: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    grouped: dict[str, set[str]] = {}
    for source, target in dependencies:
        if ref_map:
            source = ref_map.get(source, source)
            target = ref_map.get(target, target)
        if source and target and source != target:
            grouped.setdefault(source, set()).add(target)
    all_targets = {target for targets in grouped.values() for target in targets}
    for target in all_targets:
        grouped.setdefault(target, set())
    return [
        {"ref": source, "dependsOn": sorted(targets)} for source, targets in sorted(grouped.items())
    ]


def propagate_dependency_scopes(
    components: list[dict[str, Any]],
    dependencies: list[dict[str, Any]],
) -> None:
    """Propagate non-runtime scopes to transitive dependencies not needed at runtime."""

    comp_by_ref: dict[str, dict[str, Any]] = {}
    for comp in components:
        purl = comp.get("purl")
        if purl:
            comp_by_ref[str(purl)] = comp
            prefix, separator, _version = str(purl).rpartition("@")
            if separator:
                comp_by_ref.setdefault(prefix, comp)
        name = comp.get("name")
        if name:
            cname = canonicalize_name(str(name))
            comp_by_ref.setdefault(f"pkg:pypi/{cname}", comp)
            comp_by_ref.setdefault(str(name), comp)

    adj: dict[str, set[str]] = {}
    for dep in dependencies:
        source = str(dep.get("ref", ""))
        targets = [str(t) for t in dep.get("dependsOn", ()) or ()]
        if source:
            adj.setdefault(source, set()).update(targets)

    def _comp_for_ref(ref: str) -> dict[str, Any] | None:
        comp = comp_by_ref.get(ref)
        if comp is not None:
            return comp
        prefix, separator, _version = ref.rpartition("@")
        if separator:
            return comp_by_ref.get(prefix)
        return None

    runtime_roots: set[str] = set()
    for comp in components:
        props = [p for p in comp.get("properties", ()) if isinstance(p, dict)]
        scopes = {str(p.get("value", "")) for p in props if p.get("name") == "pyflow:scope"}
        ref = str(comp.get("purl") or comp.get("name") or "")
        if not ref:
            continue
        is_runtime = bool(scopes & {"runtime", "default", "main"})
        if is_runtime:
            runtime_roots.add(ref)

    runtime_reachable: set[str] = set()
    queue = list(runtime_roots)
    while queue:
        curr = queue.pop(0)
        if curr in runtime_reachable:
            continue
        runtime_reachable.add(curr)
        prefix, separator, _version = curr.rpartition("@")
        if separator:
            runtime_reachable.add(prefix)
        for nxt in adj.get(curr, ()):
            if nxt not in runtime_reachable:
                queue.append(nxt)

    # For any component reachable from runtime roots, ensure it has runtime scope
    # if it had no scope before
    for ref in runtime_reachable:
        comp = _comp_for_ref(ref)
        if comp is not None:
            props = [p for p in comp.get("properties", ()) if isinstance(p, dict)]
            scopes = {str(p.get("value", "")) for p in props if p.get("name") == "pyflow:scope"}
            if not scopes:
                add_property(comp, "pyflow:scope", "runtime")

    # Propagate non-runtime scopes to components not reachable from runtime roots
    for comp in components:
        ref = str(comp.get("purl") or comp.get("name") or "")
        if not ref:
            continue
        props = [p for p in comp.get("properties", ()) if isinstance(p, dict)]
        comp_scopes = {
            str(p.get("value", ""))
            for p in props
            if p.get("name") == "pyflow:scope"
            and str(p.get("value", "")) not in {"", "runtime", "default", "main"}
        }
        if not comp_scopes:
            continue

        non_runtime_queue = list(adj.get(ref, ()))
        seen: set[str] = set()
        while non_runtime_queue:
            target_ref = non_runtime_queue.pop(0)
            if target_ref in seen or target_ref in runtime_reachable:
                continue
            seen.add(target_ref)
            target_comp = _comp_for_ref(target_ref)
            if target_comp is not None:
                target_props = [p for p in target_comp.get("properties", ()) if isinstance(p, dict)]
                target_scopes = {
                    str(p.get("value", "")) for p in target_props if p.get("name") == "pyflow:scope"
                }
                if not (target_scopes & {"runtime", "default", "main"}):
                    for scope in sorted(comp_scopes):
                        add_property(target_comp, "pyflow:scope", scope)
            for nxt in adj.get(target_ref, ()):
                if nxt not in seen and nxt not in runtime_reachable:
                    non_runtime_queue.append(nxt)
