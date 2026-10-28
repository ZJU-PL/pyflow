"""Orchestration for local Python supply-chain analysis.

Specialized parsing and security logic lives in sibling modules. This module
is intentionally limited to target traversal, dispatch, and result assembly.
"""

from __future__ import annotations

import fnmatch
import os
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable, Iterator

from packaging.requirements import InvalidRequirement, Requirement

from .archives import (
    audit_archive_identity,
    audit_archive_payload,
    extract_archive,
    looks_like_archive,
)
from .distribution_integrity import audit_distribution_record
from .input_safety import read_error
from .inventory import (
    add_property,
    dedupe_components,
    dedupe_dependencies,
    dedupe_findings,
)
from .licenses import audit_license_policy as audit_license_policy
from .manifests import (
    component_from_metadata,
    components_from_pipfile_lock,
    components_from_pylock,
    components_from_pyproject,
    components_from_requirements,
    components_from_setup_cfg,
    components_from_setup_py,
    components_from_toml_lock,
    metadata_dependencies,
)
from .models import (
    ScanLimits,
    SupplyChainFinding,
    SupplyChainScan,
    validate_limits,
)

__all__ = [
    "ScanLimits",
    "SupplyChainFinding",
    "SupplyChainScan",
    "audit_license_policy",
    "scan_targets",
]


DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    ".bzr",
    "__pycache__",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
)


def scan_targets(
    targets: Iterable[str | os.PathLike[str]],
    *,
    recursive: bool = False,
    exclude: Iterable[str] = (),
    limits: ScanLimits | None = None,
    default_excludes: bool = True,
) -> SupplyChainScan:
    """Scan local paths for package metadata, manifests, and archive issues."""

    user_excludes = tuple(str(item).strip() for item in exclude if str(item).strip())
    excluded = (DEFAULT_EXCLUDES + user_excludes) if default_excludes else user_excludes
    effective_limits = limits or ScanLimits()
    validate_limits(effective_limits)
    components: list[dict[str, Any]] = []
    findings: list[SupplyChainFinding] = []
    dependencies: list[tuple[str, str]] = []
    seen_files: set[Path] = set()
    scan_entries = [0]
    artifacts: list[str] = []

    target_values = [str(target) for target in targets]
    for target in target_values:
        path = Path(target)
        if _is_excluded(path, excluded):
            continue
        if not path.exists() and not path.is_symlink():
            findings.append(
                SupplyChainFinding(
                    kind="missing-target",
                    message="Supply-chain target does not exist",
                    location=str(path),
                    severity="HIGH",
                )
            )
            continue
        _scan_path(
            path,
            recursive=recursive or _looks_like_installed_tree(path),
            excluded=excluded,
            components=components,
            findings=findings,
            dependencies=dependencies,
            seen_files=seen_files,
            limits=effective_limits,
            archive_depth=0,
            scan_entries=scan_entries,
            artifacts=artifacts,
            report_unsupported=True,
        )

    final_findings = tuple(dedupe_findings(findings))
    incomplete_kinds = {
        "missing-target",
        "file-read-error",
        "manifest-size-limit",
        "scan-entry-limit",
        "invalid-requirement",
        "invalid-lockfile",
        "invalid-pyproject",
        "invalid-pylock",
        "invalid-setup-config",
        "invalid-setup-script",
        "dynamic-dependency-metadata",
        "unpinned-requirement",
        "remote-requirement",
        "local-path-requirement",
        "missing-requirement-include",
        "requirement-include-symlink",
        "unversioned-lock-package",
        "archive-read-error",
        "archive-unrecognized-format",
        "archive-missing-package-metadata",
        "archive-file-size-limit",
        "archive-member-limit",
        "archive-expanded-size-limit",
        "archive-nesting-limit",
        "unsupported-supply-chain-target",
    }
    inventory_limitations = sorted(
        {finding.kind for finding in final_findings if finding.kind in incomplete_kinds}
    )
    inventory_evidence = sorted(
        {
            str(prop.get("value"))
            for component in components
            for prop in component.get("properties", ())
            if isinstance(prop, dict)
            and prop.get("name") == "pyflow:source-file"
            and prop.get("value")
        }
    )
    ref_map: dict[str, str] = {}
    deduped_components = dedupe_components(components, ref_map=ref_map)
    deduped_dependencies = dedupe_dependencies(dependencies, ref_map=ref_map)
    return SupplyChainScan(
        components=tuple(deduped_components),
        findings=final_findings,
        dependencies=tuple(deduped_dependencies),
        metadata={
            "targets": target_values,
            "artifacts": sorted(set(artifacts)),
            "inventoryComplete": not inventory_limitations,
            "inventoryEvidence": inventory_evidence,
            "inventoryLimitations": inventory_limitations,
        },
    )


def _scan_path(
    path: Path,
    *,
    recursive: bool,
    excluded: tuple[str, ...],
    components: list[dict[str, Any]],
    findings: list[SupplyChainFinding],
    dependencies: list[tuple[str, str]],
    seen_files: set[Path],
    limits: ScanLimits,
    archive_depth: int,
    scan_entries: list[int],
    artifacts: list[str],
    report_unsupported: bool,
) -> None:
    if _is_excluded(path, excluded):
        return
    if path.is_symlink():
        _audit_filesystem_symlink(path, findings)
        return
    if path.is_dir():
        for child in _iter_directory_files(
            path,
            recursive,
            excluded,
            findings,
            limits,
            scan_entries,
        ):
            _scan_path(
                child,
                recursive=False,
                excluded=excluded,
                components=components,
                findings=findings,
                dependencies=dependencies,
                seen_files=seen_files,
                limits=limits,
                archive_depth=archive_depth,
                scan_entries=scan_entries,
                artifacts=artifacts,
                report_unsupported=False,
            )
        return
    try:
        is_file = path.is_file()
    except OSError as exc:
        findings.append(read_error(path, exc))
        return
    if not is_file:
        return

    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        findings.append(read_error(path, exc))
        return
    if resolved in seen_files:
        return
    seen_files.add(resolved)

    name = path.name
    component_start = len(components)
    scanned_archive = False
    recognized_input = False
    if name in {"METADATA", "PKG-INFO"} and _is_metadata_path(path):
        recognized_input = True
        component = component_from_metadata(path, findings, limits)
        if component is not None:
            components.append(component)
            metadata_components, metadata_edges = metadata_dependencies(
                path, component, findings, limits
            )
            components.extend(metadata_components)
            dependencies.extend(metadata_edges)
        if path.parent.name.endswith(".dist-info"):
            findings.extend(audit_distribution_record(path.parent, limits))
    elif _is_requirements_file(path, limits):
        recognized_input = True
        components.extend(components_from_requirements(path, findings, limits))
    elif name == "pyproject.toml":
        recognized_input = True
        parsed_components, parsed_dependencies = components_from_pyproject(path, findings, limits)
        components.extend(parsed_components)
        dependencies.extend(parsed_dependencies)
    elif name in {"poetry.lock", "pdm.lock", "uv.lock"}:
        recognized_input = True
        parsed_components, parsed_dependencies = components_from_toml_lock(path, findings, limits)
        components.extend(parsed_components)
        dependencies.extend(parsed_dependencies)
    elif name == "Pipfile.lock":
        recognized_input = True
        components.extend(components_from_pipfile_lock(path, findings, limits))
    elif name == "pylock.toml" or name.endswith(".pylock.toml"):
        recognized_input = True
        parsed_components, parsed_dependencies = components_from_pylock(path, findings, limits)
        components.extend(parsed_components)
        dependencies.extend(parsed_dependencies)
    elif name == "setup.cfg":
        recognized_input = True
        components.extend(components_from_setup_cfg(path, findings, limits))
    elif name == "setup.py":
        recognized_input = True
        components.extend(components_from_setup_py(path, findings, limits))
    elif looks_like_archive(path):
        recognized_input = True
        scanned_archive = True
        artifacts.append(str(path))
        _scan_archive(
            path,
            excluded=excluded,
            components=components,
            findings=findings,
            dependencies=dependencies,
            seen_files=seen_files,
            limits=limits,
            archive_depth=archive_depth,
            scan_entries=scan_entries,
            artifacts=artifacts,
        )
    if not scanned_archive:
        _tag_component_sources(components[component_start:], str(path))
    if report_unsupported and not recognized_input:
        findings.append(
            SupplyChainFinding(
                kind="unsupported-supply-chain-target",
                message="Target is not a supported Python package, manifest, or archive",
                location=str(path),
                severity="HIGH",
            )
        )


def _scan_archive(
    path: Path,
    *,
    excluded: tuple[str, ...],
    components: list[dict[str, Any]],
    findings: list[SupplyChainFinding],
    dependencies: list[tuple[str, str]],
    seen_files: set[Path],
    limits: ScanLimits,
    archive_depth: int,
    scan_entries: list[int],
    artifacts: list[str],
) -> None:
    if archive_depth >= limits.max_archive_depth:
        findings.append(
            SupplyChainFinding(
                kind="archive-nesting-limit",
                message="Archive nesting exceeds the configured scan depth",
                location=str(path),
                severity="HIGH",
                details={"depth": archive_depth + 1, "limit": limits.max_archive_depth},
            )
        )
        return

    with tempfile.TemporaryDirectory(prefix="pyflow_supply_chain_") as tmp:
        destination = Path(tmp)
        finding_start = len(findings)
        if not extract_archive(path, destination, findings, limits):
            _remap_archive_findings(findings, finding_start, destination, path)
            return
        component_start = len(components)
        _scan_path(
            destination,
            recursive=True,
            excluded=excluded,
            components=components,
            findings=findings,
            dependencies=dependencies,
            seen_files=seen_files,
            limits=limits,
            archive_depth=archive_depth + 1,
            scan_entries=scan_entries,
            artifacts=artifacts,
            report_unsupported=False,
        )
        _remap_archive_findings(findings, finding_start, destination, path)
        _remap_archive_component_sources(components[component_start:], destination, path)
        audit_archive_payload(path, destination, findings, limits)
        audit_archive_identity(path, components[component_start:], findings)


def _remap_archive_findings(
    findings: list[SupplyChainFinding],
    start: int,
    destination: Path,
    archive_path: Path,
) -> None:
    """Replace temporary extraction paths with stable archive-member locations."""

    variants = _path_variants(destination)
    for index in range(start, len(findings)):
        finding = findings[index]
        relative = _relative_to_variants(finding.location, variants)
        if relative is None:
            continue
        findings[index] = replace(
            finding,
            location=f"{archive_path}!/{relative}",
            details=_remap_detail_paths(finding.details, variants, archive_path),
        )


def _tag_component_sources(components: Iterable[dict[str, Any]], source: str) -> None:
    for component in components:
        add_property(component, "pyflow:source-file", source)


def _remap_archive_component_sources(
    components: Iterable[dict[str, Any]], destination: Path, archive_path: Path
) -> None:
    variants = _path_variants(destination)
    for component in components:
        for prop in component.get("properties", ()):
            if not isinstance(prop, dict) or prop.get("name") != "pyflow:source-file":
                continue
            value = str(prop.get("value", ""))
            relative = _relative_to_variants(value, variants)
            if relative is None:
                continue
            prop["value"] = f"{archive_path}!/{relative}"


def _path_variants(path: Path) -> list[tuple[str, Path]]:
    """Return both lexical and resolved spellings of a temporary directory."""

    variants: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for candidate in (path, path.resolve(strict=False)):
        text = str(candidate)
        if text in seen:
            continue
        seen.add(text)
        variants.append((text, candidate))
    return variants


def _relative_to_variants(location: str, variants: list[tuple[str, Path]]) -> str | None:
    for text, root in variants:
        if location == text:
            return "."
        prefix = text.rstrip(os.sep) + os.sep
        if not location.startswith(prefix):
            continue
        try:
            return Path(location).relative_to(root).as_posix()
        except ValueError:
            continue
    return None


def _remap_detail_paths(
    details: dict[str, Any],
    variants: list[tuple[str, Path]],
    archive_path: Path,
) -> dict[str, Any]:
    remapped: dict[str, Any] = {}
    for key, value in details.items():
        if isinstance(value, str):
            relative = _relative_to_variants(value, variants)
            remapped[key] = f"{archive_path}!/{relative}" if relative is not None else value
        elif isinstance(value, list):
            remapped[key] = [
                (
                    f"{archive_path}!/{relative}"
                    if isinstance(item, str)
                    and (relative := _relative_to_variants(item, variants)) is not None
                    else item
                )
                for item in value
            ]
        else:
            remapped[key] = value
    return remapped


def _iter_directory_files(
    root: Path,
    recursive: bool,
    excluded: tuple[str, ...],
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
    scan_entries: list[int],
) -> Iterator[Path]:
    """Yield directory files once, without following symlinked directories."""

    try:
        children = root.iterdir()
    except OSError as exc:
        findings.append(read_error(root, exc))
        return

    for child in children:
        scan_entries[0] += 1
        if scan_entries[0] > limits.max_scan_entries:
            if not any(finding.kind == "scan-entry-limit" for finding in findings):
                findings.append(
                    SupplyChainFinding(
                        kind="scan-entry-limit",
                        message="Directory traversal exceeded the configured entry limit",
                        location=str(root),
                        severity="HIGH",
                        details={"limit": limits.max_scan_entries},
                    )
                )
            return
        if _is_excluded(child, excluded):
            continue
        if child.is_symlink():
            _audit_filesystem_symlink(child, findings)
            continue
        try:
            if child.is_file():
                yield child
            elif recursive and child.is_dir():
                yield from _iter_directory_files(
                    child,
                    True,
                    excluded,
                    findings,
                    limits,
                    scan_entries,
                )
        except OSError as exc:
            findings.append(read_error(child, exc))


def _audit_filesystem_symlink(
    path: Path,
    findings: list[SupplyChainFinding],
) -> None:
    try:
        target = os.readlink(path)
    except OSError as exc:
        findings.append(read_error(path, exc))
        return
    findings.append(
        SupplyChainFinding(
            kind="filesystem-symlink",
            message="Symlink was not followed while scanning untrusted inputs",
            location=str(path),
            severity="LOW",
            details={"target": target},
        )
    )


def _is_requirements_file(path: Path, limits: ScanLimits | None = None) -> bool:
    lowered = path.name.lower()
    if path.suffix.lower() not in {".txt", ".in"}:
        return False
    if lowered.startswith(("requirements", "constraints")):
        return True
    if lowered.endswith(("-requirements.txt", "_requirements.txt", "-constraints.txt")):
        return True
    if path.parent.name.lower() in {"requirements", "reqs", "constraints"}:
        return True
    if path.parent.name.lower().endswith((".dist-info", ".egg-info")):
        return False
    return limits is not None and _sniff_requirements_content(path, limits)


def _sniff_requirements_content(path: Path, limits: ScanLimits) -> bool:
    """Detect requirement files that do not follow a conventional name."""

    try:
        if path.stat().st_size > limits.max_manifest_size:
            return False
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(min(limits.max_manifest_size, 64 * 1024))
    except OSError:
        return False

    checked = 0
    strong = False
    for raw_line in text.splitlines()[:200]:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(
            (
                "-r ",
                "--requirement",
                "-c ",
                "--constraint",
                "--index-url",
                "--extra-index-url",
                "--find-links",
                "--trusted-host",
                "--no-index",
                "--require-hashes",
                "--only-binary",
                "--no-binary",
                "--pre",
                "--prefer-binary",
            )
        ):
            checked += 1
            strong = True
            continue
        if line.startswith(("-", "git+", "hg+", "svn+", "bzr+", "http://", "https://")):
            checked += 1
            strong = True
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            return False
        if not requirement.name:
            return False
        checked += 1
        if requirement.specifier or requirement.url:
            strong = True
    # A bare module name is also valid in a conventional requirements file, but
    # is far too weak a signal to reclassify arbitrary .txt metadata.
    return checked > 0 and strong


def _is_metadata_path(path: Path) -> bool:
    parent = path.parent.name
    if path.name == "PKG-INFO":
        return True
    return parent.endswith(".dist-info") or parent.endswith(".egg-info")


def _looks_like_installed_tree(path: Path) -> bool:
    if not path.is_dir():
        return False
    if path.name.lower() in {"site-packages", "dist-packages"}:
        return True
    try:
        return any(
            child.is_dir() and child.name.endswith((".dist-info", ".egg-info"))
            for child in path.iterdir()
        )
    except OSError:
        return False


def _is_excluded(path: Path, excluded: tuple[str, ...]) -> bool:
    path_text = path.as_posix()
    for pattern in excluded:
        normalized = pattern.replace("\\", "/").rstrip("/")
        if not normalized:
            continue
        if fnmatch.fnmatch(path_text, normalized) or fnmatch.fnmatch(path.name, normalized):
            return True
        if normalized in path.parts:
            return True
        try:
            if Path(normalized).resolve(strict=False) == path.resolve(strict=False):
                return True
        except OSError:
            pass
    return False
