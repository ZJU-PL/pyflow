"""Orchestration for local Python supply-chain analysis.

Specialized parsing and security logic lives in sibling modules. This module
is intentionally limited to target traversal, dispatch, and result assembly.
"""

from __future__ import annotations

import csv
import fnmatch
import os
import re
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
    components_from_pipfile,
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
    installed_flags: list[bool] = []
    for target in target_values:
        path = Path(target)
        if _is_excluded(path, user_excludes):
            continue
        # Default excludes are meant for descendants.  A user who explicitly
        # names .venv or site-packages wants that tree inspected.
        target_excluded = excluded
        if default_excludes:
            target_excluded = tuple(
                pattern for pattern in excluded if not _path_matches_pattern(path, pattern)
            )
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
        target_installed = _target_is_installed_tree(path)
        installed_flags.append(target_installed)
        scan_path = path
        if path.is_symlink():
            try:
                resolved_target = path.resolve(strict=True)
            except OSError:
                resolved_target = None
            if resolved_target is not None and resolved_target.is_dir():
                _audit_filesystem_symlink(path, findings)
                scan_path = resolved_target
        recognized = _scan_path(
            scan_path,
            recursive=recursive or _looks_like_installed_tree(scan_path),
            excluded=target_excluded,
            components=components,
            findings=findings,
            dependencies=dependencies,
            seen_files=seen_files,
            limits=effective_limits,
            archive_depth=0,
            scan_entries=scan_entries,
            artifacts=artifacts,
            scan_root=scan_path.parent if scan_path.is_file() else scan_path,
            report_unsupported=True,
        )
        if path.is_dir() and not recognized:
            nested, package_like = _has_nested_manifest(path, effective_limits)
            findings.append(
                SupplyChainFinding(
                    kind="empty-supply-chain-inventory",
                    message=(
                        "Supply-chain target yielded no supported Python manifests, "
                        "package metadata, or archives"
                    ),
                    location=str(path),
                    severity="HIGH" if package_like else "MEDIUM",
                    details={
                        "nested_manifests": nested,
                        "package_like": package_like,
                        "hint": (
                            "Use --recursive for repositories whose manifests are in "
                            "subdirectories, or pass the package directory explicitly."
                        ),
                    },
                )
            )

    installed_target = bool(installed_flags) and all(installed_flags)
    findings = _drop_shared_namespace_findings(findings, components)
    findings = _classify_startup_hooks(findings, target_values, effective_limits)
    findings = _downgrade_non_shipping_archive_findings(findings)
    final_findings = tuple(dedupe_findings(findings))
    incomplete_kinds = {
        "missing-target",
        "empty-supply-chain-inventory",
        "file-read-error",
        "manifest-size-limit",
        "scan-entry-limit",
        "invalid-requirement",
        "invalid-lockfile",
        "invalid-pipfile",
        "invalid-pyproject",
        "metadata-missing-name",
        "metadata-missing-version",
        "dependency-group-cycle",
        "unresolved-dependency-group",
        "invalid-pylock",
        "invalid-setup-config",
        "invalid-setup-script",
        "unresolved-setup-requirements",
        "dynamic-dependency-metadata",
        "unpinned-requirement",
        "unpinned-vcs-dependency",
        "remote-requirement",
        "local-path-requirement",
        "editable-requirement",
        "invalid-requirement-include",
        "requirement-include-cycle",
        "external-requirement-include",
        "missing-requirement-include",
        "requirement-include-symlink",
        "invalid-lock-package",
        "unversioned-lock-package",
        "archive-read-error",
        "archive-unrecognized-format",
        "archive-missing-package-metadata",
        "archive-metadata-name-mismatch",
        "archive-metadata-version-mismatch",
        "archive-dist-info-mismatch",
        "archive-multiple-dist-info",
        "archive-file-size-limit",
        "archive-member-limit",
        "archive-expanded-size-limit",
        "archive-nesting-limit",
        "unsupported-supply-chain-target",
    }

    def limits_inventory(finding: SupplyChainFinding) -> bool:
        if finding.kind not in incomplete_kinds:
            return False
        if finding.kind == "remote-requirement" and finding.details.get("pinned") is True:
            return False
        return True

    inventory_limitations = sorted(
        {finding.kind for finding in final_findings if limits_inventory(finding)}
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
            "installed": installed_target,
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
    scan_root: Path,
    report_unsupported: bool,
) -> bool:
    if _is_excluded(path, excluded):
        return False
    if path.is_symlink():
        try:
            resolved = path.resolve(strict=True)
            root_resolved = scan_root.resolve(strict=False)
        except OSError:
            _audit_filesystem_symlink(path, findings)
            return False
        if not resolved.is_file() or not _is_relative_to(resolved, root_resolved):
            # Do not follow links out of the explicitly selected tree or into
            # directories, and keep the symlink finding for those cases.
            _audit_filesystem_symlink(path, findings)
            return False
    if path.is_dir():
        recognized = False
        for child in _iter_directory_files(
            path,
            recursive,
            excluded,
            findings,
            limits,
            scan_entries,
            scan_root,
        ):
            recognized = (
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
                    scan_root=scan_root,
                    report_unsupported=False,
                )
                or recognized
            )
        return recognized
    try:
        is_file = path.is_file()
    except OSError as exc:
        findings.append(read_error(path, exc))
        return False
    if not is_file:
        return False

    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        findings.append(read_error(path, exc))
        return False
    if resolved in seen_files:
        return False
    seen_files.add(resolved)

    name = path.name
    if name.lower().endswith(".pth") or name in {"sitecustomize.py", "usercustomize.py"}:
        if path.parent.name.lower() in {"site-packages", "dist-packages"}:
            findings.append(
                SupplyChainFinding(
                    kind="python-startup-hook",
                    message=(
                        "Installed tree contains a file that runs automatically at "
                        "Python interpreter startup"
                    ),
                    location=str(path),
                    severity="HIGH",
                )
            )
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
            findings.extend(audit_distribution_record(path.parent, limits, component))
    elif _is_requirements_file(path, limits):
        recognized_input = True
        components.extend(components_from_requirements(path, findings, limits, root=scan_root))
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
    elif name == "Pipfile":
        recognized_input = True
        components.extend(components_from_pipfile(path, findings, limits))
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
            scan_root=scan_root,
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
    return recognized_input


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
    scan_root: Path,
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
            scan_root=destination,
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


_NON_SHIPPING_PARTS = frozenset(
    {"doc", "docs", "example", "examples", "fixture", "fixtures", "test", "tests", "testdata"}
)
_ARCHIVE_STRUCTURAL_KINDS = frozenset(
    {
        "archive-absolute-path",
        "archive-case-collision",
        "archive-duplicate-entry",
        "archive-encrypted-entry",
        "archive-expanded-size-limit",
        "archive-file-size-limit",
        "archive-invalid-path",
        "archive-invalid-size",
        "archive-link-entry",
        "archive-member-limit",
        "archive-member-too-large",
        "archive-nonportable-path",
        "archive-parent-reference",
        "archive-path-conflict",
        "archive-read-error",
        "archive-special-file",
        "archive-suspicious-compression-ratio",
        "archive-unrecognized-format",
    }
)


def _downgrade_non_shipping_archive_findings(
    findings: Iterable[SupplyChainFinding],
) -> list[SupplyChainFinding]:
    """Keep test/docs archive fixtures visible without failing production gates."""

    result: list[SupplyChainFinding] = []
    for finding in findings:
        if finding.kind in _ARCHIVE_STRUCTURAL_KINDS:
            outer = finding.location.partition("!/")[0]
            parts = {part.casefold() for part in Path(outer).parts}
            if parts & _NON_SHIPPING_PARTS:
                finding = replace(
                    finding,
                    severity="LOW",
                    details={**finding.details, "context": "test-or-docs"},
                )
        result.append(finding)
    return result


def _installed_record_paths(targets: Iterable[str], limits: ScanLimits) -> set[Path]:
    listed: set[Path] = set()
    for target in targets:
        directory = Path(target)
        if not directory.is_dir():
            continue
        try:
            records = directory.rglob("RECORD")
        except OSError:
            continue
        for record in records:
            if record.is_symlink() or not record.parent.name.endswith(".dist-info"):
                continue
            try:
                if record.stat().st_size > limits.max_manifest_size:
                    continue
                text = record.read_text(encoding="utf-8-sig", errors="replace")
                root = record.parent.parent.resolve(strict=False)
                for row in csv.reader(text.splitlines()):
                    if row and row[0]:
                        listed.add((root / row[0].replace("\\", "/")).resolve(strict=False))
            except (OSError, csv.Error):
                continue
    return listed


def _classify_startup_hooks(
    findings: Iterable[SupplyChainFinding],
    targets: Iterable[str],
    limits: ScanLimits,
) -> list[SupplyChainFinding]:
    """Classify installed startup hooks by whether RECORD owns them.

    A RECORD entry does not make arbitrary startup code safe: ``.pth`` files
    execute imports at every interpreter start.  Unlisted hooks are HIGH;
    listed hooks are MEDIUM unless they match a known installer-generated
    pattern.  sitecustomize/usercustomize are always HIGH.
    """

    result = list(findings)
    hooks = [finding for finding in result if finding.kind == "python-startup-hook"]
    if not hooks:
        return result
    listed = _installed_record_paths(targets, limits)
    classified: list[SupplyChainFinding] = []
    for finding in result:
        if finding.kind != "python-startup-hook":
            classified.append(finding)
            continue
        path = Path(finding.location)
        if path.name in {"sitecustomize.py", "usercustomize.py"}:
            classified.append(finding)
            continue
        if path.resolve(strict=False) not in listed:
            classified.append(finding)
            continue
        name = path.name.lower()
        editable_style = name.startswith("__editable__")
        namespace_style = name.endswith("-nspkg.pth")
        distutils_style = name == "distutils-precedence.pth"
        installer_generated = (
            (editable_style and _looks_like_editable_pth(path))
            or (distutils_style and _looks_like_distutils_pth(path))
            or (namespace_style and _looks_like_namespace_pth(path))
        )
        if (editable_style or namespace_style or distutils_style) and not installer_generated:
            classified.append(
                replace(
                    finding,
                    severity="HIGH",
                    message=(
                        ".pth file uses an installer-style name but contains code "
                        "outside the expected generated pattern"
                    ),
                    details={**finding.details, "record_listed": True},
                )
            )
            continue
        if installer_generated:
            classified.append(
                replace(
                    finding,
                    severity="LOW",
                    message="Installer-generated .pth startup hook is listed in RECORD",
                    details={**finding.details, "record_listed": True},
                )
            )
        else:
            classified.append(
                replace(
                    finding,
                    severity="MEDIUM",
                    message=(
                        "Installed .pth startup hook is listed in RECORD; "
                        "review the code it executes"
                    ),
                    details={**finding.details, "record_listed": True},
                )
            )
    return classified


def _looks_like_distutils_pth(path: Path) -> bool:
    try:
        if path.stat().st_size > 64 * 1024:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "SETUPTOOLS_USE_DISTUTILS" in text and "_distutils_hack" in text


def _looks_like_namespace_pth(path: Path) -> bool:
    try:
        if path.stat().st_size > 64 * 1024:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "sys.modules.setdefault" in text and ("__path__" in text or "PathFinder" in text)


def _looks_like_editable_pth(path: Path) -> bool:
    """Recognize pip's editable-install .pth payload, not just its filename."""

    try:
        if path.stat().st_size > 64 * 1024:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    imports = [line for line in lines if line.startswith("import ")]
    if not imports:
        return True
    return all(re.match(r"import __editable___[A-Za-z0-9_.]+_finder\s*;", line) for line in imports)


def _iter_directory_files(
    root: Path,
    recursive: bool,
    excluded: tuple[str, ...],
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
    scan_entries: list[int],
    scan_root: Path,
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
            # Let _scan_path audit the link and decide whether it is a safe
            # in-tree file symlink or a directory link that must not be
            # followed.
            yield child
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
                    scan_root,
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


_REQUIREMENT_SCOPE_WORDS = frozenset(
    {
        "all",
        "base",
        "benchmark",
        "benchmarks",
        "build",
        "ci",
        "dev",
        "develop",
        "development",
        "doc",
        "docs",
        "editable",
        "example",
        "examples",
        "extra",
        "install",
        "lint",
        "main",
        "optional",
        "prod",
        "production",
        "release",
        "runtime",
        "security",
        "test",
        "tests",
        "testing",
        "type",
        "typing",
    }
)


def _first_requirement_line_valid(path: Path, limits: ScanLimits) -> bool:
    """Reject prose/docs files that merely use a requirements-like name."""

    try:
        if path.stat().st_size > limits.max_manifest_size:
            # Keep the named file recognized so read_text reports the size
            # limit instead of silently treating it as unsupported.
            return True
        text = path.read_text(encoding="utf-8-sig", errors="replace")[: 64 * 1024]
    except OSError:
        return False
    logical: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not logical and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            logical.append(stripped[:-1].strip())
            continue
        logical.append(stripped)
        break
    if not logical:
        # An empty/commented requirements file is a valid zero-dependency manifest.
        return True
    line = " ".join(logical)
    if "{{" in line or "{%" in line:
        return True
    line = re.sub(r"\s--hash(?:=|\s+)\S+", "", line).strip()
    line = line.split("#", 1)[0].strip()
    if not line:
        return False
    if line.startswith(
        (
            "-",
            "git+",
            "hg+",
            "svn+",
            "bzr+",
            "http://",
            "https://",
            "file:",
            ".",
            "/",
            "~",
        )
    ):
        return True
    try:
        Requirement(line)
    except InvalidRequirement:
        return False
    return True


def _is_requirements_file(path: Path, limits: ScanLimits | None = None) -> bool:
    lowered = path.name.lower()
    if path.suffix.lower() not in {".txt", ".in"}:
        return False
    scoped = re.match(r"(.+)[-_](?:requirements|constraints)\.txt$", lowered)
    named = (
        lowered.startswith(("requirements", "constraints"))
        or lowered
        in {
            "dependencies.in",
            "dependencies.txt",
            "deps.in",
            "deps.txt",
            "pip-requirements.txt",
        }
        or bool(scoped and scoped.group(1) in _REQUIREMENT_SCOPE_WORDS)
        or path.parent.name.lower() in {"requirements", "reqs", "constraints"}
        or lowered.endswith(("-constraints.txt",))
    )
    if named:
        if limits is None:
            return True
        return _first_requirement_line_valid(path, limits)
    if scoped and limits is None:
        return False
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
        if line.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://")):
            checked += 1
            strong = True
            continue
        if line.startswith("-"):
            # Unknown options are not evidence that arbitrary text data is a
            # requirements file (for example scikit-learn's "-1 ..." fixtures).
            return False
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
    if path.name.lower() in {"site-packages", "dist-packages", ".venv", "venv"}:
        return True
    if (path / "pyvenv.cfg").is_file():
        return True
    try:
        return any(
            child.is_dir() and child.name.endswith((".dist-info", ".egg-info"))
            for child in path.iterdir()
        )
    except OSError:
        return False


def _path_matches_pattern(path: Path, pattern: str) -> bool:
    normalized = pattern.replace("\\", "/").rstrip("/")
    if not normalized:
        return False
    path_text = path.as_posix()
    if fnmatch.fnmatch(path_text, normalized) or fnmatch.fnmatch(path.name, normalized):
        return True
    if normalized in path.parts:
        return True
    try:
        return Path(normalized).resolve(strict=False) == path.resolve(strict=False)
    except OSError:
        return False


def _is_excluded(path: Path, excluded: tuple[str, ...]) -> bool:
    return any(_path_matches_pattern(path, pattern) for pattern in excluded)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


_MANIFEST_NAMES = frozenset(
    {
        "Pipfile",
        "Pipfile.lock",
        "pdm.lock",
        "poetry.lock",
        "pylock.toml",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "uv.lock",
    }
)


def _has_nested_manifest(root: Path, limits: ScanLimits) -> tuple[bool, bool]:
    entries = 0
    limit = min(limits.max_scan_entries, 20_000)
    nested = False
    package_like = False
    auxiliary_parts = {
        "doc",
        "docs",
        "example",
        "examples",
        "script",
        "scripts",
        "tool",
        "tools",
        "topic",
        "topics",
    }
    try:
        for child in root.rglob("*"):
            entries += 1
            if entries > limit:
                break
            if child.is_symlink():
                continue
            manifest = child.name in _MANIFEST_NAMES or child.name.endswith(".pylock.toml")
            if not manifest and child.suffix.lower() in {".txt", ".in"}:
                manifest = _is_requirements_file(child, limits)
            if not manifest:
                continue
            nested = True
            parts = {part.casefold() for part in child.relative_to(root).parts[:-1]}
            if not parts or not (parts & auxiliary_parts):
                package_like = True
                break
    except (OSError, ValueError):
        pass
    return nested, package_like


def _target_is_installed_tree(path: Path) -> bool:
    if _looks_like_installed_tree(path):
        return True
    return path.name.lower().endswith((".dist-info", ".egg-info"))


def _drop_shared_namespace_findings(
    findings: Iterable[SupplyChainFinding],
    components: Iterable[dict[str, Any]],
) -> list[SupplyChainFinding]:
    """Suppress namespace-package false positives in installed trees.

    A site-packages tree can contain many distributions that legitimately share
    one import package (google, sphinxcontrib, opentelemetry, ...).  Without
    this guard every distribution is blamed for every sibling's files.
    """

    owners: dict[str, int] = {}
    for component in components:
        properties = [prop for prop in component.get("properties", ()) if isinstance(prop, dict)]
        if not any(
            prop.get("name") == "pyflow:metadata-source"
            and str(prop.get("value", "")).lower() == "true"
            for prop in properties
        ):
            continue
        component_roots = {
            str(prop["value"])
            for prop in properties
            if prop.get("name") in {"pyflow:import-name", "pyflow:owned-root"} and prop.get("value")
        }
        for root in component_roots:
            owners[root] = owners.get(root, 0) + 1
    shared = {root for root, count in owners.items() if count > 1}
    if not shared:
        return list(findings)

    result: list[SupplyChainFinding] = []
    shared_files: dict[str, list[str]] = {root: [] for root in shared}
    for finding in findings:
        root = str(finding.details.get("top_level", ""))
        if finding.kind == "record-unlisted-owned-file" and root in shared:
            shared_files[root].append(finding.location)
            continue
        result.append(finding)
    for root in sorted(shared):
        files = sorted(set(shared_files[root]))
        result.append(
            SupplyChainFinding(
                kind="shared-python-namespace",
                message=(
                    "Installed distributions share a Python namespace package; "
                    "per-file ownership cannot be attributed to one distribution"
                ),
                location=root,
                severity="LOW",
                details={
                    "top_level": root,
                    "distributions": owners[root],
                    "unlisted_file_count": len(files),
                    "unlisted_files": files[:20],
                },
            )
        )
    return result
