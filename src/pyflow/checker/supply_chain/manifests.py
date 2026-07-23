"""Parsers and risk checks for Python manifests and lockfiles."""

from __future__ import annotations

import ast
import configparser
import hashlib
import json
import re
from email.parser import Parser
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import parse_qs, urlparse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from .common import read_text as _read_text
from .common import redacted_url as _redacted_url
from .components import add_property as _add_property
from .components import best_dependency_ref as _best_dependency_ref
from .components import component as _component
from .components import cyclonedx_hash_name as _cyclonedx_hash_name
from .components import dedupe_hashes as _dedupe_hashes
from .components import exact_version as _exact_version
from .components import string_or_none as _string_or_none
from .licenses import license_entry as _license_entry
from .licenses import licenses_from_metadata as _licenses_from_metadata
from .models import ScanLimits, SupplyChainFinding

try:
    import tomllib  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[import-not-found]


_HASH_OPTION_RE = re.compile(r"(?:^|\s)--hash[=\s]+([A-Za-z0-9_-]+):([^\s]+)")


def _component_from_metadata(
    metadata_path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> dict[str, Any] | None:
    text = _read_text(metadata_path, findings, limits, "package metadata")
    if text is None:
        return None
    data = Parser().parsestr(text)
    name = data.get("Name")
    if not name:
        findings.append(
            SupplyChainFinding(
                kind="metadata-missing-name",
                message="Distribution metadata does not declare a project name",
                location=str(metadata_path),
                severity="HIGH",
            )
        )
        return None
    version = data.get("Version")
    component = _component(name, version=version)
    description = data.get("Description") or data.get("Summary")
    if description:
        component["description"] = description.strip()
    if author := data.get("Author-email"):
        component["author"] = author
    if publisher := data.get("Author"):
        component["publisher"] = publisher
    licenses = _licenses_from_metadata(data)
    if licenses:
        component["licenses"] = licenses
    if homepage := data.get("Home-page"):
        component["externalReferences"] = [
            {"type": "website", "url": _redacted_url(homepage.strip())}
        ]
    return component


def _metadata_dependencies(
    metadata_path: Path,
    parent: dict[str, Any],
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    text = _read_text(metadata_path, findings, limits, "package metadata")
    if text is None:
        return [], []
    data = Parser().parsestr(text)
    components: list[dict[str, Any]] = []
    edges: list[tuple[str, str]] = []
    parent_ref = str(parent.get("purl", ""))
    for value in data.get_all("Requires-Dist", []) or []:
        parsed = _parse_requirement(
            str(value), metadata_path, None, findings, audit_pin=False
        )
        if parsed is None:
            continue
        components.append(parsed)
        if parent_ref:
            edges.append((parent_ref, str(parsed["purl"])))
    return components, edges


def _components_from_requirements(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
    _stack: frozenset[Path] = frozenset(),
) -> list[dict[str, Any]]:
    resolved = path.resolve(strict=False)
    if resolved in _stack:
        findings.append(
            SupplyChainFinding(
                kind="requirement-include-cycle",
                message="Requirement files include each other cyclically",
                location=str(path),
                severity="HIGH",
            )
        )
        return []
    text = _read_text(path, findings, limits, "requirements file")
    if text is None:
        return []

    components: list[dict[str, Any]] = []
    for line_no, raw_line in _logical_requirement_lines(text):
        req_line = _strip_requirement_comment(raw_line).strip()
        if not req_line:
            continue
        include = _requirement_include(req_line)
        if include is not None:
            if not include:
                findings.append(
                    SupplyChainFinding(
                        kind="invalid-requirement-include",
                        message="Requirement include option has no path",
                        location=str(path),
                        severity="HIGH",
                        details={"line": line_no},
                    )
                )
                continue
            included_path = Path(include)
            if not included_path.is_absolute():
                included_path = path.parent / included_path
            if not included_path.exists():
                findings.append(
                    SupplyChainFinding(
                        kind="missing-requirement-include",
                        message="Included requirement or constraint file does not exist",
                        location=str(path),
                        severity="HIGH",
                        details={"line": line_no, "include": include},
                    )
                )
            else:
                components.extend(
                    _components_from_requirements(
                        included_path,
                        findings,
                        limits,
                        _stack | {resolved},
                    )
                )
            continue
        is_editable = req_line.startswith(("-e ", "--editable ", "--editable="))
        if not is_editable and _audit_pip_option(path, line_no, req_line, findings):
            continue

        hashes = _requirement_hashes(req_line, path, line_no, findings)
        requirement_text = _HASH_OPTION_RE.sub("", req_line).strip()
        if is_editable:
            if requirement_text.startswith("--editable="):
                requirement_text = requirement_text.partition("=")[2].strip()
            else:
                requirement_text = requirement_text.split(maxsplit=1)[-1]
            findings.append(
                SupplyChainFinding(
                    kind="editable-requirement",
                    message="Editable dependency can change without updating the manifest",
                    location=str(path),
                    severity="HIGH",
                    details={"line": line_no, "requirement": requirement_text},
                )
            )
        component = _parse_requirement(
            requirement_text,
            path,
            line_no,
            findings,
            audit_pin=True,
            hashes=hashes,
        )
        if component is not None:
            components.append(component)
    return components


def _logical_requirement_lines(text: str) -> Iterator[tuple[int, str]]:
    buffer: list[str] = []
    start_line = 1
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.rstrip()
        if not buffer:
            start_line = line_no
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1].strip())
            continue
        buffer.append(stripped)
        yield start_line, " ".join(part for part in buffer if part)
        buffer = []
    if buffer:
        yield start_line, " ".join(part for part in buffer if part)


def _strip_requirement_comment(line: str) -> str:
    for index, char in enumerate(line):
        if char == "#" and index > 0 and line[index - 1].isspace():
            return line[:index]
    return line


def _requirement_include(line: str) -> str | None:
    for option in ("-r", "--requirement", "-c", "--constraint"):
        if line == option:
            return ""
        if line.startswith(option + "="):
            return line[len(option) + 1 :].strip()
        if line.startswith(option + " "):
            return line[len(option) :].strip()
        if option in {"-r", "-c"} and line.startswith(option) and len(line) > 2:
            return line[2:].strip()
    return None


def _audit_pip_option(
    path: Path,
    line_no: int,
    line: str,
    findings: list[SupplyChainFinding],
) -> bool:
    option = line.split(maxsplit=1)[0].split("=", 1)[0]
    if option not in {
        "--index-url",
        "-i",
        "--extra-index-url",
        "--trusted-host",
        "--find-links",
        "-f",
        "--no-index",
        "--pre",
        "--only-binary",
        "--no-binary",
        "--prefer-binary",
    }:
        if line.startswith("-"):
            findings.append(
                SupplyChainFinding(
                    kind="unrecognized-requirement-option",
                    message="Requirement file contains an option the scanner cannot model",
                    location=str(path),
                    severity="LOW",
                    details={"line": line_no, "option": option},
                )
            )
            return True
        return False

    value = line[len(line.split(maxsplit=1)[0]) :].strip()
    if "=" in line.split(maxsplit=1)[0]:
        value = line.split("=", 1)[1].strip()
    if option == "--extra-index-url":
        findings.append(
            SupplyChainFinding(
                kind="multiple-package-indexes",
                message="Extra package indexes can introduce dependency-confusion risk",
                location=str(path),
                severity="HIGH",
                details={"line": line_no, "url": _redacted_url(value)},
            )
        )
    if option in {"--index-url", "-i", "--extra-index-url", "--find-links", "-f"}:
        _audit_index_url(path, value, findings, None)
    if option == "--trusted-host":
        findings.append(
            SupplyChainFinding(
                kind="insecure-package-index",
                message="Package source disables or bypasses transport authentication",
                location=str(path),
                severity="HIGH",
                details={
                    "line": line_no,
                    "option": option,
                    "value": _redacted_url(value),
                },
            )
        )
    return True


def _requirement_hashes(
    line: str,
    path: Path,
    line_no: int,
    findings: list[SupplyChainFinding],
) -> list[dict[str, str]]:
    hashes: list[dict[str, str]] = []
    for algorithm, digest in _HASH_OPTION_RE.findall(line):
        normalized = algorithm.lower().replace("-", "")
        if normalized not in hashlib.algorithms_guaranteed:
            findings.append(
                SupplyChainFinding(
                    kind="unsupported-requirement-hash",
                    message="Requirement uses an unsupported artifact hash algorithm",
                    location=str(path),
                    severity="HIGH",
                    details={"line": line_no, "algorithm": algorithm},
                )
            )
            continue
        if normalized in {"md5", "sha1"}:
            findings.append(
                SupplyChainFinding(
                    kind="weak-requirement-hash",
                    message="Requirement uses a collision-prone artifact hash",
                    location=str(path),
                    severity="HIGH",
                    details={"line": line_no, "algorithm": algorithm},
                )
            )
        expected_length = hashlib.new(normalized).digest_size * 2
        if not re.fullmatch(r"[A-Fa-f0-9]+", digest) or len(digest) != expected_length:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-requirement-hash",
                    message="Requirement artifact hash has an invalid digest length",
                    location=str(path),
                    severity="HIGH",
                    details={"line": line_no, "algorithm": algorithm},
                )
            )
            continue
        cyclonedx_name = _cyclonedx_hash_name(normalized)
        if cyclonedx_name is None:
            findings.append(
                SupplyChainFinding(
                    kind="unsupported-sbom-hash",
                    message=(
                        "Requirement hash cannot be represented in the selected "
                        "SBOM standards"
                    ),
                    location=str(path),
                    severity="LOW",
                    details={"line": line_no, "algorithm": algorithm},
                )
            )
            continue
        hashes.append({"alg": cyclonedx_name, "content": digest.lower()})
    return hashes


def _parse_requirement(
    requirement_text: str,
    path: Path,
    line_no: int | None,
    findings: list[SupplyChainFinding],
    *,
    audit_pin: bool,
    hashes: list[dict[str, str]] | None = None,
    scope: str | None = None,
) -> dict[str, Any] | None:
    details: dict[str, Any] = {"requirement": requirement_text}
    if line_no is not None:
        details["line"] = line_no
    try:
        requirement = Requirement(requirement_text)
    except InvalidRequirement:
        legacy = _component_from_legacy_reference(requirement_text)
        if requirement_text.startswith(
            ("git+", "hg+", "svn+", "bzr+", "http://", "https://")
        ):
            details["requirement"] = _redacted_url(requirement_text)
            findings.append(
                SupplyChainFinding(
                    kind="remote-requirement",
                    message="Requirement uses a legacy VCS or direct reference",
                    location=str(path),
                    severity="HIGH",
                    details=details,
                )
            )
            return legacy
        if _looks_like_local_requirement(requirement_text):
            findings.append(
                SupplyChainFinding(
                    kind="local-path-requirement",
                    message="Local path dependency is not reproducible outside this workspace",
                    location=str(path),
                    severity="MEDIUM",
                    details=details,
                )
            )
            return None
        findings.append(
            SupplyChainFinding(
                kind="invalid-requirement",
                message="Could not parse requirement",
                location=str(path),
                severity="LOW",
                details=details,
            )
        )
        return None

    version = _exact_version(requirement)
    component = _component(requirement.name, version=version)
    if requirement.specifier:
        _add_property(component, "pyflow:specifier", str(requirement.specifier))
    if requirement.marker:
        _add_property(component, "pyflow:marker", str(requirement.marker))
    if requirement.extras:
        _add_property(component, "pyflow:extras", ",".join(sorted(requirement.extras)))
    if scope:
        _add_property(component, "pyflow:scope", scope)
    if hashes:
        component["hashes"] = hashes
    if requirement.url:
        component["externalReferences"] = [
            {"type": "distribution", "url": _redacted_url(requirement.url)}
        ]
        url_details = dict(details)
        url_details["requirement"] = requirement_text.replace(
            requirement.url, _redacted_url(requirement.url)
        )
        url_details["url"] = _redacted_url(requirement.url)
        findings.append(
            SupplyChainFinding(
                kind="remote-requirement",
                message="Requirement bypasses normal package-index resolution",
                location=str(path),
                severity="HIGH" if _is_unpinned_vcs_url(requirement.url) else "MEDIUM",
                details=url_details,
            )
        )
        if urlparse(requirement.url).username or urlparse(requirement.url).password:
            findings.append(
                SupplyChainFinding(
                    kind="embedded-credentials",
                    message="Dependency URL contains embedded credentials",
                    location=str(path),
                    severity="CRITICAL",
                    details=url_details,
                )
            )
    elif audit_pin and version is None:
        findings.append(
            SupplyChainFinding(
                kind="unpinned-requirement",
                message="Dependency is not pinned to one immutable version",
                location=str(path),
                severity="MEDIUM",
                details=details,
            )
        )
    elif audit_pin and not hashes:
        findings.append(
            SupplyChainFinding(
                kind="requirement-missing-hash",
                message="Pinned dependency does not verify the downloaded artifact",
                location=str(path),
                severity="LOW",
                details=details,
            )
        )
    return component


def _component_from_legacy_reference(value: str) -> dict[str, Any] | None:
    if not value.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://")):
        return None
    fragment = parse_qs(urlparse(value).fragment)
    names = fragment.get("egg", [])
    if not names:
        filename = Path(urlparse(value).path).name
        try:
            if filename.endswith(".whl"):
                parsed_name, parsed_version, _build, _tags = parse_wheel_filename(
                    filename
                )
            else:
                parsed_name, parsed_version = parse_sdist_filename(filename)
        except (InvalidWheelFilename, InvalidSdistFilename):
            return None
        component = _component(str(parsed_name), version=str(parsed_version))
    else:
        component = _component(names[0])
    component["externalReferences"] = [
        {"type": "distribution", "url": _redacted_url(value)}
    ]
    return component


def _looks_like_local_requirement(value: str) -> bool:
    return value.startswith((".", "/", "~", "file:")) or Path(value).suffix in {
        ".whl",
        ".zip",
        ".gz",
    }


def _is_unpinned_vcs_url(value: str) -> bool:
    parsed = urlparse(value.removeprefix("git+").removeprefix("hg+"))
    path = parsed.path.rsplit("@", 1)
    if len(path) != 2:
        return value.startswith(("git+", "hg+", "svn+", "bzr+"))
    revision = path[1]
    return not bool(re.fullmatch(r"[0-9a-fA-F]{40,64}", revision))


def _components_from_pyproject(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    data = _load_toml(path, findings, limits, "invalid-pyproject")
    if data is None:
        return [], []

    components: list[dict[str, Any]] = []
    edges: list[tuple[str, str]] = []
    project = data.get("project", {}) or {}
    root: dict[str, Any] | None = None
    if project.get("name"):
        root = _component(
            str(project["name"]), version=_string_or_none(project.get("version"))
        )
        root["type"] = "application"
        project_license = project.get("license")
        if isinstance(project_license, str):
            root["licenses"] = [_license_entry(project_license)]
        elif isinstance(project_license, dict) and project_license.get("text"):
            root["licenses"] = [_license_entry(str(project_license["text"]))]
        components.append(root)

    declared: list[tuple[str, str]] = []
    for value in project.get("dependencies", ()) or ():
        declared.append((str(value), "runtime"))
    for group, values in (project.get("optional-dependencies", {}) or {}).items():
        for value in values or ():
            declared.append((str(value), f"optional:{group}"))
    for group, values in (data.get("dependency-groups", {}) or {}).items():
        for value in values or ():
            if isinstance(value, str):
                declared.append((value, f"group:{group}"))
    for value in (data.get("build-system", {}) or {}).get("requires", ()) or ():
        declared.append((str(value), "build"))

    poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
    poetry_groups: list[tuple[str, dict[str, Any]]] = [
        ("runtime", poetry.get("dependencies", {}) or {}),
        ("dev", poetry.get("dev-dependencies", {}) or {}),
    ]
    for group, group_data in (poetry.get("group", {}) or {}).items():
        poetry_groups.append(
            (f"group:{group}", (group_data or {}).get("dependencies", {}) or {})
        )
    for scope, dependency_map in poetry_groups:
        for name, value in dependency_map.items():
            if canonicalize_name(str(name)) == "python":
                continue
            requirement_text = _poetry_requirement(str(name), value)
            if requirement_text:
                declared.append((requirement_text, scope))

    for requirement_text, scope in declared:
        component = _parse_requirement(
            requirement_text,
            path,
            None,
            findings,
            audit_pin=True,
            scope=scope,
        )
        if component is None:
            continue
        components.append(component)
        if root is not None:
            edges.append((str(root["purl"]), str(component["purl"])))

    for source in poetry.get("source", ()) or ():
        if isinstance(source, dict):
            _audit_index_url(
                path,
                str(source.get("url", "")),
                findings,
                source.get("priority"),
            )
    return components, edges


def _poetry_requirement(name: str, value: Any) -> str | None:
    if isinstance(value, str):
        constraint = _normalize_poetry_constraint(value)
        return name if not constraint else f"{name}{constraint}"
    if not isinstance(value, dict):
        return None
    marker = value.get("markers")
    extras = value.get("extras") or ()
    display_name = (
        f"{name}[{','.join(str(item) for item in extras)}]" if extras else name
    )
    for key in ("git", "url", "path"):
        if value.get(key):
            requirement = f"{display_name} @ {value[key]}"
            if marker:
                requirement += f" ; {marker}"
            return requirement
    version = value.get("version")
    constraint = _normalize_poetry_constraint(str(version)) if version else ""
    requirement = display_name if not constraint else f"{display_name}{constraint}"
    if marker:
        requirement += f" ; {marker}"
    return requirement


def _normalize_poetry_constraint(value: str) -> str:
    value = value.strip()
    if not value or value == "*":
        return ""
    if value.startswith("^"):
        lower = value[1:]
        try:
            release = list(Version(lower).release)
        except InvalidVersion:
            return value
        while len(release) < 3:
            release.append(0)
        first_nonzero = next((index for index, part in enumerate(release) if part), 2)
        upper = release[:]
        upper[first_nonzero] += 1
        for index in range(first_nonzero + 1, len(upper)):
            upper[index] = 0
        upper_text = ".".join(str(part) for part in upper)
        return f">={lower},<{upper_text}"
    if value.startswith("~") and not value.startswith("~="):
        lower = value[1:]
        try:
            release = list(Version(lower).release)
        except InvalidVersion:
            return value
        precision = len(release)
        while len(release) < 2:
            release.append(0)
        upper_index = 0 if precision == 1 else 1
        upper = release[:]
        upper[upper_index] += 1
        for index in range(upper_index + 1, len(upper)):
            upper[index] = 0
        upper_text = ".".join(str(part) for part in upper)
        return f">={lower},<{upper_text}"
    if re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z*+-]+)*", value):
        return f"=={value}"
    return value


def _components_from_toml_lock(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    data = _load_toml(path, findings, limits, "invalid-lockfile")
    if data is None:
        return [], []
    raw_packages = data.get("package", ()) or data.get("packages", ()) or ()
    components: list[dict[str, Any]] = []
    dependency_names: list[tuple[str, str]] = []
    refs_by_name: dict[str, list[str]] = {}

    for package in raw_packages:
        if not isinstance(package, dict) or not package.get("name"):
            findings.append(
                SupplyChainFinding(
                    kind="invalid-lock-package",
                    message="Lockfile package entry is missing a project name",
                    location=str(path),
                    severity="HIGH",
                )
            )
            continue
        name = str(package["name"])
        version = _string_or_none(package.get("version"))
        source = package.get("source") or {}
        if not version and not source:
            findings.append(
                SupplyChainFinding(
                    kind="unversioned-lock-package",
                    message="Lockfile package has neither an exact version nor an immutable source",
                    location=str(path),
                    severity="HIGH",
                    details={"component": name},
                )
            )
        component = _component(name, version=version)
        if package.get("license"):
            component["licenses"] = [_license_entry(str(package["license"]))]
        hashes = _hashes_from_lock_files(package.get("files", ()) or (), path, findings)
        if hashes:
            component["hashes"] = hashes
        elif _is_registry_lock_source(source):
            findings.append(
                SupplyChainFinding(
                    kind="lock-artifact-missing-hash",
                    message="Locked registry dependency has no artifact hashes",
                    location=str(path),
                    severity="MEDIUM",
                    details={"component": name, "version": version},
                )
            )
        _apply_lock_source(component, source, path, findings)
        components.append(component)
        refs_by_name.setdefault(canonicalize_name(name), []).append(
            str(component["purl"])
        )

        raw_dependencies = package.get("dependencies", {}) or {}
        names: Iterable[Any]
        if isinstance(raw_dependencies, dict):
            names = raw_dependencies.keys()
        elif isinstance(raw_dependencies, list):
            names = (
                value.get("name") if isinstance(value, dict) else str(value).split()[0]
                for value in raw_dependencies
            )
        else:
            names = ()
        for dependency_name in names:
            if dependency_name:
                dependency_names.append((str(component["purl"]), str(dependency_name)))

    edges = [
        (source_ref, _best_dependency_ref(name, refs_by_name))
        for source_ref, name in dependency_names
    ]
    return components, edges


def _components_from_pipfile_lock(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> list[dict[str, Any]]:
    text = _read_text(path, findings, limits, "Pipfile.lock")
    if text is None:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        findings.append(
            SupplyChainFinding(
                kind="invalid-lockfile",
                message="Could not parse Pipfile.lock",
                location=str(path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )
        return []

    components: list[dict[str, Any]] = []
    for scope in ("default", "develop"):
        for name, value in (data.get(scope, {}) or {}).items():
            entry = value if isinstance(value, dict) else {"version": value}
            version_text = str(entry.get("version", ""))
            version = version_text[2:] if version_text.startswith("==") else None
            component = _component(str(name), version=version)
            _add_property(component, "pyflow:scope", scope)
            hashes = _hashes_from_strings(entry.get("hashes", ()) or (), path, findings)
            if hashes:
                component["hashes"] = hashes
            elif version:
                findings.append(
                    SupplyChainFinding(
                        kind="lock-artifact-missing-hash",
                        message="Locked dependency has no artifact hashes",
                        location=str(path),
                        severity="MEDIUM",
                        details={"component": name, "version": version},
                    )
                )
            source_url = entry.get("git") or entry.get("path") or entry.get("file")
            if source_url:
                component["externalReferences"] = [
                    {"type": "distribution", "url": _redacted_url(str(source_url))}
                ]
                _audit_embedded_credentials(path, str(source_url), findings, str(name))
                if entry.get("git") and not entry.get("ref"):
                    findings.append(
                        SupplyChainFinding(
                            kind="unpinned-vcs-dependency",
                            message="VCS dependency is not locked to a revision",
                            location=str(path),
                            severity="HIGH",
                            details={"component": name},
                        )
                    )
            components.append(component)

    for source in (data.get("_meta", {}) or {}).get("sources", ()) or ():
        if isinstance(source, dict):
            _audit_index_url(path, str(source.get("url", "")), findings, None)
    return components


def _components_from_pylock(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    data = _load_toml(path, findings, limits, "invalid-pylock")
    if data is None:
        return [], []
    if not data.get("lock-version"):
        findings.append(
            SupplyChainFinding(
                kind="invalid-pylock",
                message="pylock.toml does not declare lock-version",
                location=str(path),
                severity="HIGH",
            )
        )

    components: list[dict[str, Any]] = []
    refs_by_name: dict[str, list[str]] = {}
    unresolved_edges: list[tuple[str, str]] = []
    for package in data.get("packages", ()) or ():
        if not isinstance(package, dict) or not package.get("name"):
            continue
        name = str(package["name"])
        component = _component(name, version=_string_or_none(package.get("version")))
        artifact_hashes: list[dict[str, str]] = []
        for key in ("archive", "sdist"):
            artifact = package.get(key)
            if isinstance(artifact, dict):
                artifact_hashes.extend(
                    _hashes_from_mapping(
                        artifact.get("hashes", {}) or {}, path, findings
                    )
                )
                _audit_locked_artifact(path, name, artifact, findings)
        for wheel in package.get("wheels", ()) or ():
            if isinstance(wheel, dict):
                artifact_hashes.extend(
                    _hashes_from_mapping(wheel.get("hashes", {}) or {}, path, findings)
                )
                _audit_locked_artifact(path, name, wheel, findings)
        if artifact_hashes:
            component["hashes"] = _dedupe_hashes(artifact_hashes)
        vcs = package.get("vcs")
        if isinstance(vcs, dict):
            url = vcs.get("url") or vcs.get("path")
            if url:
                component["externalReferences"] = [
                    {"type": "vcs", "url": _redacted_url(str(url))}
                ]
                _audit_embedded_credentials(path, str(url), findings, name)
            commit = str(vcs.get("commit-id", ""))
            if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
                findings.append(
                    SupplyChainFinding(
                        kind="unpinned-vcs-dependency",
                        message="VCS dependency is not locked to a full commit identifier",
                        location=str(path),
                        severity="HIGH",
                        details={"component": name, "commit": commit},
                    )
                )
        components.append(component)
        refs_by_name.setdefault(canonicalize_name(name), []).append(
            str(component["purl"])
        )
        for dependency in package.get("dependencies", ()) or ():
            dependency_name = (
                dependency.get("name") if isinstance(dependency, dict) else dependency
            )
            if dependency_name:
                unresolved_edges.append((str(component["purl"]), str(dependency_name)))

    edges = [
        (source, _best_dependency_ref(name, refs_by_name))
        for source, name in unresolved_edges
    ]
    return components, edges


def _components_from_setup_cfg(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> list[dict[str, Any]]:
    text = _read_text(path, findings, limits, "setup.cfg")
    if text is None:
        return []
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        findings.append(
            SupplyChainFinding(
                kind="invalid-setup-config",
                message="Could not parse setup.cfg",
                location=str(path),
                severity="LOW",
                details={"error": str(exc)},
            )
        )
        return []
    values: list[str] = []
    if parser.has_option("options", "install_requires"):
        values.extend(parser.get("options", "install_requires").splitlines())
    if parser.has_section("options.extras_require"):
        for _group, raw in parser.items("options.extras_require"):
            values.extend(raw.splitlines())
    components: list[dict[str, Any]] = []
    for value in values:
        if value.strip():
            component = _parse_requirement(
                value.strip(), path, None, findings, audit_pin=False
            )
            if component is not None:
                components.append(component)
    return components


def _components_from_setup_py(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> list[dict[str, Any]]:
    text = _read_text(path, findings, limits, "setup.py")
    if text is None:
        return []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        findings.append(
            SupplyChainFinding(
                kind="invalid-setup-script",
                message="Could not parse setup.py without executing it",
                location=str(path),
                severity="MEDIUM",
                details={"line": exc.lineno, "error": exc.msg},
            )
        )
        return []

    _audit_setup_behavior(path, tree, findings)
    components: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or _call_name(node.func).split(".")[-1] != "setup"
        ):
            continue
        for keyword in node.keywords:
            if keyword.arg not in {
                "install_requires",
                "setup_requires",
                "tests_require",
            }:
                continue
            try:
                values = ast.literal_eval(keyword.value)
            except (ValueError, TypeError):
                continue
            if not isinstance(values, (list, tuple)):
                continue
            for value in values:
                if isinstance(value, str):
                    component = _parse_requirement(
                        value,
                        path,
                        getattr(keyword.value, "lineno", None),
                        findings,
                        audit_pin=False,
                    )
                    if component is not None:
                        components.append(component)
    return components


def _audit_setup_behavior(
    path: Path,
    tree: ast.AST,
    findings: list[SupplyChainFinding],
) -> None:
    aliases: dict[str, str] = {}
    for node in getattr(tree, "body", ()):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    dangerous = {
        "os.system": "executes a shell command",
        "os.popen": "executes a shell command",
        "subprocess.call": "starts a subprocess",
        "subprocess.run": "starts a subprocess",
        "subprocess.Popen": "starts a subprocess",
        "urllib.request.urlopen": "performs a network request",
        "requests.get": "performs a network request",
        "requests.post": "performs a network request",
        "socket.socket": "opens a network socket",
        "builtins.eval": "evaluates dynamic code",
        "builtins.exec": "executes dynamic code",
        "eval": "evaluates dynamic code",
        "exec": "executes dynamic code",
    }
    for node in getattr(tree, "body", ()):
        for descendant in ast.walk(node):
            if not isinstance(descendant, ast.Call):
                continue
            name = _call_name(descendant.func)
            first, dot, rest = name.partition(".")
            resolved = aliases.get(first, first) + (dot + rest if dot else "")
            action = dangerous.get(resolved)
            if action is None:
                continue
            findings.append(
                SupplyChainFinding(
                    kind="install-script-dangerous-behavior",
                    message=f"Package installation script {action}",
                    location=str(path),
                    severity=(
                        "CRITICAL" if resolved.endswith(("eval", "exec")) else "HIGH"
                    ),
                    details={
                        "line": getattr(descendant, "lineno", None),
                        "call": resolved,
                    },
                )
            )


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _load_toml(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
    finding_kind: str,
) -> dict[str, Any] | None:
    text = _read_text(path, findings, limits, "TOML manifest")
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        findings.append(
            SupplyChainFinding(
                kind=finding_kind,
                message="Could not parse TOML supply-chain metadata",
                location=str(path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )
        return None
    if not isinstance(data, dict):
        return None
    return dict(data)


def _hashes_from_lock_files(
    files: Iterable[Any],
    path: Path,
    findings: list[SupplyChainFinding],
) -> list[dict[str, str]]:
    values: list[str] = []
    for entry in files:
        if isinstance(entry, dict) and entry.get("hash"):
            values.append(str(entry["hash"]))
        elif isinstance(entry, str):
            values.append(entry)
    return _hashes_from_strings(values, path, findings)


def _hashes_from_strings(
    values: Iterable[Any],
    path: Path,
    findings: list[SupplyChainFinding],
) -> list[dict[str, str]]:
    pairs: dict[str, str] = {}
    for value in values:
        raw = str(value)
        if ":" in raw:
            algorithm, digest = raw.split(":", 1)
        elif "=" in raw:
            algorithm, digest = raw.split("=", 1)
        else:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-lock-hash",
                    message="Lockfile artifact hash has no algorithm prefix",
                    location=str(path),
                    severity="HIGH",
                    details={"hash": raw[:32]},
                )
            )
            continue
        pairs[algorithm] = digest
    return _hashes_from_mapping(pairs, path, findings)


def _hashes_from_mapping(
    values: dict[str, Any],
    path: Path,
    findings: list[SupplyChainFinding],
) -> list[dict[str, str]]:
    hashes: list[dict[str, str]] = []
    for algorithm, digest_value in values.items():
        normalized = str(algorithm).lower().replace("-", "")
        digest = str(digest_value).lower()
        if normalized not in hashlib.algorithms_guaranteed:
            findings.append(
                SupplyChainFinding(
                    kind="unsupported-lock-hash",
                    message="Lockfile uses an unsupported artifact hash algorithm",
                    location=str(path),
                    severity="HIGH",
                    details={"algorithm": algorithm},
                )
            )
            continue
        if normalized in {"md5", "sha1"}:
            findings.append(
                SupplyChainFinding(
                    kind="weak-lock-hash",
                    message="Lockfile uses a collision-prone artifact hash",
                    location=str(path),
                    severity="HIGH",
                    details={"algorithm": algorithm},
                )
            )
        if (
            not re.fullmatch(r"[0-9a-f]+", digest)
            or len(digest) != hashlib.new(normalized).digest_size * 2
        ):
            findings.append(
                SupplyChainFinding(
                    kind="invalid-lock-hash",
                    message="Lockfile artifact hash has an invalid digest",
                    location=str(path),
                    severity="HIGH",
                    details={"algorithm": algorithm},
                )
            )
            continue
        cyclonedx_name = _cyclonedx_hash_name(normalized)
        if cyclonedx_name is None:
            findings.append(
                SupplyChainFinding(
                    kind="unsupported-sbom-hash",
                    message="Artifact hash cannot be represented in the selected SBOM standards",
                    location=str(path),
                    severity="LOW",
                    details={"algorithm": algorithm},
                )
            )
            continue
        hashes.append({"alg": cyclonedx_name, "content": digest})
    return _dedupe_hashes(hashes)


def _is_registry_lock_source(source: Any) -> bool:
    if not source:
        return True
    if not isinstance(source, dict):
        return False
    source_type = str(source.get("type", "")).lower()
    return source_type in {"", "legacy", "index"} and not any(
        key in source for key in ("git", "url", "path", "directory", "editable")
    )


def _apply_lock_source(
    component: dict[str, Any],
    source: Any,
    path: Path,
    findings: list[SupplyChainFinding],
) -> None:
    if not isinstance(source, dict):
        return
    registry = source.get("registry")
    if registry:
        _audit_index_url(path, str(registry), findings, None)
    source_type = str(source.get("type", "")).lower()
    vcs_url = source.get("git") or (source.get("url") if source_type == "git" else None)
    if vcs_url:
        component["externalReferences"] = [
            {"type": "vcs", "url": _redacted_url(str(vcs_url))}
        ]
        _audit_embedded_credentials(
            path, str(vcs_url), findings, str(component.get("name", ""))
        )
        commit = str(
            source.get("resolved_reference")
            or source.get("resolved-reference")
            or source.get("commit")
            or ""
        )
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
            findings.append(
                SupplyChainFinding(
                    kind="unpinned-vcs-dependency",
                    message="VCS dependency is not locked to a full commit identifier",
                    location=str(path),
                    severity="HIGH",
                    details={"component": component.get("name"), "commit": commit},
                )
            )
    local_path = source.get("path") or source.get("directory") or source.get("editable")
    if local_path:
        findings.append(
            SupplyChainFinding(
                kind="local-path-requirement",
                message="Locked dependency references mutable local workspace content",
                location=str(path),
                severity="MEDIUM",
                details={"component": component.get("name"), "path": str(local_path)},
            )
        )


def _audit_locked_artifact(
    path: Path,
    component_name: str,
    artifact: dict[str, Any],
    findings: list[SupplyChainFinding],
) -> None:
    hashes = artifact.get("hashes", {}) or {}
    if not hashes:
        findings.append(
            SupplyChainFinding(
                kind="lock-artifact-missing-hash",
                message="Locked artifact does not declare a verification hash",
                location=str(path),
                severity="HIGH",
                details={"component": component_name},
            )
        )
    url = str(artifact.get("url", ""))
    if url and urlparse(url).scheme == "http":
        findings.append(
            SupplyChainFinding(
                kind="insecure-artifact-url",
                message="Locked artifact is downloaded over unauthenticated HTTP",
                location=str(path),
                severity="HIGH",
                details={"component": component_name, "url": _redacted_url(url)},
            )
        )
    if urlparse(url).username or urlparse(url).password:
        findings.append(
            SupplyChainFinding(
                kind="embedded-credentials",
                message="Locked artifact URL contains embedded credentials",
                location=str(path),
                severity="CRITICAL",
                details={"component": component_name, "url": _redacted_url(url)},
            )
        )


def _audit_index_url(
    path: Path,
    url: str,
    findings: list[SupplyChainFinding],
    priority: Any,
) -> None:
    if not url:
        return
    if urlparse(url).scheme == "http":
        findings.append(
            SupplyChainFinding(
                kind="insecure-package-index",
                message="Package index uses unauthenticated HTTP",
                location=str(path),
                severity="HIGH",
                details={"url": _redacted_url(url)},
            )
        )
    if urlparse(url).username or urlparse(url).password:
        findings.append(
            SupplyChainFinding(
                kind="embedded-credentials",
                message="Package index URL contains embedded credentials",
                location=str(path),
                severity="CRITICAL",
                details={"url": _redacted_url(url)},
            )
        )
    if priority in {"supplemental", "secondary"}:
        findings.append(
            SupplyChainFinding(
                kind="multiple-package-indexes",
                message="Supplemental package index introduces dependency-confusion risk",
                location=str(path),
                severity="HIGH",
                details={"url": _redacted_url(url), "priority": priority},
            )
        )


def _audit_embedded_credentials(
    path: Path,
    url: str,
    findings: list[SupplyChainFinding],
    component_name: str,
) -> None:
    parsed = urlparse(url)
    if parsed.username is None and parsed.password is None:
        return
    findings.append(
        SupplyChainFinding(
            kind="embedded-credentials",
            message="Dependency source URL contains embedded credentials",
            location=str(path),
            severity="CRITICAL",
            details={
                "component": component_name,
                "url": _redacted_url(url),
            },
        )
    )


component_from_metadata = _component_from_metadata
metadata_dependencies = _metadata_dependencies
components_from_requirements = _components_from_requirements
components_from_pyproject = _components_from_pyproject
components_from_toml_lock = _components_from_toml_lock
components_from_pipfile_lock = _components_from_pipfile_lock
components_from_pylock = _components_from_pylock
components_from_setup_cfg = _components_from_setup_cfg
components_from_setup_py = _components_from_setup_py
