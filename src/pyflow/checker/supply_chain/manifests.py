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

from .input_safety import read_text as _read_text
from .input_safety import redacted_url as _redacted_url
from .input_safety import contains_credentials as _contains_credentials
from .inventory import add_property as _add_property
from .inventory import best_dependency_ref as _best_dependency_ref
from .inventory import component as _component
from .inventory import cyclonedx_hash_name as _cyclonedx_hash_name
from .inventory import dedupe_hashes as _dedupe_hashes
from .inventory import exact_version as _exact_version
from .inventory import string_or_none as _string_or_none
from .licenses import license_entries_for_value as _license_entries_for_value
from .licenses import license_entry as _license_entry
from .licenses import licenses_from_metadata as _licenses_from_metadata
from .models import ScanLimits, SupplyChainFinding

try:
    import tomllib  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[import-not-found]


_HASH_OPTION_RE = re.compile(r"(?:^|\s)--hash[=\s]+([A-Za-z0-9_-]+):([^\s]+)")
_URL_RE = re.compile(r"(?:git\+|hg\+|svn\+|bzr\+)?(?:https?|ftp)://[^\s;]+", re.IGNORECASE)


def _redact_requirement_text(value: str) -> str:
    return _URL_RE.sub(lambda match: _redacted_url(match.group(0)), value)


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
    if not version:
        findings.append(
            SupplyChainFinding(
                kind="metadata-missing-version",
                message="Distribution metadata does not declare a version",
                location=str(metadata_path),
                severity="MEDIUM",
            )
        )
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
    _add_property(component, "pyflow:metadata-source", "true")
    license_files = list(data.get_all("License-File", []) or []) + list(
        data.get_all("License-Files", []) or []
    )
    for license_file in license_files:
        value = str(license_file).strip()
        if value:
            _add_property(component, "pyflow:license-file", value)
    top_level = metadata_path.parent / "top_level.txt"
    if top_level.is_file() and not top_level.is_symlink():
        import_text = _read_text(top_level, findings, limits, "top-level module metadata")
        if import_text is not None:
            for module in import_text.splitlines():
                module = module.strip().split(".", 1)[0]
                if module and module.isidentifier():
                    _add_property(component, "pyflow:import-name", module)
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
        parsed = _parse_requirement(str(value), metadata_path, None, findings, audit_pin=False)
        if parsed is None:
            continue
        components.append(parsed)
        if parent_ref:
            edges.append((parent_ref, str(parsed["purl"])))
    return components, edges


def _requirements_scope(path: Path) -> str:
    lowered = path.stem.lower()
    parts = set(re.split(r"[-_.]", lowered))
    path_parts = {part.casefold() for part in path.parts}
    if "constraint" in parts or "constraints" in parts or path.parent.name.lower() == "constraints":
        return "constraint"
    if path_parts & {"test", "tests", "testing"} or parts & {"test", "tests", "testing"}:
        return "test"
    if path_parts & {"doc", "docs"} or parts & {"doc", "docs"}:
        return "docs"
    if path_parts & {"benchmark", "benchmarks"} or parts & {"benchmark", "benchmarks"}:
        return "benchmark"
    if path_parts & {"example", "examples", "topic", "topics"} or parts & {
        "example",
        "examples",
    }:
        return "examples"
    if path_parts & {"script", "scripts", "tool", "tools"}:
        return "dev"
    if parts & {"dev", "develop", "development"}:
        return "dev"
    if parts & {"lint", "linting", "mypy", "flake8", "ruff"}:
        return "lint"
    if parts & {"type", "typing", "types"}:
        return "typing"
    if parts & {"doc", "docs"}:
        return "docs"
    if parts & {"build", "ci"}:
        return "build"
    if parts & {"benchmark", "benchmarks"}:
        return "benchmark"
    if parts & {"example", "examples"}:
        return "examples"
    return "runtime"


def _requirement_boundary(path: Path) -> Path:
    for ancestor in (path.parent, *path.parent.parents):
        if any(
            (ancestor / marker).exists()
            for marker in (
                ".git",
                ".hg",
                ".svn",
                "Pipfile",
                "Pipfile.lock",
                "poetry.lock",
                "pyproject.toml",
                "requirements.in",
                "requirements.txt",
                "setup.cfg",
                "setup.py",
                "uv.lock",
            )
        ):
            return ancestor
    return path.parent


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _components_from_requirements(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
    _stack: frozenset[Path] = frozenset(),
    scope: str | None = None,
    root: Path | None = None,
) -> list[dict[str, Any]]:
    effective_scope = scope or _requirements_scope(path)
    project_boundary = _requirement_boundary(path).resolve(strict=False)
    if root is not None:
        root_boundary = root.resolve(strict=False)
        boundary = (
            project_boundary if _is_relative_to(root_boundary, project_boundary) else root_boundary
        )
    else:
        boundary = project_boundary
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
    if _looks_like_template(text):
        findings.append(_template_manifest_finding(path, "requirements"))
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
            explicitly_absolute = included_path.is_absolute()
            if not explicitly_absolute:
                included_path = path.parent / included_path
            resolved_included = included_path.resolve(strict=False)
            if explicitly_absolute or not _is_relative_to(resolved_included, boundary):
                findings.append(
                    SupplyChainFinding(
                        kind="external-requirement-include",
                        message="Requirement include escapes the project boundary",
                        location=str(path),
                        severity="MEDIUM",
                        details={"line": line_no, "include": include},
                    )
                )
                continue
            if included_path.is_symlink():
                findings.append(
                    SupplyChainFinding(
                        kind="requirement-include-symlink",
                        message="Requirement include is a symbolic link and was not followed",
                        location=str(path),
                        severity="HIGH",
                        details={"line": line_no, "include": include},
                    )
                )
            elif not included_path.exists():
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
                included_scope = _requirements_scope(included_path)
                components.extend(
                    _components_from_requirements(
                        included_path,
                        findings,
                        limits,
                        _stack | {resolved},
                        scope=included_scope if included_scope != "runtime" else effective_scope,
                        root=root,
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
                    severity="MEDIUM",
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
            scope=effective_scope,
        )
        if component is not None:
            components.append(component)
    return components


def _logical_requirement_lines(text: str) -> Iterator[tuple[int, str]]:
    buffer: list[str] = []
    start_line = 1
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.rstrip()
        if stripped.lstrip().startswith("#"):
            continue
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
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return ""
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
        "--require-hashes",
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
        if (urlparse(value).hostname or "").casefold() not in _DEFAULT_INDEX_HOSTS:
            findings.append(
                SupplyChainFinding(
                    kind="multiple-package-indexes",
                    message="Extra package indexes can introduce dependency-confusion risk",
                    location=str(path),
                    severity="HIGH",
                    details={"line": line_no, "url": _redacted_url(value)},
                )
            )
    if option in {"--index-url", "-i"}:
        _audit_primary_index(path, value, findings)
    elif option in {"--extra-index-url"}:
        _audit_index_url(path, value, findings, None)
    elif option in {"--find-links", "-f"}:
        _audit_index_url(path, value, findings, "additional")
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
                        "Requirement hash cannot be represented in the selected " "SBOM standards"
                    ),
                    location=str(path),
                    severity="LOW",
                    details={"line": line_no, "algorithm": algorithm},
                )
            )
            continue
        hashes.append({"alg": cyclonedx_name, "content": digest.lower()})
    return hashes


def _url_fragment_hashes(
    url: str,
    path: Path,
    findings: list[SupplyChainFinding],
) -> list[dict[str, str]]:
    fragment = parse_qs(urlparse(url).fragment)
    values = {
        key: items[0]
        for key, items in fragment.items()
        if items and key.casefold() in hashlib.algorithms_guaranteed
    }
    return _hashes_from_mapping(values, path, findings) if values else []


def _remote_requirement_pinned(url: str) -> bool:
    """Return whether a direct URL identifies an immutable artifact/revision."""

    parsed = urlparse(url)
    fragment = parse_qs(parsed.fragment)
    if any(key.casefold() in {"md5", "sha1", "sha256", "sha384", "sha512"} for key in fragment):
        return True
    if url.startswith(("git+", "hg+", "svn+", "bzr+")):
        return bool(_source_revision({}, url))
    return False


def _combine_markers(req_marker: str | None, extra_marker: str | None) -> str | None:
    if req_marker and extra_marker:
        return f"({req_marker}) and ({extra_marker})"
    return req_marker or extra_marker


def _parse_requirement(
    requirement_text: str,
    path: Path,
    line_no: int | None,
    findings: list[SupplyChainFinding],
    *,
    audit_pin: bool,
    hashes: list[dict[str, str]] | None = None,
    scope: str | None = None,
    marker: str | None = None,
) -> dict[str, Any] | None:
    cleaned = requirement_text.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (
        cleaned.startswith("'") and cleaned.endswith("'")
    ):
        cleaned = cleaned[1:-1].strip()
    details: dict[str, Any] = {"requirement": _redact_requirement_text(cleaned)}
    if line_no is not None:
        details["line"] = line_no
    if scope:
        details["scope"] = scope
    try:
        requirement = Requirement(cleaned)
    except InvalidRequirement:
        requirement = None
        if "=" in cleaned and not any(
            op in cleaned for op in ("==", ">=", "<=", "!=", "~=", "===")
        ):
            try:
                candidate = re.sub(r"(?<![=<>!~])=(?!=)", "==", cleaned)
                requirement = Requirement(candidate)
            except InvalidRequirement:
                requirement = None
        if requirement is None:
            legacy = _component_from_legacy_reference(cleaned)
            if cleaned.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://")):
                details["requirement"] = _redacted_url(cleaned)
                unpinned = _is_unpinned_vcs_url(cleaned)
                details["pinned"] = not unpinned and _remote_requirement_pinned(cleaned)
                if legacy is not None:
                    fragment_hashes = _url_fragment_hashes(cleaned, path, findings)
                    if fragment_hashes:
                        legacy["hashes"] = fragment_hashes
                findings.append(
                    SupplyChainFinding(
                        kind="remote-requirement",
                        message="Requirement uses a legacy VCS or direct reference",
                        location=str(path),
                        severity="HIGH" if unpinned else "MEDIUM",
                        details=details,
                    )
                )
                if unpinned:
                    findings.append(
                        SupplyChainFinding(
                            kind="unpinned-vcs-dependency",
                            message="VCS dependency is not pinned to an immutable revision",
                            location=str(path),
                            severity="HIGH",
                            details=details,
                        )
                    )
                return legacy
            if _looks_like_local_requirement(cleaned):
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
    effective_marker = _combine_markers(
        str(requirement.marker) if requirement.marker else None,
        marker,
    )
    if effective_marker:
        _add_property(component, "pyflow:marker", effective_marker)
        if not scope and "extra" in effective_marker:
            _add_property(component, "pyflow:scope", "optional")
    if requirement.extras:
        _add_property(component, "pyflow:extras", ",".join(sorted(requirement.extras)))
    if scope:
        _add_property(component, "pyflow:scope", scope)
    if hashes:
        component["hashes"] = hashes
    if requirement.url:
        url_text = str(requirement.url)
        if url_text.startswith(("file:", ".", "/", "~", "..")) or "://" not in url_text:
            local_url = url_text
            if not local_url.startswith("file:"):
                local_path = Path(local_url)
                if not local_path.is_absolute():
                    local_path = path.parent / local_path
                local_url = local_path.resolve(strict=False).as_uri()
            _add_property(component, "pyflow:source-url", local_url)
            findings.append(
                SupplyChainFinding(
                    kind="local-path-requirement",
                    message="Dependency references mutable local path content",
                    location=str(path),
                    severity="MEDIUM",
                    details={"requirement": _redacted_url(url_text)},
                )
            )
            return component
        _add_property(component, "pyflow:source-url", _redacted_url(requirement.url))
        component["externalReferences"] = [
            {"type": "distribution", "url": _redacted_url(requirement.url)}
        ]
        fragment_hashes = _url_fragment_hashes(str(requirement.url), path, findings)
        if fragment_hashes:
            component["hashes"] = _dedupe_hashes(fragment_hashes)
        url_details = dict(details)
        url_details["requirement"] = requirement_text.replace(
            requirement.url, _redacted_url(requirement.url)
        )
        url_details["url"] = _redacted_url(requirement.url)
        url_details["pinned"] = _remote_requirement_pinned(str(requirement.url))
        findings.append(
            SupplyChainFinding(
                kind="remote-requirement",
                message="Requirement bypasses normal package-index resolution",
                location=str(path),
                severity="HIGH" if _is_unpinned_vcs_url(requirement.url) else "MEDIUM",
                details=url_details,
            )
        )
        if _is_unpinned_vcs_url(str(requirement.url)):
            findings.append(
                SupplyChainFinding(
                    kind="unpinned-vcs-dependency",
                    message="VCS dependency is not pinned to an immutable revision",
                    location=str(path),
                    severity="HIGH",
                    details=url_details,
                )
            )
        if _contains_credentials(requirement.url):
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
                parsed_name, parsed_version, _build, _tags = parse_wheel_filename(filename)
            else:
                parsed_name, parsed_version = parse_sdist_filename(filename)
        except (InvalidWheelFilename, InvalidSdistFilename):
            return None
        component = _component(str(parsed_name), version=str(parsed_version))
    else:
        component = _component(names[0])
    _add_property(component, "pyflow:source-url", _redacted_url(value))
    component["externalReferences"] = [{"type": "distribution", "url": _redacted_url(value)}]
    return component


def _looks_like_local_requirement(value: str) -> bool:
    return value.startswith((".", "/", "~", "file:")) or Path(value).suffix in {
        ".whl",
        ".zip",
        ".gz",
    }


def _source_revision(source: dict[str, Any], url: str) -> str:
    """Extract a full commit identifier from a lock source or VCS URL."""

    for key in (
        "rev",
        "commit",
        "reference",
        "resolved_reference",
        "resolved-reference",
        "commit-id",
    ):
        value = source.get(key)
        if value and re.fullmatch(r"[0-9a-fA-F]{40,64}", str(value)):
            return str(value)
    parsed = urlparse(url)
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", parsed.fragment):
        return parsed.fragment
    _path, separator, revision = parsed.path.rpartition("@")
    if separator and re.fullmatch(r"[0-9a-fA-F]{40,64}", revision):
        return revision
    for key in ("rev", "commit", "ref"):
        for value in parse_qs(parsed.query).get(key, ()):
            if re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
                return value
    return ""


def _is_unpinned_vcs_url(value: str) -> bool:
    if not value.startswith(("git+", "hg+", "svn+", "bzr+")):
        return False
    return not bool(_source_revision({}, value))


def _manifest_type_finding(
    path: Path,
    findings: list[SupplyChainFinding],
    field: str,
    expected: str,
) -> None:
    findings.append(
        SupplyChainFinding(
            kind="invalid-pyproject",
            message=f"Manifest field {field} must be {expected}",
            location=str(path),
            severity="LOW",
            details={"field": field, "expected": expected},
        )
    )


def _mapping_field(
    data: dict[str, Any],
    key: str,
    path: Path,
    findings: list[SupplyChainFinding],
) -> dict[str, Any]:
    value = data.get(key, {}) or {}
    if not isinstance(value, dict):
        _manifest_type_finding(path, findings, key, "a table")
        return {}
    return value


def _expand_dependency_groups(
    groups: dict[str, Any],
    path: Path,
    findings: list[SupplyChainFinding],
) -> list[tuple[str, str, str | None]]:
    """Expand PEP 735 dependency groups, including ``include-group`` entries."""

    resolved: list[tuple[str, str, str | None]] = []

    def expand(name: str, stack: frozenset[str], root_group: str) -> None:
        values = groups.get(name)
        if not isinstance(values, (list, tuple)):
            _manifest_type_finding(path, findings, f"dependency-groups.{name}", "an array")
            return
        marker = f'extra == "{root_group}"'
        for item in values:
            if isinstance(item, str):
                resolved.append((item, f"group:{root_group}", marker))
            elif isinstance(item, dict) and item.get("include-group"):
                included = str(item["include-group"])
                if included in stack:
                    findings.append(
                        SupplyChainFinding(
                            kind="dependency-group-cycle",
                            message="Dependency groups include each other cyclically",
                            location=str(path),
                            severity="HIGH",
                            details={"group": name, "include_group": included},
                        )
                    )
                elif included not in groups:
                    findings.append(
                        SupplyChainFinding(
                            kind="unresolved-dependency-group",
                            message="Dependency group includes a group that is not declared",
                            location=str(path),
                            severity="MEDIUM",
                            details={"group": name, "include_group": included},
                        )
                    )
                else:
                    expand(included, stack | {name}, root_group)
            else:
                _manifest_type_finding(
                    path,
                    findings,
                    f"dependency-groups.{name} entry",
                    "a requirement string or include-group table",
                )

    for group_name in groups:
        expand(str(group_name), frozenset(), str(group_name))
    return resolved


def _resolve_dynamic_file_paths(base_dir: Path, file_spec: Any) -> list[Path] | None:
    if isinstance(file_spec, str):
        candidates = [file_spec]
    elif isinstance(file_spec, (list, tuple)):
        candidates = [str(f) for f in file_spec if isinstance(f, str)]
    else:
        return None
    if not candidates:
        return None
    paths = [base_dir / f for f in candidates]
    if all(p.is_file() for p in paths):
        return paths
    return None


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
    project = _mapping_field(data, "project", path, findings)
    dynamic_values = project.get("dynamic", ()) or ()
    if not isinstance(dynamic_values, (list, tuple)):
        _manifest_type_finding(path, findings, "project.dynamic", "an array")
        dynamic_values = ()
    dynamic_fields = {str(value) for value in dynamic_values if isinstance(value, str)}
    build_system = _mapping_field(data, "build-system", path, findings)
    backend_path = build_system.get("backend-path", ()) or ()
    if not isinstance(backend_path, (list, tuple)):
        _manifest_type_finding(path, findings, "build-system.backend-path", "an array")
        backend_path = ()
    if backend_path:
        findings.append(
            SupplyChainFinding(
                kind="local-build-backend",
                message="Project loads build-backend code from the source tree",
                location=str(path),
                severity="HIGH",
                details={"backend_path": [str(item) for item in backend_path]},
            )
        )
    backend = str(build_system.get("build-backend", ""))
    trusted_backends = {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
        "flit_core.buildapi",
        "hatchling.build",
        "poetry.core.masonry.api",
        "poetry.masonry.api",
        "pdm.backend",
        "maturin",
        "mesonpy",
        "scikit_build_core.build",
        "trampolim",
        "whey",
    }
    if backend and backend not in trusted_backends:
        findings.append(
            SupplyChainFinding(
                kind="unrecognized-build-backend",
                message="Project uses a build backend outside the built-in policy set",
                location=str(path),
                severity="MEDIUM",
                details={"backend": backend},
            )
        )
    tool = data.get("tool", {}) or {}
    if not isinstance(tool, dict):
        _manifest_type_finding(path, findings, "tool", "a table")
        tool = {}
    poetry = tool.get("poetry", {}) or {}
    if not isinstance(poetry, dict):
        _manifest_type_finding(path, findings, "tool.poetry", "a table")
        poetry = {}

    root: dict[str, Any] | None = None
    project_name = project.get("name")
    poetry_name = poetry.get("name") if isinstance(poetry.get("name"), str) else None
    root_name = str(project_name) if project_name else poetry_name
    if root_name:
        if project_name:
            root_version = project.get("version")
            root_license = project.get("license")
        else:
            root_version = poetry.get("version")
            root_license = poetry.get("license")
        root = _component(root_name, version=_string_or_none(root_version))
        root["type"] = "application"
        license_entries, license_file = _license_entries_for_value(root_license)
        if license_entries:
            root["licenses"] = license_entries
        if license_file:
            _add_property(root, "pyflow:license-file", license_file)
        license_files = project.get("license-files")
        if isinstance(license_files, (list, tuple)) and license_files:
            _add_property(
                root,
                "pyflow:license-file",
                ",".join(str(value) for value in license_files),
            )
        components.append(root)

    resolved_dynamic_fields: set[str] = set()
    setuptools_table = (
        tool.get("setuptools", {}) if isinstance(tool.get("setuptools"), dict) else {}
    )
    setuptools_dynamic = (
        setuptools_table.get("dynamic", {}) if isinstance(setuptools_table, dict) else {}
    )
    if not isinstance(setuptools_dynamic, dict):
        setuptools_dynamic = {}

    if "dependencies" in dynamic_fields:
        dep_cfg = setuptools_dynamic.get("dependencies")
        file_spec = dep_cfg.get("file") if isinstance(dep_cfg, dict) else None
        paths = _resolve_dynamic_file_paths(path.parent, file_spec) if file_spec else None
        if paths is not None:
            resolved_dynamic_fields.add("dependencies")
            for req_path in paths:
                req_components = _components_from_requirements(
                    req_path, findings, limits, root=path.parent, scope="runtime"
                )
                components.extend(req_components)
                if root is not None:
                    for comp in req_components:
                        edges.append((str(root["purl"]), str(comp["purl"])))

    if "optional-dependencies" in dynamic_fields:
        opt_cfg = setuptools_dynamic.get("optional-dependencies")
        if isinstance(opt_cfg, dict) and opt_cfg:
            all_resolved = True
            for group, group_cfg in opt_cfg.items():
                file_spec = group_cfg.get("file") if isinstance(group_cfg, dict) else None
                paths = _resolve_dynamic_file_paths(path.parent, file_spec) if file_spec else None
                if paths is not None:
                    for req_path in paths:
                        req_components = _components_from_requirements(
                            req_path,
                            findings,
                            limits,
                            root=path.parent,
                            scope=f"optional:{group}",
                        )
                        components.extend(req_components)
                        if root is not None:
                            for comp in req_components:
                                edges.append((str(root["purl"]), str(comp["purl"])))
                else:
                    all_resolved = False
            if all_resolved:
                resolved_dynamic_fields.add("optional-dependencies")

    hatch_hooks = (
        tool.get("hatch", {}).get("metadata", {}).get("hooks", {})
        if isinstance(tool.get("hatch"), dict)
        and isinstance(tool.get("hatch", {}).get("metadata"), dict)
        else {}
    )
    hatch_reqs = hatch_hooks.get("requirements_txt", {}) if isinstance(hatch_hooks, dict) else {}
    if isinstance(hatch_reqs, dict):
        if "dependencies" in dynamic_fields and "dependencies" not in resolved_dynamic_fields:
            paths = _resolve_dynamic_file_paths(path.parent, hatch_reqs.get("files"))
            if paths is not None:
                resolved_dynamic_fields.add("dependencies")
                for req_path in paths:
                    req_components = _components_from_requirements(
                        req_path, findings, limits, root=path.parent, scope="runtime"
                    )
                    components.extend(req_components)
                    if root is not None:
                        for comp in req_components:
                            edges.append((str(root["purl"]), str(comp["purl"])))
        if (
            "optional-dependencies" in dynamic_fields
            and "optional-dependencies" not in resolved_dynamic_fields
        ):
            opt_groups = hatch_reqs.get("optional-dependencies")
            if isinstance(opt_groups, dict) and opt_groups:
                all_resolved = True
                for group, files in opt_groups.items():
                    paths = _resolve_dynamic_file_paths(path.parent, files)
                    if paths is not None:
                        for req_path in paths:
                            req_components = _components_from_requirements(
                                req_path,
                                findings,
                                limits,
                                root=path.parent,
                                scope=f"optional:{group}",
                            )
                            components.extend(req_components)
                            if root is not None:
                                for comp in req_components:
                                    edges.append((str(root["purl"]), str(comp["purl"])))
                    else:
                        all_resolved = False
                if all_resolved:
                    resolved_dynamic_fields.add("optional-dependencies")

    unresolved_dynamic = (dynamic_fields - resolved_dynamic_fields) & {
        "dependencies",
        "optional-dependencies",
    }
    if unresolved_dynamic:
        findings.append(
            SupplyChainFinding(
                kind="dynamic-dependency-metadata",
                message="Project dependencies are computed dynamically and cannot be inventoried statically",
                location=str(path),
                severity="HIGH",
                details={"fields": sorted(unresolved_dynamic)},
            )
        )

    declared: list[tuple[str, str, str | None]] = []

    runtime_values = project.get("dependencies", ()) or ()
    if not isinstance(runtime_values, (list, tuple)):
        _manifest_type_finding(path, findings, "project.dependencies", "an array")
        runtime_values = ()
    for value in runtime_values:
        if isinstance(value, str):
            declared.append((value, "runtime", None))
        else:
            _manifest_type_finding(path, findings, "project.dependencies entry", "a string")

    optional = project.get("optional-dependencies", {}) or {}
    if not isinstance(optional, dict):
        _manifest_type_finding(path, findings, "project.optional-dependencies", "a table")
        optional = {}
    for group, values in optional.items():
        group_name = str(group)
        if not isinstance(values, (list, tuple)):
            _manifest_type_finding(
                path, findings, f"project.optional-dependencies.{group_name}", "an array"
            )
            continue
        marker = f'extra == "{group_name}"'
        for value in values:
            if isinstance(value, str):
                declared.append((value, f"optional:{group_name}", marker))
            else:
                _manifest_type_finding(
                    path,
                    findings,
                    f"project.optional-dependencies.{group_name} entry",
                    "a string",
                )

    groups = data.get("dependency-groups", {}) or {}
    if not isinstance(groups, dict):
        _manifest_type_finding(path, findings, "dependency-groups", "a table")
        groups = {}
    declared.extend(
        _expand_dependency_groups(
            {str(key): value for key, value in groups.items()},
            path,
            findings,
        )
    )

    requires = build_system.get("requires", ()) or ()
    if isinstance(requires, str):
        findings.append(
            SupplyChainFinding(
                kind="invalid-build-system",
                message=(
                    "build-system.requires must be an array; treating the string "
                    "as a single build requirement"
                ),
                location=str(path),
                severity="MEDIUM",
                details={"value": requires},
            )
        )
        requires = [requires]
    elif not isinstance(requires, (list, tuple)):
        _manifest_type_finding(path, findings, "build-system.requires", "an array")
        requires = ()
    for value in requires:
        if isinstance(value, str):
            declared.append((value, "build", None))
        else:
            _manifest_type_finding(path, findings, "build-system.requires entry", "a string")

    poetry_groups: list[tuple[str, dict[str, Any], str | None]] = []
    poetry_runtime = poetry.get("dependencies", {}) or {}
    if not isinstance(poetry_runtime, dict):
        _manifest_type_finding(path, findings, "tool.poetry.dependencies", "a table")
        poetry_runtime = {}
    poetry_groups.append(("runtime", poetry_runtime, None))
    poetry_dev = poetry.get("dev-dependencies", {}) or {}
    if not isinstance(poetry_dev, dict):
        _manifest_type_finding(path, findings, "tool.poetry.dev-dependencies", "a table")
        poetry_dev = {}
    poetry_groups.append(("dev", poetry_dev, 'extra == "dev"'))
    poetry_group_map = poetry.get("group", {}) or {}
    if not isinstance(poetry_group_map, dict):
        _manifest_type_finding(path, findings, "tool.poetry.group", "a table")
        poetry_group_map = {}
    for group, group_data in poetry_group_map.items():
        if not isinstance(group_data, dict):
            _manifest_type_finding(path, findings, f"tool.poetry.group.{group}", "a table")
            continue
        dependencies = group_data.get("dependencies", {}) or {}
        if not isinstance(dependencies, dict):
            _manifest_type_finding(
                path, findings, f"tool.poetry.group.{group}.dependencies", "a table"
            )
            continue
        poetry_groups.append((f"group:{group}", dependencies, f'extra == "{group}"'))

    poetry_extras = poetry.get("extras", {}) or {}
    extra_members: dict[str, set[str]] = {}
    if isinstance(poetry_extras, dict):
        for extra_name, members in poetry_extras.items():
            if not isinstance(members, (list, tuple)):
                _manifest_type_finding(
                    path, findings, f"tool.poetry.extras.{extra_name}", "an array"
                )
                continue
            for member in members:
                extra_members.setdefault(canonicalize_name(str(member)), set()).add(str(extra_name))

    for scope, dependency_map, marker in poetry_groups:
        for name, value in dependency_map.items():
            if canonicalize_name(str(name)) == "python":
                continue
            requirement_text = _poetry_requirement(str(name), value)
            if not requirement_text:
                continue
            optional = isinstance(value, dict) and bool(value.get("optional"))
            if optional:
                extras_for = sorted(extra_members.get(canonicalize_name(str(name)), ()))
                if extras_for:
                    for extra_name in extras_for:
                        declared.append(
                            (
                                requirement_text,
                                f"optional:{extra_name}",
                                _combine_markers(marker, f'extra == "{extra_name}"'),
                            )
                        )
                else:
                    declared.append((requirement_text, "optional", marker))
            else:
                declared.append((requirement_text, scope, marker))

    for requirement_text, scope, marker in declared:
        component = _parse_requirement(
            requirement_text,
            path,
            None,
            findings,
            audit_pin=False,
            scope=scope,
            marker=marker,
        )
        if component is None:
            continue
        components.append(component)
        if root is not None:
            edges.append((str(root["purl"]), str(component["purl"])))

    _audit_build_hooks(path, tool, poetry, findings)

    poetry_sources = poetry.get("source", ()) or ()
    if not isinstance(poetry_sources, (list, tuple)):
        _manifest_type_finding(path, findings, "tool.poetry.source", "an array")
        poetry_sources = ()
    for source in poetry_sources:
        if isinstance(source, dict):
            source_url = str(source.get("url", ""))
            priority = source.get("priority")
            if priority in {None, "primary", "default"}:
                _audit_primary_index(path, source_url, findings)
            else:
                _audit_index_url(path, source_url, findings, priority)
    uv = tool.get("uv", {}) or {}
    if not isinstance(uv, dict):
        _manifest_type_finding(path, findings, "tool.uv", "a table")
        uv = {}
    uv_dev = uv.get("dev-dependencies", ()) or ()
    if isinstance(uv_dev, (list, tuple)):
        for value in uv_dev:
            if not isinstance(value, str):
                _manifest_type_finding(path, findings, "tool.uv.dev-dependencies entry", "a string")
                continue
            component = _parse_requirement(
                value,
                path,
                None,
                findings,
                audit_pin=False,
                scope="dev",
                marker='extra == "dev"',
            )
            if component is not None:
                components.append(component)
                if root is not None:
                    edges.append((str(root["purl"]), str(component["purl"])))
    elif uv_dev:
        _manifest_type_finding(path, findings, "tool.uv.dev-dependencies", "an array")

    rye = tool.get("rye", {}) or {}
    rye_dev = rye.get("dev-dependencies", ()) if isinstance(rye, dict) else ()
    if isinstance(rye_dev, (list, tuple)):
        for value in rye_dev:
            if not isinstance(value, str):
                _manifest_type_finding(
                    path, findings, "tool.rye.dev-dependencies entry", "a string"
                )
                continue
            component = _parse_requirement(
                value,
                path,
                None,
                findings,
                audit_pin=False,
                scope="dev",
                marker='extra == "dev"',
            )
            if component is not None:
                components.append(component)
                if root is not None:
                    edges.append((str(root["purl"]), str(component["purl"])))
    elif rye_dev:
        _manifest_type_finding(path, findings, "tool.rye.dev-dependencies", "an array")

    pdm = tool.get("pdm", {}) or {}
    hatch = tool.get("hatch", {}) or {}
    hatch_envs = hatch.get("envs", {}) if isinstance(hatch, dict) else {}
    if isinstance(hatch_envs, dict):
        for env_name, env_config in hatch_envs.items():
            if not isinstance(env_config, dict):
                continue
            values = env_config.get("dependencies", ()) or ()
            if not isinstance(values, (list, tuple)):
                _manifest_type_finding(
                    path, findings, f"tool.hatch.envs.{env_name}.dependencies", "an array"
                )
                continue
            for value in values:
                if not isinstance(value, str):
                    continue
                component = _parse_requirement(
                    value,
                    path,
                    None,
                    findings,
                    audit_pin=False,
                    scope=f"env:{env_name}",
                    marker=f'extra == "{env_name}"',
                )
                if component is not None:
                    components.append(component)
                    if root is not None:
                        edges.append((str(root["purl"]), str(component["purl"])))

    pdm_dev = pdm.get("dev-dependencies", {}) if isinstance(pdm, dict) else {}
    if isinstance(pdm_dev, dict):
        for group_name, values in pdm_dev.items():
            if not isinstance(values, (list, tuple)):
                _manifest_type_finding(
                    path, findings, f"tool.pdm.dev-dependencies.{group_name}", "an array"
                )
                continue
            for value in values:
                if not isinstance(value, str):
                    continue
                component = _parse_requirement(
                    value,
                    path,
                    None,
                    findings,
                    audit_pin=False,
                    scope=f"dev:{group_name}",
                    marker=f'extra == "{group_name}"',
                )
                if component is not None:
                    components.append(component)
                    if root is not None:
                        edges.append((str(root["purl"]), str(component["purl"])))
    elif pdm_dev:
        _manifest_type_finding(path, findings, "tool.pdm.dev-dependencies", "a table")

    uv_indexes = uv.get("index", ()) or ()
    if isinstance(uv_indexes, dict):
        uv_indexes = [uv_indexes]
    if not isinstance(uv_indexes, (list, tuple)):
        _manifest_type_finding(path, findings, "tool.uv.index", "an array of tables")
        uv_indexes = ()
    index_by_name: dict[str, dict[str, Any]] = {}
    for entry in uv_indexes:
        if not isinstance(entry, dict):
            _manifest_type_finding(path, findings, "tool.uv.index entry", "a table")
            continue
        name = str(entry.get("name", ""))
        url = str(entry.get("url", "") or "")
        if name:
            index_by_name[name] = entry
        if url:
            # A non-explicit uv index participates in resolution just like
            # --extra-index-url and is a dependency-confusion vector.
            priority = "additional" if entry.get("explicit") is not True else None
            _audit_index_url(path, url, findings, priority)

    uv_sources = uv.get("sources", {}) or {}
    if not isinstance(uv_sources, dict):
        _manifest_type_finding(path, findings, "tool.uv.sources", "a table")
        uv_sources = {}
    for name, source in uv_sources.items():
        entries = source if isinstance(source, list) else [source]
        if not isinstance(source, (dict, list)):
            _manifest_type_finding(path, findings, f"tool.uv.sources.{name}", "a table")
            continue
        if isinstance(source, list) and not source:
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                _manifest_type_finding(path, findings, f"tool.uv.sources.{name} entry", "a table")
                continue
            source_url = entry.get("git") or entry.get("url")
            index_name = entry.get("index")
            if index_name:
                index_entry = index_by_name.get(str(index_name))
                if index_entry is None:
                    findings.append(
                        SupplyChainFinding(
                            kind="unresolved-package-index",
                            message="uv dependency source references an undeclared index",
                            location=str(path),
                            severity="MEDIUM",
                            details={"component": name, "index": str(index_name)},
                        )
                    )
                else:
                    index_url = str(index_entry.get("url", "") or "")
                    source_url = source_url or index_url
                    if index_url:
                        _audit_index_url(path, index_url, findings, None)
            if source_url:
                _audit_embedded_credentials(path, str(source_url), findings, str(name))
            if entry.get("git"):
                revision = entry.get("rev") or entry.get("tag") or entry.get("branch")
                if revision and source_url and not str(source_url).endswith(f"@{revision}"):
                    source_url = f"{source_url}@{revision}"
            if entry.get("git") or entry.get("url"):
                if source_url and not _remote_requirement_pinned(str(source_url)):
                    findings.append(
                        SupplyChainFinding(
                            kind="remote-requirement",
                            message="Dependency bypasses normal package-index resolution",
                            location=str(path),
                            severity="MEDIUM",
                            details={
                                "component": str(name),
                                "url": _redacted_url(str(source_url)),
                                "pinned": False,
                            },
                        )
                    )
                target_component = next(
                    (
                        component
                        for component in components
                        if canonicalize_name(str(component.get("name", "")))
                        == canonicalize_name(str(name))
                    ),
                    None,
                )
                if target_component is not None and source_url:
                    safe_url = _redacted_url(str(source_url))
                    _add_property(target_component, "pyflow:source-url", safe_url)
                    target_component["externalReferences"] = [
                        {"type": "vcs" if entry.get("git") else "distribution", "url": safe_url}
                    ]
                    fragment_hashes = _url_fragment_hashes(str(source_url), path, findings)
                    if fragment_hashes:
                        target_component["hashes"] = _dedupe_hashes(fragment_hashes)
            if entry.get("git") and not _source_revision(entry, str(source_url or "")):
                findings.append(
                    SupplyChainFinding(
                        kind="unpinned-vcs-dependency",
                        message="uv dependency source is not pinned to a revision",
                        location=str(path),
                        severity="HIGH",
                        details={"component": name},
                    )
                )
            if entry.get("path") or entry.get("workspace"):
                findings.append(
                    SupplyChainFinding(
                        kind="local-path-requirement",
                        message="uv dependency references mutable local workspace content",
                        location=str(path),
                        severity="MEDIUM",
                        details={"component": name},
                    )
                )
    return components, edges


def _audit_build_hooks(
    path: Path,
    tool: dict[str, Any],
    poetry: dict[str, Any],
    findings: list[SupplyChainFinding],
) -> None:
    """Report PEP 517/518 hooks that execute project code at build time."""

    executions: list[str] = []
    hatch = tool.get("hatch", {}) or {}
    if isinstance(hatch, dict):
        build = hatch.get("build", {}) or {}
        hooks = build.get("hooks", {}) if isinstance(build, dict) else {}
        if isinstance(hooks, dict):
            for name, config in hooks.items():
                if name == "custom" or (
                    isinstance(config, dict) and (config.get("path") or config.get("script"))
                ):
                    executions.append(f"tool.hatch.build.hooks.{name}")
    poetry_build = poetry.get("build")
    if isinstance(poetry_build, dict) and poetry_build.get("script"):
        executions.append("tool.poetry.build.script")
    setuptools = tool.get("setuptools", {}) or {}
    cmdclass = setuptools.get("cmdclass") if isinstance(setuptools, dict) else None
    if isinstance(cmdclass, dict) and cmdclass:
        executions.append("tool.setuptools.cmdclass")
    pdm = tool.get("pdm", {}) or {}
    pdm_build = pdm.get("build") if isinstance(pdm, dict) else None
    if isinstance(pdm_build, dict) and (pdm_build.get("script") or pdm_build.get("run-script")):
        executions.append("tool.pdm.build.script")
    if executions:
        findings.append(
            SupplyChainFinding(
                kind="build-hook-code-execution",
                message="Build configuration executes project code during package builds",
                location=str(path),
                severity="HIGH",
                details={"hooks": executions},
            )
        )


def _poetry_requirement(name: str, value: Any) -> str | None:
    if isinstance(value, str):
        constraint = _normalize_poetry_constraint(value)
        return name if not constraint else f"{name}{constraint}"
    if not isinstance(value, dict):
        return None
    marker = value.get("markers")
    raw_extras = value.get("extras") or ()
    extras = raw_extras if isinstance(raw_extras, (list, tuple)) else ()
    display_name = f"{name}[{','.join(str(item) for item in extras)}]" if extras else name
    for key in ("git", "url", "path"):
        if value.get(key):
            target = str(value[key])
            if key == "git":
                if not target.startswith(("git+", "hg+", "svn+", "bzr+", "ssh://")):
                    target = "git+" + target
                revision = value.get("rev") or value.get("tag") or value.get("branch")
                if revision:
                    target += f"@{revision}"
            requirement = f"{display_name} @ {target}"
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
    if not isinstance(raw_packages, (list, tuple)):
        findings.append(
            SupplyChainFinding(
                kind="invalid-lockfile",
                message="Lockfile package entries must be an array of tables",
                location=str(path),
                severity="HIGH",
            )
        )
        return [], []
    components: list[dict[str, Any]] = []
    dependency_names: list[tuple[str, str, str | None]] = []
    refs_by_name: dict[str, list[str]] = {}
    version_markers: dict[tuple[str, str], set[str]] = {}
    group_scopes: dict[tuple[str, str | None], set[tuple[str, str]]] = {}

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
        if isinstance(source, dict) and (
            source.get("virtual")
            or str(source.get("editable", "")).strip() in {".", "./"}
            or str(source.get("workspace", "")).strip() in {".", "./"}
        ):
            component["type"] = "application"
        if package.get("license"):
            component["licenses"] = [_license_entry(str(package["license"]))]
        markers = package.get("markers")
        if isinstance(markers, dict):
            for marker_value in markers.values():
                if marker_value:
                    _add_property(component, "pyflow:marker", str(marker_value))
        elif markers:
            _add_property(component, "pyflow:marker", str(markers))
        groups = package.get("groups")
        category = package.get("category")
        scopes: list[str] = []
        if isinstance(groups, (list, tuple)):
            scopes = [str(group) for group in groups if str(group)]
        elif category:
            scopes = [str(category)]
        optional = bool(package.get("optional"))
        if optional:
            _add_property(component, "pyflow:scope", "optional")
        elif scopes:
            if "main" in scopes or "default" in scopes:
                _add_property(component, "pyflow:scope", "runtime")
            else:
                for group in scopes:
                    _add_property(
                        component,
                        "pyflow:scope",
                        "dev" if group in {"dev", "development", "test"} else f"group:{group}",
                    )
        raw_files = package.get("files", ()) or ()
        if not isinstance(raw_files, (list, tuple)):
            findings.append(
                SupplyChainFinding(
                    kind="invalid-lock-package",
                    message="Lockfile files field must be an array",
                    location=str(path),
                    severity="HIGH",
                    details={"component": name},
                )
            )
            raw_files = ()
        artifacts = list(raw_files)
        if isinstance(package.get("sdist"), dict):
            artifacts.append(package["sdist"])
        raw_wheels = package.get("wheels", ()) or ()
        if isinstance(raw_wheels, (list, tuple)):
            artifacts.extend(raw_wheels)
        elif raw_wheels:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-lock-package",
                    message="Lockfile wheels field must be an array",
                    location=str(path),
                    severity="HIGH",
                    details={"component": name},
                )
            )
        hashes = _hashes_from_lock_files(artifacts, path, findings)
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
        refs_by_name.setdefault(canonicalize_name(name), []).append(str(component["purl"]))

        raw_dependencies = package.get("dependencies", {}) or {}
        names: Iterable[tuple[Any, Any]]
        if isinstance(raw_dependencies, dict):
            names = raw_dependencies.items()
        elif isinstance(raw_dependencies, list):
            names = (
                (
                    (
                        value.get("name"),
                        value.get("version") or value.get("specifier"),
                    )
                    if isinstance(value, dict)
                    else (str(value).split()[0], None)
                )
                for value in raw_dependencies
            )
        else:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-lock-package",
                    message="Lockfile dependencies field must be a table or array",
                    location=str(path),
                    severity="HIGH",
                    details={"component": name},
                )
            )
            names = ()
        for dependency_name, constraint in names:
            if dependency_name:
                constraint_text = (
                    _normalize_poetry_constraint(str(constraint))
                    if isinstance(constraint, str)
                    else None
                )
                dependency_names.append(
                    (str(component["purl"]), str(dependency_name), constraint_text)
                )
        if isinstance(raw_dependencies, list):
            for dependency in raw_dependencies:
                if not isinstance(dependency, dict):
                    continue
                dependency_name = dependency.get("name")
                dependency_version = dependency.get("version")
                dependency_marker = dependency.get("marker")
                if dependency_name and dependency_marker:
                    version_markers.setdefault(
                        (
                            canonicalize_name(str(dependency_name)),
                            str(dependency_version) if dependency_version else None,
                        ),
                        set(),
                    ).add(str(dependency_marker))
        for section, scope_kind in (
            ("optional-dependencies", "optional"),
            ("dev-dependencies", "dev"),
        ):
            groups = package.get(section, {}) or {}
            if not isinstance(groups, dict):
                continue
            for group_name, members in groups.items():
                if not isinstance(members, (list, tuple)):
                    continue
                for member in members:
                    member_name = member.get("name") if isinstance(member, dict) else member
                    if not member_name:
                        continue
                    member_version = member.get("version") if isinstance(member, dict) else None
                    scope = f"optional:{group_name}" if scope_kind == "optional" else "dev"
                    group_scopes.setdefault(
                        (
                            canonicalize_name(str(member_name)),
                            str(member_version) if member_version else None,
                        ),
                        set(),
                    ).add((scope, f'extra == "{group_name}"'))

    for component in components:
        component_name = canonicalize_name(str(component.get("name", "")))
        component_version = str(component.get("version", ""))
        markers = set(version_markers.get((component_name, component_version), ()))
        markers.update(version_markers.get((component_name, None), ()))
        for marker in sorted(markers):
            _add_property(component, "pyflow:marker", marker)
        group_entries = set(group_scopes.get((component_name, component_version), ()))
        group_entries.update(group_scopes.get((component_name, None), ()))
        for scope, marker in group_entries:
            _add_property(component, "pyflow:scope", scope)
            _add_property(component, "pyflow:marker", marker)

    edges = [
        (source_ref, _best_dependency_ref(name, refs_by_name, constraint))
        for source_ref, name, constraint in dependency_names
    ]
    return components, edges


def _pipfile_requirement(name: str, value: Any) -> str | None:
    if isinstance(value, str):
        constraint = value.strip()
        if not constraint or constraint == "*":
            return name
        if constraint[0].isdigit():
            return f"{name}=={constraint}"
        return f"{name}{constraint}"
    if not isinstance(value, dict):
        return None
    raw_extras = value.get("extras") or ()
    extras = raw_extras if isinstance(raw_extras, (list, tuple)) else ()
    display_name = f"{name}[{','.join(str(item) for item in extras)}]" if extras else name
    marker = value.get("markers")
    for key in ("git", "url", "path", "file"):
        target = value.get(key)
        if not target:
            continue
        target_text = str(target)
        if key == "git" and not target_text.startswith(("git+", "ssh://")):
            target_text = "git+" + target_text
        revision = value.get("ref") or value.get("rev") or value.get("commit")
        if revision and target_text.startswith(("git+", "hg+", "svn+", "bzr+")):
            target_text += f"@{revision}"
        requirement = f"{display_name} @ {target_text}"
        if marker:
            requirement += f" ; {marker}"
        return requirement
    version = value.get("version")
    constraint = str(version).strip() if version else ""
    if constraint == "*":
        constraint = ""
    elif constraint and constraint[0].isdigit():
        constraint = f"=={constraint}"
    requirement = display_name if not constraint else f"{display_name}{constraint}"
    if marker:
        requirement += f" ; {marker}"
    return requirement


def _components_from_pipfile(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> list[dict[str, Any]]:
    data = _load_toml(path, findings, limits, "invalid-pipfile")
    if data is None:
        return []
    components: list[dict[str, Any]] = []
    groups: list[tuple[str, str, str | None]] = [
        ("packages", "runtime", None),
        ("dev-packages", "dev", 'extra == "dev"'),
    ]
    for section, scope, marker in groups:
        mapping = data.get(section, {}) or {}
        if not isinstance(mapping, dict):
            _manifest_type_finding(path, findings, section, "a table")
            continue
        for name, value in mapping.items():
            if not isinstance(value, (str, dict)):
                findings.append(
                    SupplyChainFinding(
                        kind="invalid-pipfile",
                        message="Pipfile dependency must be a string or table",
                        location=str(path),
                        severity="MEDIUM",
                        details={"section": section, "component": str(name)},
                    )
                )
                continue
            requirement_text = _pipfile_requirement(str(name), value)
            if not requirement_text:
                continue
            component = _parse_requirement(
                requirement_text,
                path,
                None,
                findings,
                audit_pin=False,
                scope=scope,
                marker=marker,
            )
            if component is not None:
                components.append(component)
    sources = data.get("source", ()) or ()
    if isinstance(sources, dict):
        sources = [sources]
    if isinstance(sources, (list, tuple)):
        for source in sources:
            if isinstance(source, dict):
                _audit_primary_index(path, str(source.get("url", "")), findings)
                if source.get("verify_ssl") is False:
                    findings.append(
                        SupplyChainFinding(
                            kind="insecure-package-index",
                            message="Package source disables TLS certificate verification",
                            location=str(path),
                            severity="HIGH",
                            details={
                                "url": _redacted_url(str(source.get("url", ""))),
                                "verify_ssl": False,
                            },
                        )
                    )
    elif sources:
        _manifest_type_finding(path, findings, "source", "an array of tables")
    return components


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

    if not isinstance(data, dict):
        findings.append(
            SupplyChainFinding(
                kind="invalid-lockfile",
                message="Pipfile.lock must contain a JSON object",
                location=str(path),
                severity="HIGH",
            )
        )
        return []

    components: list[dict[str, Any]] = []
    for scope in ("default", "develop"):
        section = data.get(scope, {}) or {}
        if not isinstance(section, dict):
            findings.append(
                SupplyChainFinding(
                    kind="invalid-lockfile",
                    message=f"Pipfile.lock {scope} section must be an object",
                    location=str(path),
                    severity="HIGH",
                    details={"section": scope},
                )
            )
            continue
        for name, value in section.items():
            entry = value if isinstance(value, dict) else {"version": value}
            version_text = str(entry.get("version", ""))
            version = version_text[2:] if version_text.startswith("==") else None
            component = _component(str(name), version=version)
            _add_property(component, "pyflow:scope", scope)
            marker = entry.get("markers") or entry.get("marker")
            if marker:
                _add_property(component, "pyflow:marker", str(marker).strip())
            raw_extras = entry.get("extras") or ()
            if isinstance(raw_extras, (list, tuple)) and raw_extras:
                _add_property(component, "pyflow:extras", ",".join(str(e) for e in raw_extras))
            raw_hashes = entry.get("hashes", ()) or ()
            if not isinstance(raw_hashes, (list, tuple)):
                findings.append(
                    SupplyChainFinding(
                        kind="invalid-lockfile",
                        message="Pipfile.lock hashes field must be an array",
                        location=str(path),
                        severity="HIGH",
                        details={"component": str(name)},
                    )
                )
                raw_hashes = ()
            hashes = _hashes_from_strings(raw_hashes, path, findings)
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
            source_url = (
                entry.get("git") or entry.get("path") or entry.get("file") or entry.get("url")
            )
            if not version and not source_url:
                findings.append(
                    SupplyChainFinding(
                        kind="unversioned-lock-package",
                        message="Pipfile.lock entry has neither an exact version nor an immutable source",
                        location=str(path),
                        severity="HIGH",
                        details={"component": str(name)},
                    )
                )
            if source_url:
                revision = str(entry.get("ref") or entry.get("rev") or entry.get("commit") or "")
                recorded_url = str(source_url)
                if entry.get("git"):
                    if not recorded_url.startswith(("git+", "hg+", "svn+", "bzr+", "ssh://")):
                        recorded_url = "git+" + recorded_url
                    if revision:
                        recorded_url += f"@{revision}"
                if entry.get("path") or entry.get("file"):
                    local_source = Path(str(source_url))
                    if not local_source.is_absolute():
                        local_source = path.parent / local_source
                    recorded_url = local_source.resolve(strict=False).as_uri()
                    findings.append(
                        SupplyChainFinding(
                            kind="local-path-requirement",
                            message="Locked dependency references mutable local path content",
                            location=str(path),
                            severity="MEDIUM",
                            details={"component": str(name), "path": str(source_url)},
                        )
                    )
                safe_url = _redacted_url(recorded_url)
                component["externalReferences"] = [{"type": "distribution", "url": safe_url}]
                _add_property(component, "pyflow:source-url", safe_url)
                _audit_embedded_credentials(path, str(source_url), findings, str(name))
                if entry.get("git") and not re.fullmatch(r"[0-9a-fA-F]{40,64}", revision):
                    findings.append(
                        SupplyChainFinding(
                            kind="unpinned-vcs-dependency",
                            message="VCS dependency is not locked to a full commit identifier",
                            location=str(path),
                            severity="HIGH",
                            details={"component": name, "ref": revision},
                        )
                    )
            components.append(component)

    meta = data.get("_meta", {}) or {}
    meta_sources = meta.get("sources", ()) or () if isinstance(meta, dict) else ()
    if not isinstance(meta_sources, (list, tuple)):
        meta_sources = ()
    for source in meta_sources:
        if isinstance(source, dict):
            _audit_primary_index(path, str(source.get("url", "")), findings)
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
    unresolved_edges: list[tuple[str, str, str | None]] = []
    raw_packages = data.get("packages", ()) or ()
    if not isinstance(raw_packages, (list, tuple)):
        findings.append(
            SupplyChainFinding(
                kind="invalid-pylock",
                message="pylock.toml packages must be an array of tables",
                location=str(path),
                severity="HIGH",
            )
        )
        return [], []
    for package in raw_packages:
        if not isinstance(package, dict) or not package.get("name"):
            continue
        name = str(package["name"])
        version = _string_or_none(package.get("version"))
        component = _component(name, version=version)
        if not version and not package.get("vcs") and not package.get("directory"):
            findings.append(
                SupplyChainFinding(
                    kind="unversioned-lock-package",
                    message="Lockfile package has neither an exact version nor an immutable source",
                    location=str(path),
                    severity="HIGH",
                    details={"component": name},
                )
            )
        directory = package.get("directory")
        if directory is not None and not isinstance(directory, dict):
            findings.append(
                SupplyChainFinding(
                    kind="invalid-pylock",
                    message="pylock.toml directory entry must be a table",
                    location=str(path),
                    severity="HIGH",
                    details={"component": name},
                )
            )
        elif isinstance(directory, dict) and directory.get("path"):
            local_path = str(directory["path"])
            local_source = Path(local_path)
            if not local_source.is_absolute():
                local_source = path.parent / local_source
            source_uri = local_source.resolve(strict=False).as_uri()
            _add_property(component, "pyflow:source-url", source_uri)
            findings.append(
                SupplyChainFinding(
                    kind="local-path-requirement",
                    message="Locked dependency references mutable local path content",
                    location=str(path),
                    severity="MEDIUM",
                    details={"component": name, "path": local_path},
                )
            )
        artifact_hashes: list[dict[str, str]] = []
        for key in ("archive", "sdist"):
            artifact = package.get(key)
            if isinstance(artifact, dict):
                artifact_hashes.extend(
                    _hashes_from_mapping(artifact.get("hashes", {}) or {}, path, findings)
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
        if vcs is not None and not isinstance(vcs, dict):
            findings.append(
                SupplyChainFinding(
                    kind="invalid-pylock",
                    message="pylock.toml vcs entry must be a table",
                    location=str(path),
                    severity="HIGH",
                    details={"component": name},
                )
            )
        elif isinstance(vcs, dict):
            url = vcs.get("url") or vcs.get("path")
            commit = str(vcs.get("commit-id", ""))
            if url:
                recorded_url = str(url)
                vcs_type = str(vcs.get("type") or "git").casefold()
                if vcs_type in {"git", "hg", "svn", "bzr"} and not recorded_url.startswith(
                    ("git+", "hg+", "svn+", "bzr+", "ssh://")
                ):
                    recorded_url = f"{vcs_type}+{recorded_url}"
                if commit:
                    recorded_url += f"@{commit}"
                safe_url = _redacted_url(recorded_url)
                component["externalReferences"] = [{"type": "vcs", "url": safe_url}]
                _add_property(component, "pyflow:source-url", safe_url)
                _audit_embedded_credentials(path, str(url), findings, name)
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
        refs_by_name.setdefault(canonicalize_name(name), []).append(str(component["purl"]))
        raw_dependencies = package.get("dependencies", ()) or ()
        if not isinstance(raw_dependencies, (list, tuple)):
            findings.append(
                SupplyChainFinding(
                    kind="invalid-pylock",
                    message="pylock.toml dependencies must be an array",
                    location=str(path),
                    severity="HIGH",
                    details={"component": name},
                )
            )
            raw_dependencies = ()
        for dependency in raw_dependencies:
            dependency_name = dependency.get("name") if isinstance(dependency, dict) else dependency
            if dependency_name:
                constraint = None
                if isinstance(dependency, dict):
                    constraint = dependency.get("version") or dependency.get("specifier")
                unresolved_edges.append(
                    (
                        str(component["purl"]),
                        str(dependency_name),
                        str(constraint) if constraint else None,
                    )
                )

    edges = [
        (source, _best_dependency_ref(name, refs_by_name, constraint))
        for source, name, constraint in unresolved_edges
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
    components: list[dict[str, Any]] = []

    root: dict[str, Any] | None = None
    if parser.has_option("metadata", "name"):
        root = _component(
            parser.get("metadata", "name").strip(),
            version=(
                parser.get("metadata", "version").strip()
                if parser.has_option("metadata", "version")
                else None
            ),
        )
        root["type"] = "application"
        if parser.has_option("metadata", "license"):
            root["licenses"] = [_license_entry(parser.get("metadata", "license").strip())]
        if parser.has_option("metadata", "license_file"):
            _add_property(
                root,
                "pyflow:license-file",
                parser.get("metadata", "license_file").strip(),
            )
        if parser.has_option("metadata", "license_files"):
            _add_property(
                root,
                "pyflow:license-file",
                parser.get("metadata", "license_files").strip(),
            )
        components.append(root)

    declared: list[tuple[str, str, str | None]] = []
    if parser.has_option("options", "install_requires"):
        for value in parser.get("options", "install_requires").splitlines():
            cleaned = _strip_requirement_comment(value).strip()
            if cleaned:
                declared.append((cleaned, "runtime", None))
    if parser.has_option("options", "setup_requires"):
        for value in parser.get("options", "setup_requires").splitlines():
            cleaned = _strip_requirement_comment(value).strip()
            if cleaned:
                declared.append((cleaned, "build", None))
    if parser.has_section("options.extras_require"):
        for group, raw in parser.items("options.extras_require"):
            marker = f'extra == "{group}"'
            for value in raw.splitlines():
                cleaned = _strip_requirement_comment(value).strip()
                if cleaned:
                    declared.append((cleaned, f"optional:{group}", marker))

    expanded: list[tuple[str, str, str | None]] = []
    for requirement_text, scope, marker in declared:
        if requirement_text.startswith("file:"):
            included_text = requirement_text[5:].strip()
            included = path.parent / included_text
            if included.is_file() and not included.is_symlink():
                for value in _read_setup_requirement_file(included, limits, findings):
                    expanded.append((value, scope, marker))
            else:
                findings.append(
                    SupplyChainFinding(
                        kind="missing-requirement-include",
                        message="setup.cfg file: include does not exist",
                        location=str(path),
                        severity="HIGH",
                        details={"include": included_text},
                    )
                )
            continue
        expanded.append((requirement_text, scope, marker))

    for requirement_text, scope, marker in expanded:
        component = _parse_requirement(
            requirement_text,
            path,
            None,
            findings,
            audit_pin=False,
            scope=scope,
            marker=marker,
        )
        if component is not None:
            components.append(component)
    return components


def _setup_requirement_file_candidates(base_dir: Path, value: str) -> list[Path]:
    if not value.endswith((".txt", ".in")):
        return []
    candidates = [base_dir / value]
    if not value.startswith(("requirements/", "req/", "constraints/")):
        candidates.append(base_dir / "requirements" / value)
    return [
        candidate for candidate in candidates if candidate.is_file() and not candidate.is_symlink()
    ]


def _setup_requirement_file_like(path: Path) -> bool:
    lowered = path.name.lower()
    if lowered.startswith(("requirements", "constraints")):
        return True
    if lowered.endswith(("-requirements.txt", "_requirements.txt", "-constraints.txt")):
        return True
    return path.parent.name.lower() in {"requirements", "reqs", "constraints"}


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _read_setup_requirement_file(
    path: Path,
    limits: ScanLimits | None,
    findings: list[SupplyChainFinding],
    stack: frozenset[Path] = frozenset(),
) -> list[str]:
    """Read a setup.py-referenced requirements file with normal pip semantics."""

    resolved = path.resolve(strict=False)
    if resolved in stack:
        findings.append(
            SupplyChainFinding(
                kind="requirement-include-cycle",
                message="Requirement files include each other cyclically",
                location=str(path),
                severity="HIGH",
            )
        )
        return []
    text = _read_text(path, findings, limits or ScanLimits(), "setup.py requirement file")
    if text is None:
        return []
    requirements: list[str] = []
    for line_no, raw_line in _logical_requirement_lines(text):
        line = _strip_requirement_comment(raw_line).strip()
        if not line:
            continue
        include = _requirement_include(line)
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
            included = Path(include)
            explicitly_absolute = included.is_absolute()
            if not explicitly_absolute:
                included = path.parent / included
            boundary = _requirement_boundary(path).resolve(strict=False)
            resolved_included = included.resolve(strict=False)
            if explicitly_absolute or not _is_relative_to(resolved_included, boundary):
                findings.append(
                    SupplyChainFinding(
                        kind="external-requirement-include",
                        message="Requirement include escapes the project boundary",
                        location=str(path),
                        severity="MEDIUM",
                        details={"line": line_no, "include": include},
                    )
                )
                continue
            if included.is_symlink():
                findings.append(
                    SupplyChainFinding(
                        kind="requirement-include-symlink",
                        message="Requirement include is a symbolic link and was not followed",
                        location=str(path),
                        severity="HIGH",
                        details={"line": line_no, "include": include},
                    )
                )
            elif not included.is_file():
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
                requirements.extend(
                    _read_setup_requirement_file(
                        included,
                        limits,
                        findings,
                        stack | {resolved},
                    )
                )
            continue
        if line.startswith("-"):
            # Index options, --require-hashes, editable installs, etc. are not
            # dependency strings, but index/security options still need an
            # audit when setup.py is the only reference to this file.
            if line.startswith(("-e ", "--editable ", "--editable=")):
                findings.append(
                    SupplyChainFinding(
                        kind="editable-requirement",
                        message="Editable dependency can change without updating the manifest",
                        location=str(path),
                        severity="MEDIUM",
                        details={"line": line_no, "requirement": line},
                    )
                )
                continue
            _audit_pip_option(path, line_no, line, findings)
            continue
        requirements.append(line)
    return requirements


def _referenced_requirement_strings(
    node: ast.AST,
    base_dir: Path,
    limits: ScanLimits | None,
    findings: list[SupplyChainFinding],
    *,
    only_requirement_like: bool = False,
) -> list[str]:
    values: list[str] = []
    for sub in ast.walk(node):
        if not (isinstance(sub, ast.Constant) and isinstance(sub.value, str)):
            continue
        for candidate in _setup_requirement_file_candidates(base_dir, sub.value):
            if only_requirement_like and not _setup_requirement_file_like(candidate):
                continue
            values.extend(_read_setup_requirement_file(candidate, limits, findings))
    return _dedupe_strings(values)


def _resolve_setup_expr_to_strings(
    expr: ast.AST,
    env: dict[str, ast.AST],
    funcs: dict[str, ast.AST],
    base_dir: Path,
    depth: int = 0,
    *,
    limits: ScanLimits | None = None,
    findings: list[SupplyChainFinding] | None = None,
) -> list[str]:
    if depth > 10:
        return []
    audit_findings = findings if findings is not None else []
    try:
        val = ast.literal_eval(expr)
        if isinstance(val, str):
            return [val]
        if isinstance(val, (list, tuple, set)):
            return [str(x) for x in val if isinstance(x, str)]
    except (ValueError, TypeError, SyntaxError, MemoryError):
        pass

    if isinstance(expr, ast.Name) and expr.id in env:
        return _resolve_setup_expr_to_strings(
            env[expr.id],
            env,
            funcs,
            base_dir,
            depth + 1,
            limits=limits,
            findings=audit_findings,
        )

    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        results: list[str] = []
        for elt in expr.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                results.append(elt.value)
            elif isinstance(elt, ast.Name) and elt.id in env:
                results.extend(
                    _resolve_setup_expr_to_strings(
                        env[elt.id],
                        env,
                        funcs,
                        base_dir,
                        depth + 1,
                        limits=limits,
                        findings=audit_findings,
                    )
                )
            elif isinstance(elt, (ast.Subscript, ast.BinOp, ast.Call)):
                results.extend(
                    _resolve_setup_expr_to_strings(
                        elt,
                        env,
                        funcs,
                        base_dir,
                        depth + 1,
                        limits=limits,
                        findings=audit_findings,
                    )
                )
        return _dedupe_strings(results)

    if isinstance(expr, ast.Subscript):
        slice_node = getattr(expr, "slice", None)
        slice_val = slice_node.value if isinstance(slice_node, ast.Constant) else None
        if isinstance(slice_val, int):
            target_seq = _resolve_setup_expr_to_strings(
                expr.value,
                env,
                funcs,
                base_dir,
                depth + 1,
                limits=limits,
                findings=audit_findings,
            )
            if 0 <= slice_val < len(target_seq):
                return [target_seq[slice_val]]
        elif slice_val and isinstance(slice_val, str):
            for candidate_name in (
                "_deps",
                "deps",
                "DEPENDENCIES",
                "requirements",
                "install_requires",
            ):
                if candidate_name in env:
                    cand_strings = _resolve_setup_expr_to_strings(
                        env[candidate_name],
                        env,
                        funcs,
                        base_dir,
                        depth + 1,
                        limits=limits,
                        findings=audit_findings,
                    )
                    for s in cand_strings:
                        norm_s = canonicalize_name(
                            s.split("<")[0]
                            .split(">")[0]
                            .split("=")[0]
                            .split("!")[0]
                            .split("~")[0]
                            .strip()
                        )
                        if norm_s == canonicalize_name(slice_val):
                            return [s]
            base_name = getattr(expr.value, "id", "")
            if base_name in {
                "_deps",
                "deps",
                "DEPENDENCIES",
                "requirements",
                "install_requires",
                "REQUIRES",
            }:
                return [slice_val]
            return []

    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _dedupe_strings(
            _resolve_setup_expr_to_strings(
                expr.left,
                env,
                funcs,
                base_dir,
                depth + 1,
                limits=limits,
                findings=audit_findings,
            )
            + _resolve_setup_expr_to_strings(
                expr.right,
                env,
                funcs,
                base_dir,
                depth + 1,
                limits=limits,
                findings=audit_findings,
            )
        )

    if isinstance(expr, ast.Call):
        func_name = getattr(expr.func, "id", "") or getattr(expr.func, "attr", "")
        if func_name in ("list", "tuple", "set") and expr.args:
            return _resolve_setup_expr_to_strings(
                expr.args[0],
                env,
                funcs,
                base_dir,
                depth + 1,
                limits=limits,
                findings=audit_findings,
            )
        if func_name in funcs:
            func_node = funcs[func_name]
            collected: list[str] = []
            for ret in ast.walk(func_node):
                if isinstance(ret, ast.Return) and ret.value:
                    collected.extend(
                        _resolve_setup_expr_to_strings(
                            ret.value,
                            env,
                            funcs,
                            base_dir,
                            depth + 1,
                            limits=limits,
                            findings=audit_findings,
                        )
                    )
            # A setup.py helper may branch between platform-specific files.
            # Union every referenced requirements file instead of selecting an
            # arbitrary return or branch.
            collected.extend(
                _referenced_requirement_strings(func_node, base_dir, limits, audit_findings)
            )
            reqs = _dedupe_strings(collected)
            if reqs:
                return reqs

    reqs = _referenced_requirement_strings(expr, base_dir, limits, audit_findings)
    return reqs


def _setup_module_requirement_fallback(
    tree: ast.AST,
    base_dir: Path,
    limits: ScanLimits | None,
    findings: list[SupplyChainFinding],
) -> list[str]:
    """Resolve ``with open("requirements.txt")``-style setup.py helpers.

    These files are referenced outside the ``install_requires`` expression
    itself, so the expression resolver cannot see them.
    """

    return _referenced_requirement_strings(
        tree,
        base_dir,
        limits,
        findings,
        only_requirement_like=True,
    )


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
    except (SyntaxError, ValueError) as exc:
        findings.append(
            SupplyChainFinding(
                kind="invalid-setup-script",
                message="Could not parse setup.py without executing it",
                location=str(path),
                severity="MEDIUM",
                details={
                    "line": getattr(exc, "lineno", None),
                    "error": getattr(exc, "msg", str(exc)),
                },
            )
        )
        return []

    _audit_setup_behavior(path, tree, findings)
    components: list[dict[str, Any]] = []
    env: dict[str, ast.AST] = {}
    funcs: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    env[target.id] = node.value
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = node

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func).split(".")[-1] != "setup":
            continue
        keywords = {keyword.arg: keyword for keyword in node.keywords if keyword.arg}

        root: dict[str, Any] | None = None
        name = _setup_first_string(
            keywords.get("name"), env, funcs, path.parent, limits=limits, findings=findings
        )
        if not name:
            # Common setup.py shims derive metadata from JSON/modules.  Use a
            # project-name constant when it is statically available.
            for constant_name in ("PROJ_NAME", "PROJECT_NAME", "PACKAGE_NAME"):
                if constant_name not in env:
                    continue
                candidates = _resolve_setup_expr_to_strings(
                    env[constant_name],
                    env,
                    funcs,
                    path.parent,
                    limits=limits,
                    findings=findings,
                )
                if candidates and candidates[0].strip():
                    name = candidates[0].strip()
                    break
        if name:
            version = _setup_first_string(
                keywords.get("version"), env, funcs, path.parent, limits=limits, findings=findings
            )
            root = _component(name, version=version)
            root["type"] = "application"
            license_value = _setup_first_string(
                keywords.get("license"), env, funcs, path.parent, limits=limits, findings=findings
            )
            if license_value:
                root["licenses"] = [_license_entry(license_value)]
            components.append(root)

        declared: list[tuple[str, str, str | None]] = []
        for keyword_name, scope in (
            ("install_requires", "runtime"),
            ("setup_requires", "build"),
            ("tests_require", "test"),
        ):
            keyword = keywords.get(keyword_name)
            if keyword is None:
                continue
            values = _resolve_setup_expr_to_strings(
                keyword.value,
                env,
                funcs,
                path.parent,
                limits=limits,
                findings=findings,
            )
            if not values and keyword_name == "install_requires":
                values = _setup_module_requirement_fallback(tree, path.parent, limits, findings)
            if not values and not _is_empty_sequence_literal(keyword.value):
                findings.append(
                    SupplyChainFinding(
                        kind="unresolved-setup-requirements",
                        message=(
                            "setup.py dependency list could not be resolved statically; "
                            "the inventory may be incomplete"
                        ),
                        location=str(path),
                        severity="HIGH",
                        details={"keyword": keyword_name},
                    )
                )
            for value in values:
                clean_val = _strip_requirement_comment(value).strip()
                if clean_val and not clean_val.startswith(("#", "-")):
                    declared.append((clean_val, scope, None))

        extras_keyword = keywords.get("extras_require")
        if extras_keyword is not None:
            extras_groups = _resolve_setup_extras(
                extras_keyword.value,
                env,
                funcs,
                path.parent,
                limits=limits,
                findings=findings,
            )
            if not extras_groups and not _is_empty_mapping_literal(extras_keyword.value, env):
                findings.append(
                    SupplyChainFinding(
                        kind="unresolved-setup-requirements",
                        message=(
                            "setup.py extras_require could not be resolved statically; "
                            "the inventory may be incomplete"
                        ),
                        location=str(path),
                        severity="HIGH",
                        details={"keyword": "extras_require"},
                    )
                )
            for group, values in extras_groups:
                marker = f'extra == "{group}"'
                for value in values:
                    clean_val = _strip_requirement_comment(value).strip()
                    if clean_val and not clean_val.startswith(("#", "-")):
                        declared.append((clean_val, f"optional:{group}", marker))

        for requirement_text, scope, marker in declared:
            component = _parse_requirement(
                requirement_text,
                path,
                getattr(keywords.get("install_requires"), "lineno", None),
                findings,
                audit_pin=False,
                scope=scope,
                marker=marker,
            )
            if component is not None:
                components.append(component)
    return components


def _is_empty_mapping_literal(expr: ast.AST, env: dict[str, ast.AST]) -> bool:
    if isinstance(expr, ast.Dict):
        return not expr.keys
    if isinstance(expr, ast.Name) and expr.id in env:
        return _is_empty_mapping_literal(env[expr.id], env)
    return False


def _is_empty_sequence_literal(expr: ast.AST) -> bool:
    return isinstance(expr, (ast.List, ast.Tuple, ast.Set)) and not getattr(expr, "elts", ())


def _setup_first_string(
    keyword: ast.keyword | None,
    env: dict[str, ast.AST],
    funcs: dict[str, ast.AST],
    base_dir: Path,
    *,
    limits: ScanLimits | None = None,
    findings: list[SupplyChainFinding] | None = None,
) -> str | None:
    if keyword is None:
        return None
    values = _resolve_setup_expr_to_strings(
        keyword.value,
        env,
        funcs,
        base_dir,
        limits=limits,
        findings=findings,
    )
    for value in values:
        cleaned = value.strip()
        if cleaned:
            return cleaned
    return None


def _resolve_setup_extras(
    expr: ast.AST,
    env: dict[str, ast.AST],
    funcs: dict[str, ast.AST],
    base_dir: Path,
    *,
    limits: ScanLimits | None = None,
    findings: list[SupplyChainFinding] | None = None,
) -> list[tuple[str, list[str]]]:
    """Resolve ``extras_require`` mappings without executing setup.py."""

    if isinstance(expr, ast.Name) and expr.id in env:
        return _resolve_setup_extras(
            env[expr.id], env, funcs, base_dir, limits=limits, findings=findings
        )
    if not isinstance(expr, ast.Dict):
        return []
    groups: list[tuple[str, list[str]]] = []
    for key, value in zip(expr.keys, expr.values):
        if key is None:
            continue
        try:
            group = ast.literal_eval(key)
        except (ValueError, TypeError, SyntaxError, MemoryError):
            continue
        if isinstance(group, str) and group.strip():
            groups.append(
                (
                    group.strip(),
                    _resolve_setup_expr_to_strings(
                        value,
                        env,
                        funcs,
                        base_dir,
                        limits=limits,
                        findings=findings,
                    ),
                )
            )
    return groups


def _audit_setup_behavior(
    path: Path,
    tree: ast.AST,
    findings: list[SupplyChainFinding],
) -> None:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    dangerous = {
        "os.system": "executes a shell command",
        "os.popen": "executes a shell command",
        "os.execv": "replaces the installer process",
        "os.execve": "replaces the installer process",
        "os.execl": "replaces the installer process",
        "os.execle": "replaces the installer process",
        "os.spawnl": "starts a subprocess",
        "os.spawnv": "starts a subprocess",
        "subprocess.call": "starts a subprocess",
        "subprocess.run": "starts a subprocess",
        "subprocess.Popen": "starts a subprocess",
        "subprocess.check_call": "starts a subprocess",
        "subprocess.check_output": "starts a subprocess",
        "urllib.request.urlopen": "performs a network request",
        "urllib.request.urlretrieve": "downloads a file during installation",
        "requests.get": "performs a network request",
        "requests.post": "performs a network request",
        "requests.request": "performs a network request",
        "socket.socket": "opens a network socket",
        "socket.create_connection": "opens a network connection",
        "http.client.HTTPConnection": "opens a network connection",
        "http.client.HTTPSConnection": "opens a network connection",
        "ftplib.FTP": "opens a network connection",
        "shutil.rmtree": "recursively deletes files",
        "pathlib.Path.write_text": "writes files during installation",
        "pathlib.Path.write_bytes": "writes files during installation",
        "ctypes.CDLL": "loads native code",
        "ctypes.PyDLL": "loads native code",
        "importlib.import_module": "imports a module dynamically",
        "builtins.compile": "compiles dynamic code",
        "compile": "compiles dynamic code",
        "builtins.eval": "evaluates dynamic code",
        "builtins.exec": "executes dynamic code",
        "eval": "evaluates dynamic code",
        "exec": "executes dynamic code",
    }
    for descendant in _executed_setup_calls(tree):
        name = _call_name(descendant.func)
        first, dot, rest = name.partition(".")
        resolved = aliases.get(first, first) + (dot + rest if dot else "")
        action = dangerous.get(resolved)
        if action is None:
            continue
        if resolved.endswith(("eval", "exec", "compile")):
            severity = "CRITICAL"
        elif resolved.startswith("subprocess.") and _is_benign_subprocess(descendant):
            # Build backends commonly query the toolchain (git, python, a C
            # compiler) from setup.py.  Keep reporting it, but do not equate it
            # with an arbitrary downloader or shell.
            severity = "MEDIUM"
        else:
            severity = "HIGH"
        findings.append(
            SupplyChainFinding(
                kind="install-script-dangerous-behavior",
                message=f"Package installation script {action}",
                location=str(path),
                severity=severity,
                details={
                    "line": getattr(descendant, "lineno", None),
                    "call": resolved,
                },
            )
        )


_BENIGN_BUILD_COMMANDS = frozenset(
    {
        "cc",
        "cmake",
        "cp",
        "echo",
        "find",
        "g++",
        "gcc",
        "git",
        "grep",
        "ls",
        "make",
        "mkdir",
        "mv",
        "ninja",
        "pkg-config",
        "python",
        "python3",
        "sed",
        "tar",
        "true",
        "uname",
        "unzip",
    }
)


def _is_benign_subprocess(call: ast.Call) -> bool:
    """Return whether a subprocess call only runs a familiar build tool."""

    for keyword in call.keywords:
        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
            if bool(keyword.value.value):
                return False
    if not call.args:
        return False
    command = call.args[0]
    if isinstance(command, (ast.List, ast.Tuple)) and command.elts:
        executable = command.elts[0]
    else:
        executable = command
    if isinstance(executable, ast.Constant) and isinstance(executable.value, str):
        name = Path(executable.value).name
        if name in {"python", "python3", "py"}:
            # ``python -c ...`` and ``python some_script.py`` can execute
            # arbitrary code or network payloads.  Only version probes are
            # benign build-tool queries.
            if not isinstance(command, (ast.List, ast.Tuple)):
                return False
            args = [
                str(elt.value)
                for elt in command.elts[1:]
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ]
            return args in (["--version"], ["-V"])
        return name in _BENIGN_BUILD_COMMANDS
    return False


def _executed_setup_calls(tree: ast.AST) -> list[ast.Call]:
    """Return calls reachable from module execution without running setup.py."""

    functions = {
        node.name: node
        for node in getattr(tree, "body", ())
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    calls: list[ast.Call] = []
    queued_functions: list[str] = []
    visited_functions: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            calls.append(node)
            call_name = _call_name(node.func)
            if call_name in functions and call_name not in visited_functions:
                queued_functions.append(call_name)
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self.visit(default)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self.visit(default)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self.visit(default)

        def visit_If(self, node: ast.If) -> None:
            self.visit(node.test)
            if isinstance(node.test, ast.Constant):
                branch = node.body if bool(node.test.value) else node.orelse
                for child in branch:
                    self.visit(child)
                return
            for child in (*node.body, *node.orelse):
                self.visit(child)

    visitor = Visitor()
    for node in getattr(tree, "body", ()):
        visitor.visit(node)
    while queued_functions:
        name = queued_functions.pop()
        if name in visited_functions:
            continue
        visited_functions.add(name)
        for node in functions[name].body:
            visitor.visit(node)
    return calls


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _looks_like_template(text: str) -> bool:
    return any(
        ("{{" in line or "{%" in line) and not line.lstrip().startswith("#")
        for line in text.splitlines()
    )


def _template_manifest_finding(path: Path, description: str) -> SupplyChainFinding:
    return SupplyChainFinding(
        kind="template-manifest-skipped",
        message=f"Skipped an unrendered {description} template",
        location=str(path),
        severity="LOW",
    )


def _load_toml(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
    finding_kind: str,
) -> dict[str, Any] | None:
    text = _read_text(path, findings, limits, "TOML manifest")
    if text is None:
        return None
    if _looks_like_template(text):
        findings.append(_template_manifest_finding(path, "TOML"))
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
    hashes = []
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
        hashes.extend(_hashes_from_mapping({algorithm: digest}, path, findings))
    return _dedupe_hashes(hashes)


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
                    message="Artifact hash uses an unsupported algorithm",
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
                    message="Artifact hash uses a collision-prone algorithm",
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
                    message="Artifact hash has an invalid digest",
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
        key in source
        for key in (
            "git",
            "url",
            "path",
            "directory",
            "editable",
            "virtual",
            "workspace",
        )
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
    direct_url = source.get("url")
    vcs_url = source.get("git") or (direct_url if source_type == "git" else None)
    if vcs_url:
        safe_url = _redacted_url(str(vcs_url))
        component["externalReferences"] = [{"type": "vcs", "url": safe_url}]
        _add_property(component, "pyflow:source-url", safe_url)
        _audit_embedded_credentials(path, str(vcs_url), findings, str(component.get("name", "")))
        commit = _source_revision(source, str(vcs_url))
        if not commit:
            findings.append(
                SupplyChainFinding(
                    kind="unpinned-vcs-dependency",
                    message="VCS dependency is not locked to a full commit identifier",
                    location=str(path),
                    severity="HIGH",
                    details={"component": component.get("name"), "commit": commit},
                )
            )
    elif direct_url:
        safe_url = _redacted_url(str(direct_url))
        component["externalReferences"] = [{"type": "distribution", "url": safe_url}]
        _add_property(component, "pyflow:source-url", safe_url)
        if source.get("hash"):
            lock_hashes = _hashes_from_strings([str(source["hash"])], path, findings)
            if lock_hashes:
                component["hashes"] = lock_hashes
        _audit_embedded_credentials(path, str(direct_url), findings, str(component.get("name", "")))
        if not _remote_requirement_pinned(str(direct_url)) and not source.get("hash"):
            findings.append(
                SupplyChainFinding(
                    kind="remote-requirement",
                    message="Locked dependency uses a mutable direct URL",
                    location=str(path),
                    severity="MEDIUM",
                    details={
                        "component": component.get("name"),
                        "url": safe_url,
                        "pinned": False,
                    },
                )
            )
    local_path = source.get("path") or source.get("directory") or source.get("editable")
    if local_path and str(local_path).strip() not in {".", "./"}:
        local_text = str(local_path)
        local_source = Path(local_text)
        if not local_source.is_absolute():
            local_source = path.parent / local_source
        source_uri = local_source.resolve(strict=False).as_uri()
        _add_property(component, "pyflow:source-url", source_uri)
        component["externalReferences"] = [{"type": "distribution", "url": source_uri}]
        findings.append(
            SupplyChainFinding(
                kind="local-path-requirement",
                message="Locked dependency references mutable local workspace content",
                location=str(path),
                severity="MEDIUM",
                details={"component": component.get("name"), "path": local_text},
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
    if _contains_credentials(url):
        findings.append(
            SupplyChainFinding(
                kind="embedded-credentials",
                message="Locked artifact URL contains embedded credentials",
                location=str(path),
                severity="CRITICAL",
                details={"component": component_name, "url": _redacted_url(url)},
            )
        )


_DEFAULT_INDEX_HOSTS = frozenset(
    {
        "pypi.org",
        "pypi.python.org",
        "files.pythonhosted.org",
        "test.pypi.org",
    }
)


def _audit_primary_index(
    path: Path,
    url: str,
    findings: list[SupplyChainFinding],
) -> None:
    _audit_index_url(path, url, findings, "primary")
    parsed = urlparse(url)
    host = (parsed.hostname or "").casefold()
    if host and host not in _DEFAULT_INDEX_HOSTS:
        findings.append(
            SupplyChainFinding(
                kind="non-default-package-index",
                message="Primary package index is not PyPI",
                location=str(path),
                severity="MEDIUM",
                details={"url": _redacted_url(url), "host": host},
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
    if _contains_credentials(url):
        findings.append(
            SupplyChainFinding(
                kind="embedded-credentials",
                message="Package index URL contains embedded credentials",
                location=str(path),
                severity="CRITICAL",
                details={"url": _redacted_url(url)},
            )
        )
    if priority in {"supplemental", "secondary", "additional"}:
        if priority == "additional" and urlparse(url).scheme not in {"http", "https", "ftp"}:
            return
        if (urlparse(url).hostname or "").casefold() in _DEFAULT_INDEX_HOSTS:
            return
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
    if not _contains_credentials(url):
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
components_from_pipfile = _components_from_pipfile
components_from_pipfile_lock = _components_from_pipfile_lock
components_from_pylock = _components_from_pylock
components_from_setup_cfg = _components_from_setup_cfg
components_from_setup_py = _components_from_setup_py
