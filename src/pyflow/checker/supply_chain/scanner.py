"""Local supply-chain analysis helpers.

This module intentionally works only from local files and package metadata. It
does not query package indexes, so generated SBOMs are reproducible offline.
"""

from __future__ import annotations

import base64
import csv
import datetime as _datetime
import hashlib
import json
import os
import tarfile
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[import-not-found]


MAX_ARCHIVE_MEMBER_SIZE = 100 * 1024 * 1024


@dataclass(frozen=True)
class SupplyChainFinding:
    """A local supply-chain risk or metadata anomaly."""

    kind: str
    message: str
    location: str
    severity: str = "MEDIUM"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "location": self.location,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass(frozen=True)
class SupplyChainScan:
    """Components and findings discovered from local supply-chain inputs."""

    components: tuple[dict[str, Any], ...]
    findings: tuple[SupplyChainFinding, ...]


def scan_targets(
    targets: Iterable[str | os.PathLike[str]],
    *,
    recursive: bool = False,
    exclude: Iterable[str] = (),
) -> SupplyChainScan:
    """Scan local paths for package metadata, manifests, and archive issues."""

    excluded = tuple(str(item) for item in exclude if str(item))
    components: list[dict[str, Any]] = []
    findings: list[SupplyChainFinding] = []
    seen_files: set[Path] = set()

    for target in targets:
        path = Path(target)
        if _is_excluded(path, excluded):
            continue
        if not path.exists():
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
            recursive=recursive,
            excluded=excluded,
            components=components,
            findings=findings,
            seen_files=seen_files,
        )

    return SupplyChainScan(
        components=tuple(_dedupe_components(components)),
        findings=tuple(sorted(findings, key=lambda f: (f.location, f.kind, f.message))),
    )


def build_cyclonedx_document(scan: SupplyChainScan) -> dict[str, Any]:
    """Build a CycloneDX 1.3 JSON document from a local scan."""

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.3",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _datetime.datetime.now(_datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "tools": [{"vendor": "PyFlow", "name": "pyflow", "version": "0.1.0"}],
        },
        "components": list(scan.components),
    }


def format_findings_text(scan: SupplyChainScan) -> str:
    """Render local supply-chain findings for humans."""

    if not scan.findings:
        return "No supply-chain findings."
    lines = [f"Found {len(scan.findings)} supply-chain finding(s):", ""]
    for finding in scan.findings:
        lines.append(f"[{finding.severity}] {finding.kind}: {finding.message}")
        lines.append(f"  location: {finding.location}")
        if finding.details:
            lines.append(f"  details: {json.dumps(finding.details, sort_keys=True)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _scan_path(
    path: Path,
    *,
    recursive: bool,
    excluded: tuple[str, ...],
    components: list[dict[str, Any]],
    findings: list[SupplyChainFinding],
    seen_files: set[Path],
) -> None:
    if _is_excluded(path, excluded):
        return
    if path.is_dir():
        iterator = path.rglob("*") if recursive else path.iterdir()
        for child in sorted(iterator):
            if child.is_file() or child.is_dir():
                _scan_path(
                    child,
                    recursive=recursive,
                    excluded=excluded,
                    components=components,
                    findings=findings,
                    seen_files=seen_files,
                )
        return
    if not path.is_file():
        return

    resolved = path.resolve(strict=False)
    if resolved in seen_files:
        return
    seen_files.add(resolved)

    name = path.name
    if name == "METADATA" and path.parent.name.endswith(".dist-info"):
        component = _component_from_metadata(path)
        if component is not None:
            components.append(component)
        findings.extend(_audit_distribution_record(path.parent))
    elif _is_requirements_file(path):
        components.extend(_components_from_requirements(path, findings))
    elif name == "pyproject.toml":
        components.extend(_components_from_pyproject(path, findings))
    elif name == "poetry.lock":
        components.extend(_components_from_poetry_lock(path, findings))
    elif _looks_like_archive(path):
        _scan_archive(
            path,
            recursive=recursive,
            excluded=excluded,
            components=components,
            findings=findings,
            seen_files=seen_files,
        )


def _scan_archive(
    path: Path,
    *,
    recursive: bool,
    excluded: tuple[str, ...],
    components: list[dict[str, Any]],
    findings: list[SupplyChainFinding],
    seen_files: set[Path],
) -> None:
    with tempfile.TemporaryDirectory(prefix="pyflow_supply_chain_") as tmp:
        destination = Path(tmp)
        if zipfile.is_zipfile(path):
            _extract_zip(path, destination, findings)
        elif tarfile.is_tarfile(path):
            _extract_tar(path, destination, findings)
        else:
            return

        _scan_path(
            destination,
            recursive=True,
            excluded=excluded,
            components=components,
            findings=findings,
            seen_files=seen_files,
        )


def _extract_zip(
    path: Path, destination: Path, findings: list[SupplyChainFinding]
) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                issue = _archive_entry_issue(path, info.filename, info.file_size)
                if issue is not None:
                    findings.append(issue)
                    continue
                archive.extract(info, destination)
    except (OSError, zipfile.BadZipFile) as exc:
        findings.append(
            SupplyChainFinding(
                kind="archive-read-error",
                message="Could not read zip archive",
                location=str(path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )


def _extract_tar(
    path: Path, destination: Path, findings: list[SupplyChainFinding]
) -> None:
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive.getmembers():
                issue = _archive_entry_issue(path, member.name, member.size)
                if issue is not None:
                    findings.append(issue)
                    continue
                if member.issym() or member.islnk():
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-link-entry",
                            message="Archive member is a link",
                            location=str(path),
                            severity="HIGH",
                            details={"entry": member.name},
                        )
                    )
                    continue
                archive.extract(member, destination, set_attrs=False)
    except (OSError, tarfile.TarError) as exc:
        findings.append(
            SupplyChainFinding(
                kind="archive-read-error",
                message="Could not read tar archive",
                location=str(path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )


def _archive_entry_issue(
    archive_path: Path, entry: str, size: int
) -> SupplyChainFinding | None:
    entry_path = PurePosixPath(entry)
    if entry.startswith("/") or entry_path.is_absolute():
        return SupplyChainFinding(
            kind="archive-absolute-path",
            message="Archive contains an absolute path entry",
            location=str(archive_path),
            severity="HIGH",
            details={"entry": entry},
        )
    if ".." in entry_path.parts:
        return SupplyChainFinding(
            kind="archive-parent-reference",
            message="Archive contains an entry with a parent directory reference",
            location=str(archive_path),
            severity="HIGH",
            details={"entry": entry},
        )
    if size > MAX_ARCHIVE_MEMBER_SIZE:
        return SupplyChainFinding(
            kind="archive-member-too-large",
            message="Archive contains a member exceeding the size limit",
            location=str(archive_path),
            severity="MEDIUM",
            details={"entry": entry, "size": size, "limit": MAX_ARCHIVE_MEMBER_SIZE},
        )
    return None


def _component_from_metadata(metadata_path: Path) -> dict[str, Any] | None:
    data = Parser().parsestr(
        metadata_path.read_text(encoding="utf-8", errors="replace")
    )
    name = data.get("Name")
    if not name:
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
    return component


def _components_from_requirements(
    path: Path, findings: list[SupplyChainFinding]
) -> Iterator[dict[str, Any]]:
    for line_no, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        req_line = raw_line.split("#", 1)[0].strip()
        if not req_line:
            continue
        if "://" in req_line:
            findings.append(
                SupplyChainFinding(
                    kind="remote-requirement",
                    message="Requirement uses a remote URL",
                    location=str(path),
                    severity="MEDIUM",
                    details={"line": line_no, "requirement": req_line},
                )
            )
            continue
        component = _component_from_requirement(req_line)
        if component is not None:
            yield component
        else:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-requirement",
                    message="Could not parse requirement",
                    location=str(path),
                    severity="LOW",
                    details={"line": line_no, "requirement": req_line},
                )
            )


def _components_from_pyproject(
    path: Path, findings: list[SupplyChainFinding]
) -> Iterator[dict[str, Any]]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        findings.append(
            SupplyChainFinding(
                kind="invalid-pyproject",
                message="Could not parse pyproject.toml",
                location=str(path),
                severity="LOW",
                details={"error": str(exc)},
            )
        )
        return

    project = data.get("project", {})
    dependencies = list(project.get("dependencies", ()) or ())
    optional = project.get("optional-dependencies", {}) or {}
    for values in optional.values():
        dependencies.extend(values or ())

    for item in dependencies:
        component = _component_from_requirement(str(item))
        if component is not None:
            yield component


def _components_from_poetry_lock(
    path: Path, findings: list[SupplyChainFinding]
) -> Iterator[dict[str, Any]]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        findings.append(
            SupplyChainFinding(
                kind="invalid-poetry-lock",
                message="Could not parse poetry.lock",
                location=str(path),
                severity="LOW",
                details={"error": str(exc)},
            )
        )
        return

    for package in data.get("package", ()) or ():
        name = package.get("name")
        if name:
            yield _component(str(name), version=package.get("version"))


def _component_from_requirement(requirement_text: str) -> dict[str, Any] | None:
    try:
        requirement = Requirement(requirement_text)
    except InvalidRequirement:
        return None
    version = _exact_version(requirement)
    return _component(requirement.name, version=version)


def _component(name: str, *, version: str | None = None) -> dict[str, Any]:
    canonical = canonicalize_name(name)
    purl = f"pkg:pypi/{canonical}"
    if version:
        purl += f"@{version}"
    data: dict[str, Any] = {
        "type": "library",
        "name": canonical,
        "purl": purl,
    }
    if version:
        data["version"] = version
    return data


def _exact_version(requirement: Requirement) -> str | None:
    for spec in requirement.specifier:
        if spec.operator in {"==", "==="} and "*" not in spec.version:
            return spec.version
    return None


def _audit_distribution_record(dist_info: Path) -> Iterator[SupplyChainFinding]:
    record = dist_info / "RECORD"
    if not record.exists():
        yield SupplyChainFinding(
            kind="missing-record",
            message="Distribution metadata is missing RECORD",
            location=str(dist_info),
            severity="HIGH",
        )
        return

    root = dist_info.parent
    listed: set[Path] = set()
    rows = csv.reader(record.read_text(encoding="utf-8", errors="replace").splitlines())
    for parts in rows:
        if not parts or not parts[0]:
            continue
        rel_path = parts[0]
        target = (root / rel_path).resolve(strict=False)
        listed.add(target)
        if not target.exists():
            yield SupplyChainFinding(
                kind="record-missing-file",
                message="RECORD lists a file that is missing",
                location=str(record),
                severity="HIGH",
                details={"record": rel_path},
            )
            continue
        if len(parts) >= 2 and parts[1]:
            expected = parts[1]
            actual = _record_hash(target, expected)
            if actual is not None and actual != expected:
                yield SupplyChainFinding(
                    kind="record-invalid-hash",
                    message="RECORD file hash does not match local content",
                    location=str(target),
                    severity="HIGH",
                    details={"record_hash": expected, "actual_hash": actual},
                )

    for file_path in root.rglob("*"):
        if file_path.is_file() and file_path.resolve(strict=False) not in listed:
            yield SupplyChainFinding(
                kind="record-unlisted-file",
                message="Distribution contains a file not listed in RECORD",
                location=str(file_path),
                severity="LOW",
            )


def _record_hash(path: Path, expected: str) -> str | None:
    if "=" not in expected:
        return None
    algorithm, _digest = expected.split("=", 1)
    normalized = algorithm.lower().replace("-", "")
    if normalized not in hashlib.algorithms_available:
        return None
    hasher = hashlib.new(normalized)
    hasher.update(path.read_bytes())
    digest = base64.urlsafe_b64encode(hasher.digest()).decode("ascii").rstrip("=")
    return f"{algorithm}={digest}"


def _licenses_from_metadata(data: Any) -> list[dict[str, dict[str, str]]]:
    licenses: list[dict[str, dict[str, str]]] = []
    if license_text := data.get("License"):
        licenses.append(_license_entry(license_text))
    for classifier in data.get_all("Classifier", []) or []:
        if classifier.startswith("License ::"):
            licenses.append(_license_entry(classifier.rsplit("::", 1)[-1].strip()))
    unique: dict[str, dict[str, dict[str, str]]] = {}
    for item in licenses:
        key = json.dumps(item, sort_keys=True)
        unique[key] = item
    return list(unique.values())


def _license_entry(value: str) -> dict[str, dict[str, str]]:
    value = value.strip()
    if value and " " not in value and len(value) <= 64:
        return {"license": {"id": value}}
    return {"license": {"name": value}}


def _dedupe_components(components: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str | None], dict[str, Any]] = {}
    for component in components:
        key = (
            str(component.get("purl") or component.get("name")),
            component.get("version"),
        )
        deduped.setdefault(key, component)
    return [deduped[key] for key in sorted(deduped)]


def _is_requirements_file(path: Path) -> bool:
    return path.name.startswith("requirements") and path.suffix == ".txt"


def _looks_like_archive(path: Path) -> bool:
    suffixes = path.suffixes
    if not suffixes:
        return False
    if path.suffix == ".whl":
        return True
    if path.suffix in {".zip", ".tar", ".tgz"}:
        return True
    return len(suffixes) >= 2 and "".join(suffixes[-2:]) in {
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
    }


def _is_excluded(path: Path, excluded: tuple[str, ...]) -> bool:
    path_text = str(path)
    return any(item and item in path_text for item in excluded)
