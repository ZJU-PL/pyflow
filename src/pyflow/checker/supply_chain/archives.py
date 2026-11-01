"""Bounded, traversal-safe inspection of Python package archives."""

from __future__ import annotations

import csv
import lzma
import stat
import tarfile
import unicodedata
import zipfile
import zlib
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any, IO, Iterable

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from .models import ScanLimits, SupplyChainFinding


def extract_archive(
    path: Path,
    destination: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> bool:
    """Safely extract inspectable regular files under configured budgets."""

    try:
        archive_size = path.stat().st_size
        if archive_size > limits.max_archive_size:
            findings.append(
                SupplyChainFinding(
                    kind="archive-file-size-limit",
                    message="Archive exceeds the configured input-size limit",
                    location=str(path),
                    severity="HIGH",
                    details={"size": archive_size, "limit": limits.max_archive_size},
                )
            )
            return False
        if zipfile.is_zipfile(path):
            return _extract_zip(path, destination, findings, limits)
        if tarfile.is_tarfile(path):
            return _extract_tar(path, destination, findings, limits)
    except OSError as exc:
        findings.append(
            SupplyChainFinding(
                kind="archive-read-error",
                message="Could not identify package archive",
                location=str(path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )
        return False
    findings.append(
        SupplyChainFinding(
            kind="archive-unrecognized-format",
            message=(
                "File extension indicates an archive but content is not a " "supported archive"
            ),
            location=str(path),
            severity="HIGH",
        )
    )
    return False


def _extract_zip(
    path: Path,
    destination: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_archive_members:
                findings.append(
                    SupplyChainFinding(
                        kind="archive-member-limit",
                        message="Archive exceeds the configured member-count limit",
                        location=str(path),
                        severity="HIGH",
                        details={
                            "members": len(infos),
                            "limit": limits.max_archive_members,
                        },
                    )
                )
                return False

            total_size = 0
            seen_entries: set[str] = set()
            seen_casefolded: dict[str, str] = {}
            for info in infos:
                normalized = _normalized_archive_entry(info.filename)
                issue = _archive_entry_issue(path, info.filename, info.file_size, limits)
                if issue is not None:
                    findings.append(issue)
                    continue
                assert normalized is not None
                if _audit_archive_collision(
                    path, normalized, seen_entries, seen_casefolded, findings
                ):
                    continue
                total_size += info.file_size
                if total_size > limits.max_archive_uncompressed_size:
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-expanded-size-limit",
                            message="Archive exceeds the configured expanded-size limit",
                            location=str(path),
                            severity="HIGH",
                            details={
                                "size": total_size,
                                "limit": limits.max_archive_uncompressed_size,
                            },
                        )
                    )
                    return False
                ratio = info.file_size / max(info.compress_size, 1)
                if info.file_size and ratio > limits.max_compression_ratio:
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-suspicious-compression-ratio",
                            message="Archive member has a suspicious compression ratio",
                            location=str(path),
                            severity="HIGH",
                            details={
                                "entry": info.filename,
                                "ratio": round(ratio, 2),
                                "limit": limits.max_compression_ratio,
                            },
                        )
                    )
                    continue
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if unix_mode and stat.S_ISLNK(unix_mode):
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-link-entry",
                            message="Archive member is a symbolic link",
                            location=str(path),
                            severity="HIGH",
                            details={"entry": info.filename},
                        )
                    )
                    continue
                file_type = stat.S_IFMT(unix_mode)
                if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-special-file",
                            message="Archive contains a device, FIFO, or other special entry",
                            location=str(path),
                            severity="HIGH",
                            details={"entry": info.filename, "mode": oct(unix_mode)},
                        )
                    )
                    continue
                if info.flag_bits & 0x1:
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-encrypted-entry",
                            message="Encrypted archive member cannot be inspected safely",
                            location=str(path),
                            severity="HIGH",
                            details={"entry": info.filename},
                        )
                    )
                    continue

                target = _prepare_target(
                    destination,
                    normalized,
                    info.is_dir(),
                    path,
                    findings,
                )
                if target is None:
                    continue
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("wb") as output:
                    _copy_limited(source, output, info.file_size)
        return True
    except (
        OSError,
        RuntimeError,
        EOFError,
        zipfile.BadZipFile,
        zlib.error,
        lzma.LZMAError,
    ) as exc:
        findings.append(
            SupplyChainFinding(
                kind="archive-read-error",
                message="Could not read zip archive",
                location=str(path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )
        return False


def _extract_tar(
    path: Path,
    destination: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> bool:
    try:
        compressed_size = max(path.stat().st_size, 1)
        with tarfile.open(path, mode="r:*") as archive:
            total_size = 0
            seen_entries: set[str] = set()
            seen_casefolded: dict[str, str] = {}
            for member_count, member in enumerate(archive, start=1):
                if member_count > limits.max_archive_members:
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-member-limit",
                            message="Archive exceeds the configured member-count limit",
                            location=str(path),
                            severity="HIGH",
                            details={
                                "members": member_count,
                                "limit": limits.max_archive_members,
                            },
                        )
                    )
                    return False
                normalized = _normalized_archive_entry(member.name)
                issue = _archive_entry_issue(path, member.name, member.size, limits)
                if issue is not None:
                    findings.append(issue)
                    continue
                assert normalized is not None
                if _audit_archive_collision(
                    path, normalized, seen_entries, seen_casefolded, findings
                ):
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
                if not (member.isfile() or member.isdir()):
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-special-file",
                            message="Archive contains a device, FIFO, or other special entry",
                            location=str(path),
                            severity="HIGH",
                            details={"entry": member.name, "type": repr(member.type)},
                        )
                    )
                    continue
                total_size += member.size
                if total_size > limits.max_archive_uncompressed_size:
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-expanded-size-limit",
                            message="Archive exceeds the configured expanded-size limit",
                            location=str(path),
                            severity="HIGH",
                            details={
                                "size": total_size,
                                "limit": limits.max_archive_uncompressed_size,
                            },
                        )
                    )
                    return False
                ratio = total_size / compressed_size
                if total_size and ratio > limits.max_compression_ratio:
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-suspicious-compression-ratio",
                            message="Tar archive has a suspicious compression ratio",
                            location=str(path),
                            severity="HIGH",
                            details={
                                "ratio": round(ratio, 2),
                                "limit": limits.max_compression_ratio,
                            },
                        )
                    )
                    return False

                target = _prepare_target(
                    destination,
                    normalized,
                    member.isdir(),
                    path,
                    findings,
                )
                if target is None:
                    continue
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                source = archive.extractfile(member)
                if source is None:
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-read-error",
                            message="Could not read tar archive member",
                            location=str(path),
                            severity="HIGH",
                            details={"entry": member.name},
                        )
                    )
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as output:
                    _copy_limited(source, output, member.size)
        return True
    except (OSError, EOFError, tarfile.TarError) as exc:
        findings.append(
            SupplyChainFinding(
                kind="archive-read-error",
                message="Could not read tar archive",
                location=str(path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )
        return False


def _prepare_target(
    destination: Path,
    normalized: str,
    is_dir: bool,
    archive_path: Path,
    findings: list[SupplyChainFinding],
) -> Path | None:
    """Reject file/directory conflicts before writing an archive member."""

    target = destination.joinpath(*PurePosixPath(normalized).parts)
    try:
        relative = target.relative_to(destination)
    except ValueError:
        findings.append(
            SupplyChainFinding(
                kind="archive-invalid-path",
                message="Archive entry escapes the extraction directory",
                location=str(archive_path),
                severity="HIGH",
                details={"entry": normalized},
            )
        )
        return None
    current = destination
    for part in relative.parts:
        current = current / part
        if current == target:
            break
        if current.exists() and not current.is_dir():
            findings.append(
                SupplyChainFinding(
                    kind="archive-path-conflict",
                    message="Archive entry is nested under an existing regular file",
                    location=str(archive_path),
                    severity="HIGH",
                    details={"entry": normalized, "conflicts_with": current.name},
                )
            )
            return None
    if target.exists() and target.is_dir() != is_dir:
        findings.append(
            SupplyChainFinding(
                kind="archive-path-conflict",
                message="Archive entry changes an existing path between file and directory",
                location=str(archive_path),
                severity="HIGH",
                details={"entry": normalized},
            )
        )
        return None
    return target


def _archive_entry_issue(
    archive_path: Path,
    entry: str,
    size: int,
    limits: ScanLimits,
) -> SupplyChainFinding | None:
    normalized = _normalized_archive_entry(entry)
    if normalized is None:
        return SupplyChainFinding(
            kind="archive-invalid-path",
            message="Archive contains an invalid or non-portable path entry",
            location=str(archive_path),
            severity="HIGH",
            details={"entry": entry},
        )
    entry_path = PurePosixPath(normalized)
    if entry.startswith(("/", "\\")) or entry_path.is_absolute() or _is_windows_absolute(entry):
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
    if _is_nonportable_windows_path(entry_path):
        return SupplyChainFinding(
            kind="archive-nonportable-path",
            message="Archive path is unsafe or ambiguous on Windows filesystems",
            location=str(archive_path),
            severity="HIGH",
            details={"entry": entry},
        )
    if size < 0:
        return SupplyChainFinding(
            kind="archive-invalid-size",
            message="Archive contains a member with an invalid size",
            location=str(archive_path),
            severity="HIGH",
            details={"entry": entry, "size": size},
        )
    if size > limits.max_archive_member_size:
        return SupplyChainFinding(
            kind="archive-member-too-large",
            message="Archive contains a member exceeding the size limit",
            location=str(archive_path),
            severity="MEDIUM",
            details={
                "entry": entry,
                "size": size,
                "limit": limits.max_archive_member_size,
            },
        )
    return None


def _is_windows_absolute(entry: str) -> bool:
    return len(entry) >= 2 and entry[0].isalpha() and entry[1] == ":"


def _is_nonportable_windows_path(path: PurePosixPath) -> bool:
    reserved = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
    for part in path.parts:
        if part.rstrip(" .") != part or ":" in part:
            return True
        if part.split(".", 1)[0].upper() in reserved:
            return True
    return False


def _normalized_archive_entry(entry: str) -> str | None:
    if not entry or "\x00" in entry:
        return None
    normalized = entry.replace("\\", "/")
    if any(part in {"", "."} for part in PurePosixPath(normalized).parts[:-1]):
        normalized = str(PurePosixPath(normalized))
    return normalized


def _audit_archive_collision(
    archive_path: Path,
    entry: str,
    seen_entries: set[str],
    seen_casefolded: dict[str, str],
    findings: list[SupplyChainFinding],
) -> bool:
    if entry in seen_entries:
        findings.append(
            SupplyChainFinding(
                kind="archive-duplicate-entry",
                message="Archive contains duplicate entries for the same path",
                location=str(archive_path),
                severity="HIGH",
                details={"entry": entry},
            )
        )
        return True
    seen_entries.add(entry)
    folded = unicodedata.normalize("NFC", entry).casefold()
    previous = seen_casefolded.get(folded)
    if previous is not None and previous != entry:
        findings.append(
            SupplyChainFinding(
                kind="archive-case-collision",
                message="Archive paths collide on case-insensitive filesystems",
                location=str(archive_path),
                severity="HIGH",
                details={"entry": entry, "collides_with": previous},
            )
        )
        return True
    seen_casefolded[folded] = entry
    return False


def _copy_limited(source: IO[bytes], output: IO[bytes], expected_size: int) -> None:
    remaining = expected_size
    while remaining:
        chunk = source.read(min(1024 * 1024, remaining))
        if not chunk:
            raise OSError("archive member ended before its declared size")
        output.write(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise OSError("archive member exceeded its declared size")


def audit_archive_payload(
    archive_path: Path,
    destination: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> None:
    """Inspect extracted wheel payload for interpreter hooks and RECORD drift."""

    try:
        entries = list(destination.rglob("*"))
    except OSError as exc:
        findings.append(
            SupplyChainFinding(
                kind="archive-read-error",
                message="Could not inspect extracted archive payload",
                location=str(archive_path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )
        return
    if len(entries) > limits.max_scan_entries:
        findings.append(
            SupplyChainFinding(
                kind="archive-member-limit",
                message="Extracted archive payload exceeds the inspection limit",
                location=str(archive_path),
                severity="HIGH",
                details={"limit": limits.max_scan_entries},
            )
        )
        entries = entries[: limits.max_scan_entries]

    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            continue
        entry_name = entry.name.lower()
        if entry_name.endswith(".pth"):
            findings.append(
                SupplyChainFinding(
                    kind="archive-pth-file",
                    message="Archive installs a .pth file that runs code at interpreter startup",
                    location=_member_location(archive_path, destination, entry),
                    severity="HIGH",
                )
            )
        elif entry_name in {"sitecustomize.py", "usercustomize.py"}:
            findings.append(
                SupplyChainFinding(
                    kind="archive-startup-hook",
                    message=(
                        "Archive installs a module that runs automatically at Python "
                        "interpreter startup"
                    ),
                    location=_member_location(archive_path, destination, entry),
                    severity="HIGH",
                )
            )

    try:
        dist_infos = sorted(
            child
            for child in destination.iterdir()
            if child.is_dir() and child.name.endswith(".dist-info")
        )
    except OSError as exc:
        findings.append(
            SupplyChainFinding(
                kind="archive-read-error",
                message="Could not inspect archive distribution metadata",
                location=str(archive_path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )
        return
    if len(dist_infos) > 1:
        findings.append(
            SupplyChainFinding(
                kind="archive-multiple-dist-info",
                message="Wheel contains more than one distribution metadata directory",
                location=str(archive_path),
                severity="HIGH",
                details={"dist_info": [item.name for item in dist_infos]},
            )
        )
    if dist_infos and (destination / "setup.py").is_file():
        findings.append(
            SupplyChainFinding(
                kind="archive-unexpected-setup-script",
                message="Wheel payload contains an installation script",
                location=_member_location(archive_path, destination, destination / "setup.py"),
                severity="HIGH",
            )
        )
    for dist_info in dist_infos:
        _audit_wheel_metadata(archive_path, destination, dist_info, entries, findings)


def _audit_wheel_metadata(
    archive_path: Path,
    destination: Path,
    dist_info: Path,
    entries: list[Path],
    findings: list[SupplyChainFinding],
) -> None:
    metadata = dist_info / "METADATA"
    if metadata.is_file() and not metadata.is_symlink():
        try:
            data = Parser().parsestr(metadata.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            data = None
        if data is not None:
            name = str(data.get("Name", "")).strip()
            version = str(data.get("Version", "")).strip()
            stem = dist_info.name[: -len(".dist-info")]
            directory_name, separator, directory_version = stem.rpartition("-")
            if separator and name:
                if canonicalize_name(directory_name) != canonicalize_name(name):
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-dist-info-mismatch",
                            message="Distribution directory and METADATA disagree on the name",
                            location=_member_location(archive_path, destination, metadata),
                            severity="HIGH",
                            details={"directory": directory_name, "metadata": name},
                        )
                    )
                if version and not _same_version(directory_version, version):
                    findings.append(
                        SupplyChainFinding(
                            kind="archive-dist-info-mismatch",
                            message="Distribution directory and METADATA disagree on the version",
                            location=_member_location(archive_path, destination, metadata),
                            severity="HIGH",
                            details={"directory": directory_version, "metadata": version},
                        )
                    )

    record = dist_info / "RECORD"
    if not record.is_file() or record.is_symlink():
        return
    try:
        rows = list(csv.reader(record.read_text(encoding="utf-8", errors="replace").splitlines()))
    except (OSError, csv.Error):
        return
    listed: set[str] = set()
    for parts in rows:
        if len(parts) != 3 or not parts[0]:
            continue
        relative = PurePosixPath(parts[0].replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            continue
        normalized = relative.as_posix()
        listed.add(normalized)
        target = destination.joinpath(*relative.parts)
        if not target.is_file() and not target.is_symlink():
            findings.append(
                SupplyChainFinding(
                    kind="archive-record-missing-file",
                    message="Wheel RECORD lists a file that is not present in the payload",
                    location=str(archive_path),
                    severity="HIGH",
                    details={"record": normalized},
                )
            )

    for entry in entries:
        if entry.is_dir() or entry.is_symlink():
            continue
        try:
            relative = entry.relative_to(destination)
        except ValueError:
            continue
        normalized = relative.as_posix()
        if normalized in listed:
            continue
        if normalized.endswith((".pyc", ".pyo")) or "__pycache__" in relative.parts:
            continue
        if relative.parts and relative.parts[0] == dist_info.name:
            continue
        findings.append(
            SupplyChainFinding(
                kind="archive-record-unlisted-file",
                message="Wheel payload contains a file not listed in RECORD",
                location=_member_location(archive_path, destination, entry),
                severity="HIGH",
                details={"record": normalized},
            )
        )


def _member_location(archive_path: Path, destination: Path, member: Path) -> str:
    try:
        relative = member.relative_to(destination).as_posix()
    except ValueError:
        return str(member)
    return f"{archive_path}!/{relative}"


def _same_version(left: str, right: str) -> bool:
    if left == right:
        return True
    try:
        return Version(left) == Version(right)
    except InvalidVersion:
        return False


def _is_metadata_component(component: dict[str, Any]) -> bool:
    return any(
        isinstance(prop, dict)
        and prop.get("name") == "pyflow:metadata-source"
        and str(prop.get("value", "")).lower() == "true"
        for prop in component.get("properties", ())
    )


def audit_archive_identity(
    path: Path,
    components: Iterable[dict[str, Any]],
    findings: list[SupplyChainFinding],
) -> None:
    """Compare wheel/sdist filename identity with discovered package metadata."""

    try:
        if path.suffix == ".whl":
            parsed_name, parsed_version, _build, _tags = parse_wheel_filename(path.name)
        else:
            parsed_name, parsed_version = parse_sdist_filename(path.name)
    except (InvalidWheelFilename, InvalidSdistFilename):
        if path.suffix != ".whl":
            return
        findings.append(
            SupplyChainFinding(
                kind="invalid-package-filename",
                message="Package archive filename does not follow Python packaging conventions",
                location=str(path),
                severity="MEDIUM",
            )
        )
        return

    expected_name = canonicalize_name(parsed_name)
    expected_version = str(parsed_version)
    candidates = [item for item in components if _is_metadata_component(item)]
    if not candidates:
        candidates = [item for item in components if item.get("type") == "application"]
    if not candidates:
        findings.append(
            SupplyChainFinding(
                kind="archive-missing-package-metadata",
                message="Package archive contains no inspectable distribution metadata",
                location=str(path),
                severity="HIGH",
                details={"filename": path.name},
            )
        )
        return
    matching = [
        component
        for component in candidates
        if canonicalize_name(str(component.get("name", ""))) == expected_name
    ]
    for component in matching:
        # The archive's own distribution is the subject package, not a
        # dependency.  This also keeps requirements exports from installing
        # the package into itself.
        component["type"] = "application"
    if not matching and candidates:
        findings.append(
            SupplyChainFinding(
                kind="archive-metadata-name-mismatch",
                message=("Archive filename and package metadata disagree on the project name"),
                location=str(path),
                severity="HIGH",
                details={
                    "filename": expected_name,
                    "metadata": sorted(
                        {
                            canonicalize_name(str(item.get("name", "")))
                            for item in candidates
                            if item.get("name")
                        }
                    ),
                },
            )
        )
        return
    for component in matching:
        actual_version = str(component.get("version", ""))
        if actual_version and not _same_version(actual_version, expected_version):
            findings.append(
                SupplyChainFinding(
                    kind="archive-metadata-version-mismatch",
                    message=("Archive filename and package metadata disagree on the version"),
                    location=str(path),
                    severity="HIGH",
                    details={
                        "filename": expected_version,
                        "metadata": actual_version,
                    },
                )
            )


def looks_like_archive(path: Path) -> bool:
    suffixes = path.suffixes
    if not suffixes:
        return False
    if path.suffix == ".whl":
        return True
    if path.suffix.lower() in {".zip", ".tar", ".tgz", ".tbz2", ".txz"}:
        return True
    return len(suffixes) >= 2 and "".join(suffixes[-2:]).lower() in {
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
    }
