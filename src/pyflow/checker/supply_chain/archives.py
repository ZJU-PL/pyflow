"""Bounded, traversal-safe inspection of Python package archives."""

from __future__ import annotations

import stat
import tarfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, IO, Iterable

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)

from .models import ScanLimits, SupplyChainFinding


def extract_archive(
    path: Path,
    destination: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
) -> bool:
    """Safely extract inspectable regular files under configured budgets."""

    try:
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
                issue = _archive_entry_issue(
                    path, info.filename, info.file_size, limits
                )
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

                target = destination.joinpath(*PurePosixPath(normalized).parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("wb") as output:
                    _copy_limited(source, output, info.file_size)
        return True
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile) as exc:
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
        with tarfile.open(path, mode="r:*") as archive:
            members = archive.getmembers()
            if len(members) > limits.max_archive_members:
                findings.append(
                    SupplyChainFinding(
                        kind="archive-member-limit",
                        message="Archive exceeds the configured member-count limit",
                        location=str(path),
                        severity="HIGH",
                        details={
                            "members": len(members),
                            "limit": limits.max_archive_members,
                        },
                    )
                )
                return False

            total_size = 0
            seen_entries: set[str] = set()
            seen_casefolded: dict[str, str] = {}
            for member in members:
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

                target = destination.joinpath(*PurePosixPath(normalized).parts)
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
    if (
        entry.startswith(("/", "\\"))
        or entry_path.is_absolute()
        or _is_windows_absolute(entry)
    ):
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
    candidates = list(components)
    matching = [
        component
        for component in candidates
        if canonicalize_name(str(component.get("name", ""))) == expected_name
    ]
    if not matching and candidates:
        findings.append(
            SupplyChainFinding(
                kind="archive-metadata-name-mismatch",
                message=(
                    "Archive filename and package metadata disagree on the project name"
                ),
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
        if actual_version and actual_version != expected_version:
            findings.append(
                SupplyChainFinding(
                    kind="archive-metadata-version-mismatch",
                    message=(
                        "Archive filename and package metadata disagree on the version"
                    ),
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
