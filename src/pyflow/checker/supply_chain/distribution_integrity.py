"""Installed-distribution integrity checks for PEP 376 RECORD metadata."""

from __future__ import annotations

import base64
import csv
import hashlib
from pathlib import Path
from typing import Iterator

from .input_safety import is_relative_to, read_error, read_text
from .models import ScanLimits, SupplyChainFinding

_RECORD_HASH_ALGORITHMS = frozenset(
    {
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
    }
)


def audit_distribution_record(
    dist_info: Path,
    limits: ScanLimits,
) -> Iterator[SupplyChainFinding]:
    """Verify a distribution RECORD without reading outside the scan root."""

    record = dist_info / "RECORD"
    if not record.exists():
        yield SupplyChainFinding(
            kind="missing-record",
            message="Distribution metadata is missing RECORD",
            location=str(dist_info),
            severity="HIGH",
        )
        return

    root = dist_info.parent.resolve(strict=False)
    listed: set[Path] = set()
    seen_records: set[str] = set()
    read_findings: list[SupplyChainFinding] = []
    text = read_text(record, read_findings, limits, "distribution RECORD")
    yield from read_findings
    if text is None:
        return
    try:
        rows = list(csv.reader(text.splitlines()))
    except csv.Error as exc:
        yield SupplyChainFinding(
            kind="invalid-record",
            message="Distribution RECORD is not valid CSV",
            location=str(record),
            severity="HIGH",
            details={"error": str(exc)},
        )
        return

    for row_no, parts in enumerate(rows, start=1):
        if len(parts) != 3 or not parts[0]:
            yield SupplyChainFinding(
                kind="invalid-record-entry",
                message="Distribution RECORD row must contain path, hash, and size",
                location=str(record),
                severity="HIGH",
                details={"row": row_no},
            )
            continue
        rel_path, expected_hash, expected_size = parts
        if rel_path in seen_records:
            yield SupplyChainFinding(
                kind="duplicate-record-entry",
                message="Distribution RECORD lists the same path more than once",
                location=str(record),
                severity="HIGH",
                details={"row": row_no, "record": rel_path},
            )
            continue
        seen_records.add(rel_path)

        raw_target = Path(rel_path)
        if not raw_target.is_absolute():
            raw_target = root / raw_target
        target = raw_target.resolve(strict=False)
        if not is_relative_to(target, root):
            yield SupplyChainFinding(
                kind="record-external-path",
                message="Distribution RECORD references a file outside the scan root",
                location=str(record),
                severity="MEDIUM",
                details={"row": row_no, "record": rel_path},
            )
            continue
        listed.add(target)
        if _contains_symlink(raw_target, root):
            yield SupplyChainFinding(
                kind="record-symlink",
                message="Distribution RECORD path resolves through a symbolic link",
                location=str(raw_target),
                severity="HIGH",
                details={"record": rel_path},
            )
            continue
        if not target.is_file():
            yield SupplyChainFinding(
                kind="record-missing-file",
                message="RECORD lists a file that is missing",
                location=str(record),
                severity="HIGH",
                details={"record": rel_path},
            )
            continue
        if expected_hash:
            yield from _audit_record_hash(target, record, expected_hash, row_no)
        if expected_size:
            yield from _audit_record_size(target, record, expected_size, row_no)

    # A shared site-packages directory can contain many distributions. Only the
    # current distribution's own metadata directory has unambiguous ownership.
    try:
        metadata_files = list(dist_info.rglob("*"))
    except OSError as exc:
        yield read_error(dist_info, exc)
        return
    for file_path in metadata_files:
        if (
            file_path.is_file()
            and not file_path.is_symlink()
            and file_path.resolve(strict=False) not in listed
        ):
            yield SupplyChainFinding(
                kind="record-unlisted-file",
                message="Distribution metadata contains a file not listed in RECORD",
                location=str(file_path),
                severity="LOW",
            )

    # top_level.txt is the packaging ecosystem's explicit ownership hint.  Use
    # it to inspect package/module roots without claiming unrelated namespace
    # packages in a shared site-packages directory.
    top_level = dist_info / "top_level.txt"
    if top_level.is_file() and not top_level.is_symlink():
        top_level_findings: list[SupplyChainFinding] = []
        names = read_text(top_level, top_level_findings, limits, "top-level metadata")
        yield from top_level_findings
        if names is not None:
            inspected = 0
            for name in names.splitlines():
                name = name.strip()
                if not name.isidentifier():
                    continue
                candidates = (root / name, root / f"{name}.py")
                for owned_root in candidates:
                    if not owned_root.exists() or owned_root.is_symlink():
                        continue
                    paths = (
                        [owned_root] if owned_root.is_file() else owned_root.rglob("*")
                    )
                    try:
                        for file_path in paths:
                            inspected += 1
                            if inspected > limits.max_scan_entries:
                                yield SupplyChainFinding(
                                    kind="record-owned-file-limit",
                                    message="Installed-file integrity audit exceeded its entry limit",
                                    location=str(owned_root),
                                    severity="HIGH",
                                    details={"limit": limits.max_scan_entries},
                                )
                                return
                            if (
                                file_path.is_file()
                                and not file_path.is_symlink()
                                and file_path.resolve(strict=False) not in listed
                            ):
                                yield SupplyChainFinding(
                                    kind="record-unlisted-owned-file",
                                    message="Installed package contains a file not listed in RECORD",
                                    location=str(file_path),
                                    severity="HIGH",
                                    details={"top_level": name},
                                )
                    except OSError as exc:
                        yield read_error(owned_root, exc)


def _audit_record_hash(
    target: Path,
    record: Path,
    expected_hash: str,
    row_no: int,
) -> Iterator[SupplyChainFinding]:
    if "=" not in expected_hash:
        yield SupplyChainFinding(
            kind="record-malformed-hash",
            message="RECORD hash does not declare an algorithm",
            location=str(record),
            severity="HIGH",
            details={"row": row_no, "record_hash": expected_hash},
        )
        return
    algorithm = expected_hash.split("=", 1)[0].lower().replace("-", "")
    if algorithm not in _RECORD_HASH_ALGORITHMS:
        yield SupplyChainFinding(
            kind="record-unsupported-hash",
            message="RECORD uses an unsupported hash algorithm",
            location=str(record),
            severity="HIGH",
            details={"row": row_no, "algorithm": algorithm},
        )
        return
    if algorithm in {"md5", "sha1"}:
        yield SupplyChainFinding(
            kind="record-weak-hash",
            message="RECORD uses a collision-prone hash algorithm",
            location=str(record),
            severity="HIGH",
            details={"row": row_no, "algorithm": algorithm},
        )
    try:
        actual = _record_hash(target, expected_hash)
    except OSError as exc:
        yield read_error(target, exc)
        return
    if actual is not None and actual != expected_hash:
        yield SupplyChainFinding(
            kind="record-invalid-hash",
            message="RECORD file hash does not match local content",
            location=str(target),
            severity="HIGH",
            details={"record_hash": expected_hash, "actual_hash": actual},
        )


def _audit_record_size(
    target: Path,
    record: Path,
    expected_size: str,
    row_no: int,
) -> Iterator[SupplyChainFinding]:
    try:
        declared_size = int(expected_size)
    except ValueError:
        yield SupplyChainFinding(
            kind="record-invalid-size",
            message="RECORD contains a non-integer file size",
            location=str(record),
            severity="HIGH",
            details={"row": row_no, "size": expected_size},
        )
        return
    if declared_size < 0:
        yield SupplyChainFinding(
            kind="record-invalid-size",
            message="RECORD contains a negative file size",
            location=str(record),
            severity="HIGH",
            details={"row": row_no, "size": expected_size},
        )
        return
    try:
        actual_size = target.stat().st_size
    except OSError as exc:
        yield read_error(target, exc)
        return
    if actual_size != declared_size:
        yield SupplyChainFinding(
            kind="record-size-mismatch",
            message="RECORD file size does not match local content",
            location=str(target),
            severity="HIGH",
            details={
                "record_size": declared_size,
                "actual_size": actual_size,
            },
        )


def _record_hash(path: Path, expected: str) -> str | None:
    if "=" not in expected:
        return None
    algorithm, _digest = expected.split("=", 1)
    normalized = algorithm.lower().replace("-", "")
    if normalized not in hashlib.algorithms_available:
        return None
    hasher = hashlib.new(normalized)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    digest = base64.urlsafe_b64encode(hasher.digest()).decode("ascii").rstrip("=")
    return f"{algorithm}={digest}"


def _contains_symlink(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False
