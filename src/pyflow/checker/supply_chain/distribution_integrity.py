"""Installed-distribution integrity checks for PEP 376 RECORD metadata."""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Iterator

from .input_safety import is_relative_to, read_error, read_text, redacted_url
from .inventory import add_property
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
    component: dict | None = None,
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
    record_roots: set[str] = set()
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
        if _is_compiled_artifact(Path(rel_path.replace("\\", "/"))):
            # Bytecode caches are optional and are routinely removed, regenerated,
            # or never created by installers.  They are not distribution integrity
            # evidence.
            continue
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

        raw_target = Path(rel_path.replace("\\", "/"))
        if not raw_target.is_absolute():
            raw_target = root / raw_target
        target = raw_target.resolve(strict=False)
        if not is_relative_to(target, root):
            if _is_installed_data_target(target, root):
                # Console scripts and data files are installed outside
                # site-packages by design.
                continue
            yield SupplyChainFinding(
                kind="record-external-path",
                message="Distribution RECORD references a file outside the scan root",
                location=str(record),
                severity="MEDIUM",
                details={"row": row_no, "record": rel_path},
            )
            continue
        listed.add(target)
        owned_name = _record_owned_name(raw_target, root, dist_info)
        if owned_name:
            record_roots.add(owned_name)
            if component is not None:
                add_property(component, "pyflow:owned-root", owned_name)
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
            and not _is_compiled_artifact(file_path)
            and file_path.resolve(strict=False) not in listed
        ):
            yield SupplyChainFinding(
                kind="record-unlisted-file",
                message="Distribution metadata contains a file not listed in RECORD",
                location=str(file_path),
                severity="LOW",
            )

    # top_level.txt is the packaging ecosystem's explicit ownership hint.  When
    # it is absent, derive owned roots from the distribution's own RECORD so a
    # shared site-packages directory still cannot hide injected modules.
    owned_names: list[str] = []
    top_level = dist_info / "top_level.txt"
    if top_level.is_file() and not top_level.is_symlink():
        top_level_findings: list[SupplyChainFinding] = []
        names = read_text(top_level, top_level_findings, limits, "top-level metadata")
        yield from top_level_findings
        if names is not None:
            for name in names.splitlines():
                name = name.strip()
                if name.isidentifier():
                    owned_names.append(name)
    owned_names.extend(sorted(record_roots))
    if component is not None:
        for name in dict.fromkeys(owned_names):
            add_property(component, "pyflow:owned-root", name)

    inspected = 0
    reported: set[Path] = set()
    for name in dict.fromkeys(owned_names):
        candidates = (root / name, root / f"{name}.py")
        for owned_root in candidates:
            if not owned_root.exists() or owned_root.is_symlink():
                continue
            paths = [owned_root] if owned_root.is_file() else owned_root.rglob("*")
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
                        and not _is_compiled_artifact(file_path)
                        and file_path.resolve(strict=False) not in listed
                        and file_path not in reported
                    ):
                        reported.add(file_path)
                        yield SupplyChainFinding(
                            kind="record-unlisted-owned-file",
                            message="Installed package contains a file not listed in RECORD",
                            location=str(file_path),
                            severity="HIGH",
                            details={"top_level": name},
                        )
            except OSError as exc:
                yield read_error(owned_root, exc)
    yield from _audit_direct_url(dist_info, limits, component)


def _audit_direct_url(
    dist_info: Path,
    limits: ScanLimits,
    component: dict | None = None,
) -> Iterator[SupplyChainFinding]:
    path = dist_info / "direct_url.json"
    if not path.is_file() or path.is_symlink():
        return
    try:
        if path.stat().st_size > limits.max_manifest_size:
            return
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        yield SupplyChainFinding(
            kind="invalid-direct-url-metadata",
            message="Installed distribution has invalid direct_url.json",
            location=str(path),
            severity="MEDIUM",
            details={"error": str(exc)},
        )
        return
    if not isinstance(data, dict):
        return
    url = str(data.get("url", ""))
    details = {"url": redacted_url(url)} if url else {}
    if url and component is not None:
        # Requirements/SBOM exports must not redirect an editable or VCS install
        # to a same-named package on PyPI.
        add_property(component, "pyflow:source-url", redacted_url(url))
    dir_info = data.get("dir_info") or {}
    if isinstance(dir_info, dict) and dir_info.get("editable"):
        yield SupplyChainFinding(
            kind="editable-install",
            message="Installed distribution is an editable install of mutable source",
            location=str(path),
            severity="MEDIUM",
            details=details,
        )
    if url.startswith("file:"):
        yield SupplyChainFinding(
            kind="installed-local-path",
            message="Installed distribution comes from a local path",
            location=str(path),
            severity="MEDIUM",
            details=details,
        )
    vcs_info = data.get("vcs_info") or {}
    if isinstance(vcs_info, dict) and vcs_info:
        commit = str(vcs_info.get("commit_id", ""))
        url_has_commit = bool(re.search(r"@[0-9a-fA-F]{40,64}(?:$|[#?])", url))
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit) and not url_has_commit:
            yield SupplyChainFinding(
                kind="installed-vcs-unpinned",
                message="Installed VCS distribution is not pinned to a full commit",
                location=str(path),
                severity="HIGH",
                details={**details, "commit": commit},
            )


def _is_compiled_artifact(path: Path) -> bool:
    return path.suffix.casefold() in {".pyc", ".pyo"} or "__pycache__" in path.parts


def _is_installed_data_target(path: Path, root: Path) -> bool:
    """Return whether *path* is a normal interpreter-prefix install location.

    Pip moves console scripts and ``data_files`` out of site-packages into the
    environment prefix (``bin``, ``Scripts``, ``share``, ...).  Those paths are
    expected and must not be reported as escaped RECORD entries.  Paths outside
    the prefix (for example ``/etc/passwd``) remain findings.
    """

    if root.name.lower() in {"site-packages", "dist-packages"}:
        try:
            prefix = root.parents[2]
        except IndexError:
            prefix = None
        if prefix is not None and is_relative_to(path, prefix):
            return True
    return path.parent.name in {"bin", "Scripts"}


def _record_owned_name(raw_target: Path, root: Path, dist_info: Path) -> str | None:
    try:
        relative = raw_target.relative_to(root)
    except ValueError:
        return None
    if not relative.parts:
        return None
    first = relative.parts[0]
    if first == dist_info.name or first in {"__pycache__", "bin", "Scripts"}:
        return None
    if first.endswith((".dist-info", ".egg-info", ".data")):
        return None
    if first.endswith((".pyc", ".pyo")):
        return None
    if first.endswith(".py"):
        return first[: -len(".py")]
    return first


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
