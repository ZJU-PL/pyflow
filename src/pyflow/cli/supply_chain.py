"""Supply-chain analysis CLI commands."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from pyflow.checker.supply_chain import (
    ScanLimits,
    SupplyChainScan,
    audit_license_policy,
    audit_vulnerabilities,
    build_cyclonedx_document,
    build_requirements_text,
    build_spdx_document,
    format_findings_text,
    scan_targets,
)


def add_supply_chain_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "supply-chain",
        help="Run local package and dependency supply-chain analyses",
        description="Analyze local archives, Python package metadata, and dependency manifests.",
    )
    child = parser.add_subparsers(dest="supply_chain_command", required=True)

    sbom = child.add_parser(
        "sbom",
        help="Generate a local SBOM (CycloneDX, SPDX, or requirements.txt)",
        description="Generate an SBOM from local package metadata and manifests. "
        "Supports CycloneDX 1.7 JSON, SPDX 2.3 JSON, and requirements.txt output.",
    )
    _add_common_args(sbom)
    sbom.add_argument(
        "--format",
        choices=["cyclonedx-json", "spdx-json", "requirements"],
        default="cyclonedx-json",
        help="SBOM output format",
    )

    audit = child.add_parser(
        "audit",
        help="Report local package/archive supply-chain findings",
        description=(
            "Audit dependency manifests, package sources, installation scripts, "
            "archives, distribution integrity, licenses, and local OSV records."
        ),
    )
    _add_common_args(audit)
    audit.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Audit output format",
    )
    audit.add_argument(
        "--license-policy",
        metavar="FILE",
        type=Path,
        help="JSON file with a list of allowed license IDs (default: built-in allowlist)",
    )
    audit.add_argument(
        "--skip-license-audit",
        action="store_true",
        help="Do not report missing or disallowed package licenses",
    )
    audit.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical", "none"],
        default="low",
        help="Lowest finding severity that produces a non-zero exit (default: low)",
    )
    audit.add_argument(
        "--osv-database",
        metavar="PATH",
        type=Path,
        action="append",
        default=[],
        help="Local OSV JSON/JSONL file or directory (repeatable; no network access)",
    )


def run_supply_chain(args: Any) -> int:
    targets = getattr(args, "targets", None) or ["."]
    exclude = _parse_exclude(getattr(args, "exclude", "") or "")
    scan = scan_targets(
        targets,
        recursive=getattr(args, "recursive", False),
        exclude=exclude,
        limits=_scan_limits(args),
    )

    out_file = None
    try:
        if getattr(args, "output", None):
            out_file = open(args.output, "w", encoding="utf-8")
        output = out_file or sys.stdout

        if args.supply_chain_command == "sbom":
            fmt = args.format
            if fmt == "requirements":
                output.write(build_requirements_text(scan))
            elif fmt == "spdx-json":
                json.dump(build_spdx_document(scan), output, indent=2)
                output.write("\n")
            else:
                json.dump(build_cyclonedx_document(scan), output, indent=2)
                output.write("\n")
            return 0

        if args.supply_chain_command == "audit":
            findings = list(scan.findings)

            license_policy_path = getattr(args, "license_policy", None)
            skip_license_audit = getattr(args, "skip_license_audit", False)
            if license_policy_path is not None and not skip_license_audit:
                allowed = _load_license_policy(license_policy_path)
                findings.extend(audit_license_policy(scan, allowed_licenses=allowed))
            elif scan.components and not skip_license_audit:
                findings.extend(audit_license_policy(scan))
            osv_databases = getattr(args, "osv_database", ()) or ()
            if osv_databases:
                findings.extend(audit_vulnerabilities(scan, osv_databases))

            findings.sort(
                key=lambda finding: (
                    finding.location,
                    -_severity_rank(finding.severity),
                    finding.kind,
                    finding.message,
                )
            )

            if args.format == "json":
                severity_counts = Counter(f.severity.upper() for f in findings)
                json.dump(
                    {
                        "summary": {
                            "components": len(scan.components),
                            "findings": len(findings),
                            "severity": {
                                severity: severity_counts.get(severity, 0)
                                for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                            },
                        },
                        "results": [f.to_dict() for f in findings],
                    },
                    output,
                    indent=2,
                )
                output.write("\n")
            else:
                # Rebuild a Scan-like container for formatting
                formatted = SupplyChainScan(
                    components=scan.components,
                    findings=tuple(findings),
                )
                output.write(format_findings_text(formatted))
                output.write("\n")
            fail_on = getattr(args, "fail_on", "low")
            return 1 if _should_fail(findings, fail_on) else 0
    finally:
        if out_file:
            out_file.close()

    print(f"Unknown supply-chain command: {args.supply_chain_command}", file=sys.stderr)
    return 1


def _add_common_args(parser: Any) -> None:
    parser.add_argument(
        "targets",
        nargs="*",
        help="Files, archives, or directories to analyze (default: current directory)",
    )
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Scan directories recursively",
    )
    parser.add_argument("--exclude", help="Comma-separated paths to exclude")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file (default: stdout)",
    )
    defaults = ScanLimits()
    parser.add_argument(
        "--max-archive-depth",
        type=_non_negative_int,
        default=defaults.max_archive_depth,
        help="Maximum nested archive depth (default: 3)",
    )
    parser.add_argument(
        "--max-archive-members",
        type=_non_negative_int,
        default=defaults.max_archive_members,
        help="Maximum entries per archive (default: 10000)",
    )
    parser.add_argument(
        "--max-archive-member-mb",
        type=_non_negative_float,
        default=defaults.max_archive_member_size / (1024 * 1024),
        help="Maximum expanded size of one archive member in MiB (default: 100)",
    )
    parser.add_argument(
        "--max-archive-expanded-mb",
        type=_non_negative_float,
        default=defaults.max_archive_uncompressed_size / (1024 * 1024),
        help="Maximum total expanded archive size in MiB (default: 1000)",
    )
    parser.add_argument(
        "--max-compression-ratio",
        type=_positive_float,
        default=defaults.max_compression_ratio,
        help="Maximum archive member compression ratio (default: 200)",
    )
    parser.add_argument(
        "--max-manifest-mb",
        type=_non_negative_float,
        default=defaults.max_manifest_size / (1024 * 1024),
        help="Maximum metadata or manifest size in MiB (default: 10)",
    )


def _parse_exclude(exclude: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in exclude.split(",") if item.strip())


def _load_license_policy(path: Path) -> list[str]:
    """Load an allowed-license list from a JSON file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"Could not read license policy file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"License policy file is not valid JSON: {exc}") from exc
    if isinstance(data, list):
        return [str(item) for item in data]
    if isinstance(data, dict) and isinstance(data.get("allowed_licenses"), list):
        return [str(item) for item in data["allowed_licenses"]]
    raise SystemExit(
        "License policy file must be a JSON array or an object with an "
        "allowed_licenses array"
    )


def _scan_limits(args: Any) -> ScanLimits:
    defaults = ScanLimits()
    mib = 1024 * 1024
    return ScanLimits(
        max_manifest_size=int(
            getattr(args, "max_manifest_mb", defaults.max_manifest_size / mib) * mib
        ),
        max_archive_members=getattr(
            args, "max_archive_members", defaults.max_archive_members
        ),
        max_archive_member_size=int(
            getattr(
                args,
                "max_archive_member_mb",
                defaults.max_archive_member_size / mib,
            )
            * mib
        ),
        max_archive_uncompressed_size=int(
            getattr(
                args,
                "max_archive_expanded_mb",
                defaults.max_archive_uncompressed_size / mib,
            )
            * mib
        ),
        max_compression_ratio=getattr(
            args, "max_compression_ratio", defaults.max_compression_ratio
        ),
        max_archive_depth=getattr(
            args, "max_archive_depth", defaults.max_archive_depth
        ),
    )


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _non_negative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _severity_rank(value: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value.upper(), 0)


def _should_fail(findings: list[Any], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = _severity_rank(fail_on)
    return any(_severity_rank(finding.severity) >= threshold for finding in findings)
