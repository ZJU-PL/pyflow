"""Supply-chain analysis CLI commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from pyflow.checker.supply_chain import (
    SupplyChainScan,
    audit_license_policy,
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
        "Supports CycloneDX JSON, SPDX 2.2 JSON, and requirements.txt output.",
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
        description="Audit local archives and distribution metadata for structural issues.",
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


def run_supply_chain(args: Any) -> int:
    targets = getattr(args, "targets", None) or ["."]
    exclude = _parse_exclude(getattr(args, "exclude", "") or "")
    scan = scan_targets(
        targets,
        recursive=getattr(args, "recursive", False),
        exclude=exclude,
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
            if license_policy_path is not None:
                allowed = _load_license_policy(license_policy_path)
                findings.extend(audit_license_policy(scan, allowed_licenses=allowed))
            elif scan.components:
                findings.extend(audit_license_policy(scan))

            if args.format == "json":
                json.dump(
                    {"results": [f.to_dict() for f in findings]},
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
            return 1 if findings else 0
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


def _parse_exclude(exclude: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in exclude.split(",") if item.strip())


def _load_license_policy(path: Path) -> list[str]:
    """Load an allowed-license list from a JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [str(item) for item in data]
    raise SystemExit(f"License policy file must be a JSON array of license IDs, got {type(data).__name__}")
