"""Supply-chain analysis CLI commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from pyflow.checker.supply_chain import (
    build_cyclonedx_document,
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
        help="Generate a local CycloneDX SBOM",
        description="Generate a CycloneDX SBOM from local package metadata and manifests.",
    )
    _add_common_args(sbom)
    sbom.add_argument(
        "--format",
        choices=["cyclonedx-json", "json"],
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
            json.dump(build_cyclonedx_document(scan), output, indent=2)
            output.write("\n")
            return 0

        if args.supply_chain_command == "audit":
            if args.format == "json":
                json.dump(
                    {"results": [finding.to_dict() for finding in scan.findings]},
                    output,
                    indent=2,
                )
                output.write("\n")
            else:
                output.write(format_findings_text(scan))
                output.write("\n")
            return 1 if scan.findings else 0
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
