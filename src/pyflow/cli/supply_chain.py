"""Supply-chain analysis CLI commands."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from pyflow.checker.supply_chain import (
    FindingPolicy,
    ScanLimits,
    SbomValidationError,
    SupplyChainFinding,
    SupplyChainScan,
    apply_finding_policy,
    analyze_reachability,
    audit_license_policy,
    audit_package_names,
    audit_provenance,
    audit_sigstore_bundles,
    audit_vulnerabilities,
    build_cyclonedx_document,
    build_requirements_text,
    build_sarif_document,
    build_spdx_document,
    format_findings_text,
    load_baseline,
    load_finding_policy,
    load_import_map,
    resolve_environment,
    scan_targets,
    validate_json_schema,
    write_baseline,
)
from pyflow.checker.supply_chain.input_safety import load_json_file


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
    sbom.add_argument(
        "--deterministic",
        action="store_true",
        help="Use content-derived identifiers and SOURCE_DATE_EPOCH timestamps",
    )
    sbom.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Return success even when high-severity scan errors make the SBOM incomplete",
    )
    sbom.add_argument(
        "--schema",
        type=Path,
        help="Validate JSON output against a pinned local CycloneDX or SPDX schema",
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
        choices=["text", "json", "sarif"],
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
        default="high",
        help="Lowest finding severity that produces a non-zero exit (default: high)",
    )
    audit.add_argument(
        "--osv-database",
        metavar="PATH",
        type=Path,
        action="append",
        default=[],
        help="Local OSV JSON/JSONL file or directory (repeatable; no network access)",
    )
    audit.add_argument(
        "--osv-max-age-days",
        type=_non_negative_float,
        help="Fail policy when local vulnerability data is older than this many days",
    )
    audit.add_argument(
        "--require-osv-checksum",
        action="store_true",
        help="Require a FILE.sha256 sidecar for every local OSV database file",
    )
    audit.add_argument(
        "--vex",
        metavar="FILE",
        type=Path,
        action="append",
        default=[],
        help="CycloneDX or OpenVEX document used to qualify vulnerability results",
    )
    audit.add_argument(
        "--reachability",
        action="store_true",
        help="Annotate vulnerabilities with conservative source-import evidence",
    )
    audit.add_argument(
        "--import-map",
        type=Path,
        help="JSON mapping of distribution names to importable top-level modules",
    )
    audit.add_argument(
        "--policy",
        type=Path,
        help="JSON policy containing expiring finding exceptions",
    )
    audit.add_argument(
        "--baseline",
        type=Path,
        help="Suppress finding IDs recorded in a PyFlow baseline",
    )
    audit.add_argument(
        "--write-baseline",
        type=Path,
        help="Write all current finding IDs to a baseline file",
    )
    audit.add_argument(
        "--show-suppressed",
        action="store_true",
        help="Include policy-suppressed findings in JSON/SARIF output",
    )
    audit.add_argument(
        "--protected-package",
        action="append",
        default=[],
        help="Protected internal or high-value package name for typosquatting checks",
    )
    audit.add_argument(
        "--attestation",
        type=Path,
        action="append",
        default=[],
        help="Local in-toto/SLSA attestation (repeatable)",
    )
    audit.add_argument(
        "--require-provenance",
        action="store_true",
        help="Require every scanned archive to have digest-bound provenance",
    )
    audit.add_argument(
        "--require-dsse",
        action="store_true",
        help="Require provenance to be wrapped in a DSSE envelope",
    )
    audit.add_argument(
        "--trusted-builder",
        action="append",
        default=[],
        help="Allowed SLSA builder ID (repeatable)",
    )
    audit.add_argument(
        "--sigstore-bundle",
        action="append",
        default=[],
        metavar="ARTIFACT=BUNDLE",
        help="Verify an artifact against a local Sigstore bundle",
    )
    audit.add_argument("--cert-identity", help="Expected Sigstore certificate identity")
    audit.add_argument(
        "--cert-oidc-issuer", help="Expected Sigstore certificate OIDC issuer"
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
    environment = _target_environment(args)
    if environment or getattr(args, "extra", None):
        scan = resolve_environment(
            scan,
            environment=environment,
            extras=getattr(args, "extra", ()) or (),
        )

    out_file = None
    output_path = getattr(args, "output", None)
    temporary_output: Path | None = None
    commit_output = False
    try:
        if output_path:
            try:
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{output_path.name}.",
                    suffix=".tmp",
                    dir=output_path.parent,
                )
                temporary_output = Path(temporary_name)
                out_file = os.fdopen(descriptor, "w", encoding="utf-8")
            except OSError as exc:
                print(f"Could not open supply-chain output: {exc}", file=sys.stderr)
                return 2
        output = out_file or sys.stdout

        if args.supply_chain_command == "sbom":
            fmt = args.format
            if fmt == "requirements":
                output.write(build_requirements_text(scan))
            elif fmt == "spdx-json":
                document = build_spdx_document(
                    scan, deterministic=getattr(args, "deterministic", False)
                )
                if getattr(args, "schema", None):
                    validate_json_schema(document, args.schema)
                json.dump(document, output, indent=2)
                output.write("\n")
            else:
                document = build_cyclonedx_document(
                    scan, deterministic=getattr(args, "deterministic", False)
                )
                if getattr(args, "schema", None):
                    validate_json_schema(document, args.schema)
                json.dump(document, output, indent=2)
                output.write("\n")
            incomplete = not bool(scan.metadata.get("inventoryComplete", True)) or any(
                _severity_rank(finding.severity) >= _severity_rank("high")
                for finding in scan.findings
            )
            commit_output = True
            return (
                2 if incomplete and not getattr(args, "allow_incomplete", False) else 0
            )

        if args.supply_chain_command == "audit":
            findings = list(scan.findings)

            license_policy_path = getattr(args, "license_policy", None)
            skip_license_audit = getattr(args, "skip_license_audit", False)
            if license_policy_path is not None and not skip_license_audit:
                try:
                    allowed, exceptions = _load_license_policy(license_policy_path)
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    print(f"Could not load license policy: {exc}", file=sys.stderr)
                    return 2
                findings.extend(
                    audit_license_policy(
                        scan,
                        allowed_licenses=allowed,
                        allowed_exceptions=exceptions,
                    )
                )
            elif scan.components and not skip_license_audit:
                findings.extend(audit_license_policy(scan))
            protected_packages = getattr(args, "protected_package", ()) or ()
            if protected_packages:
                findings.extend(audit_package_names(scan, protected_packages))
            osv_databases = getattr(args, "osv_database", ()) or ()
            if osv_databases:
                reachable_refs = None
                if getattr(args, "reachability", False):
                    try:
                        import_map = (
                            load_import_map(args.import_map)
                            if getattr(args, "import_map", None)
                            else None
                        )
                        reachable_refs, reachability_findings = analyze_reachability(
                            scan, targets, import_map=import_map
                        )
                        findings.extend(reachability_findings)
                    except (OSError, ValueError, json.JSONDecodeError) as exc:
                        findings.append(
                            _configuration_finding(
                                f"Could not load reachability import map: {exc}"
                            )
                        )
                findings.extend(
                    audit_vulnerabilities(
                        scan,
                        osv_databases,
                        max_database_age_days=getattr(args, "osv_max_age_days", None),
                        require_hashes=getattr(args, "require_osv_checksum", False),
                        vex_documents=getattr(args, "vex", ()) or (),
                        reachable_refs=reachable_refs,
                    )
                )
            artifacts = [
                Path(value)
                for value in scan.metadata.get("artifacts", ())
                if Path(value).is_file()
            ]
            attestations = getattr(args, "attestation", ()) or ()
            if attestations or getattr(args, "require_provenance", False):
                findings.extend(
                    audit_provenance(
                        artifacts,
                        attestations,
                        trusted_builders=getattr(args, "trusted_builder", ()) or (),
                        require_provenance=getattr(args, "require_provenance", False),
                        require_dsse=getattr(args, "require_dsse", False),
                    )
                )
            sigstore_bundles = getattr(args, "sigstore_bundle", ()) or ()
            if sigstore_bundles:
                identity = getattr(args, "cert_identity", None)
                issuer = getattr(args, "cert_oidc_issuer", None)
                if not identity or not issuer:
                    findings.append(
                        _configuration_finding(
                            "Sigstore verification requires --cert-identity and "
                            "--cert-oidc-issuer"
                        )
                    )
                else:
                    findings.extend(
                        audit_sigstore_bundles(
                            sigstore_bundles,
                            certificate_identity=identity,
                            certificate_oidc_issuer=issuer,
                        )
                    )

            if getattr(args, "write_baseline", None):
                try:
                    write_baseline(args.write_baseline, findings)
                except OSError as exc:
                    print(
                        f"Could not write supply-chain baseline: {exc}", file=sys.stderr
                    )
                    return 2

            policy = FindingPolicy()
            policy_path = getattr(args, "policy", None)
            baseline_path = getattr(args, "baseline", None)
            try:
                if policy_path:
                    policy = load_finding_policy(policy_path)
                if baseline_path:
                    policy = FindingPolicy(
                        exceptions=policy.exceptions,
                        baseline_ids=policy.baseline_ids | load_baseline(baseline_path),
                    )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"Could not load supply-chain policy: {exc}", file=sys.stderr)
                return 2
            kept, suppressed = apply_finding_policy(findings, policy)
            findings = list(kept)

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
                results = [f.to_dict() for f in findings]
                if getattr(args, "show_suppressed", False):
                    results.extend(
                        {**finding.to_dict(), "suppressed": True}
                        for finding in suppressed
                    )
                json.dump(
                    {
                        "schemaVersion": "1.0",
                        "summary": {
                            "components": len(scan.components),
                            "findings": len(findings),
                            "suppressed": len(suppressed),
                            "severity": {
                                severity: severity_counts.get(severity, 0)
                                for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                            },
                        },
                        "results": results,
                    },
                    output,
                    indent=2,
                )
                output.write("\n")
            elif args.format == "sarif":
                sarif_findings = list(findings)
                if getattr(args, "show_suppressed", False):
                    sarif_findings.extend(suppressed)
                sarif_document = build_sarif_document(
                    SupplyChainScan(
                        components=scan.components,
                        findings=tuple(sarif_findings),
                        dependencies=scan.dependencies,
                        metadata=scan.metadata,
                    )
                )
                suppressed_ids = {finding.to_dict()["id"] for finding in suppressed}
                for result in sarif_document["runs"][0]["results"]:
                    finding_id = result.get("partialFingerprints", {}).get(
                        "pyflowFindingId"
                    )
                    if finding_id in suppressed_ids:
                        result["suppressions"] = [
                            {
                                "kind": "external",
                                "justification": "Suppressed by PyFlow policy or baseline",
                            }
                        ]
                json.dump(sarif_document, output, indent=2)
                output.write("\n")
            else:
                # Rebuild a Scan-like container for formatting
                formatted = SupplyChainScan(
                    components=scan.components,
                    findings=tuple(findings),
                    dependencies=scan.dependencies,
                    metadata=scan.metadata,
                )
                output.write(format_findings_text(formatted))
                output.write("\n")
            fail_on = getattr(args, "fail_on", "high")
            commit_output = True
            return 1 if _should_fail(findings, fail_on) else 0
    except (OSError, SbomValidationError) as exc:
        print(f"Supply-chain command failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if out_file:
            if commit_output:
                out_file.flush()
                os.fsync(out_file.fileno())
            out_file.close()
        if temporary_output is not None:
            if commit_output and output_path is not None:
                try:
                    os.replace(temporary_output, output_path)
                except OSError as exc:
                    temporary_output.unlink(missing_ok=True)
                    print(
                        f"Could not commit supply-chain output: {exc}",
                        file=sys.stderr,
                    )
                    return 2
            else:
                temporary_output.unlink(missing_ok=True)

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
        "--python-version",
        help="Target Python version for PEP 508 marker evaluation (for example 3.12)",
    )
    parser.add_argument("--platform", help="Target sys_platform marker value")
    parser.add_argument(
        "--implementation", help="Target implementation_name marker value"
    )
    parser.add_argument(
        "--extra",
        action="append",
        default=[],
        help="Selected dependency extra for marker evaluation (repeatable)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file (default: stdout)",
    )
    defaults = ScanLimits()
    parser.add_argument(
        "--max-scan-entries",
        type=_non_negative_int,
        default=defaults.max_scan_entries,
        help="Maximum directory entries inspected across the scan (default: 200000)",
    )
    parser.add_argument(
        "--max-archive-mb",
        type=_non_negative_float,
        default=defaults.max_archive_size / (1024 * 1024),
        help="Maximum archive input size in MiB (default: 5000)",
    )
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


def _load_license_policy(path: Path) -> tuple[list[str], list[str] | None]:
    """Load an allowed-license list from a JSON file."""
    try:
        data = load_json_file(path)
    except OSError as exc:
        raise ValueError(f"Could not read license policy file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"License policy file is not valid JSON: {exc}") from exc
    if isinstance(data, list):
        return [str(item) for item in data], None
    if isinstance(data, dict) and isinstance(data.get("allowed_licenses"), list):
        raw_exceptions = data.get("allowed_exceptions")
        if raw_exceptions is not None and not isinstance(raw_exceptions, list):
            raise ValueError("allowed_exceptions must be a JSON array")
        return [str(item) for item in data["allowed_licenses"]], (
            [str(item) for item in raw_exceptions]
            if raw_exceptions is not None
            else None
        )
    raise ValueError(
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
        max_archive_size=int(
            getattr(args, "max_archive_mb", defaults.max_archive_size / mib) * mib
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
        max_scan_entries=getattr(args, "max_scan_entries", defaults.max_scan_entries),
    )


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _non_negative_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("value must be finite and non-negative")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be finite and greater than zero")
    return parsed


def _severity_rank(value: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value.upper(), 0)


def _should_fail(findings: list[Any], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = _severity_rank(fail_on)
    return any(_severity_rank(finding.severity) >= threshold for finding in findings)


def _target_environment(args: Any) -> dict[str, str]:
    environment: dict[str, str] = {}
    python_version = getattr(args, "python_version", None)
    if python_version:
        environment["python_version"] = str(python_version)
        environment["python_full_version"] = str(python_version)
    platform = getattr(args, "platform", None)
    if platform:
        environment["sys_platform"] = str(platform)
    implementation = getattr(args, "implementation", None)
    if implementation:
        environment["implementation_name"] = str(implementation)
    return environment


def _configuration_finding(message: str) -> SupplyChainFinding:
    return SupplyChainFinding(
        kind="invalid-supply-chain-configuration",
        message=message,
        location="command-line",
        severity="HIGH",
    )
