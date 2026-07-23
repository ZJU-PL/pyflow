# SPDX-License-Identifier: Apache-2.0

"""Local supply-chain analysis helpers.

This module intentionally works only from local files and package metadata. It
does not query package indexes, so generated SBOMs are reproducible offline.
"""

from .formats import (
    build_cyclonedx_document,
    build_requirements_text,
    build_sarif_document,
    build_spdx_document,
    format_findings_text,
)
from .environment import resolve_environment
from .licenses import audit_license_policy
from .models import (
    ScanLimits,
    SupplyChainFinding,
    SupplyChainScan,
)
from .scanner import scan_targets
from .policy import (
    FindingPolicy,
    apply_finding_policy,
    audit_package_names,
    load_baseline,
    load_finding_policy,
    write_baseline,
)
from .provenance import audit_provenance, audit_sigstore_bundles
from .reachability import analyze_reachability, load_import_map
from .validation import (
    SbomValidationError,
    validate_cyclonedx_document,
    validate_json_schema,
    validate_spdx_document,
)
from .vulnerabilities import audit_vulnerabilities

__all__ = [
    "ScanLimits",
    "SupplyChainFinding",
    "SupplyChainScan",
    "FindingPolicy",
    "SbomValidationError",
    "apply_finding_policy",
    "analyze_reachability",
    "audit_license_policy",
    "audit_package_names",
    "audit_provenance",
    "audit_sigstore_bundles",
    "audit_vulnerabilities",
    "build_cyclonedx_document",
    "build_requirements_text",
    "build_sarif_document",
    "build_spdx_document",
    "format_findings_text",
    "load_baseline",
    "load_finding_policy",
    "load_import_map",
    "resolve_environment",
    "scan_targets",
    "validate_cyclonedx_document",
    "validate_json_schema",
    "validate_spdx_document",
    "write_baseline",
]
