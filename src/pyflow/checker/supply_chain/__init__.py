# SPDX-License-Identifier: Apache-2.0

"""Local supply-chain analysis helpers.

This module intentionally works only from local files and package metadata. It
does not query package indexes, so generated SBOMs are reproducible offline.
"""

from .formats import (
    build_cyclonedx_document,
    build_requirements_text,
    build_spdx_document,
    format_findings_text,
)
from .licenses import audit_license_policy
from .models import (
    ScanLimits,
    SupplyChainFinding,
    SupplyChainScan,
)
from .scanner import scan_targets
from .vulnerabilities import audit_vulnerabilities

__all__ = [
    "ScanLimits",
    "SupplyChainFinding",
    "SupplyChainScan",
    "audit_license_policy",
    "audit_vulnerabilities",
    "build_cyclonedx_document",
    "build_requirements_text",
    "build_spdx_document",
    "format_findings_text",
    "scan_targets",
]
