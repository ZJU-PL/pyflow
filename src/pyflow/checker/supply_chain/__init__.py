# SPDX-License-Identifier: Apache-2.0

"""Local supply-chain analysis helpers.

This module intentionally works only from local files and package metadata. It
does not query package indexes, so generated SBOMs are reproducible offline.
"""

from .scanner import (
    SupplyChainFinding,
    SupplyChainScan,
    build_cyclonedx_document,
    format_findings_text,
    scan_targets,
)

__all__ = [
    "SupplyChainFinding",
    "SupplyChainScan",
    "build_cyclonedx_document",
    "format_findings_text",
    "scan_targets",
]
