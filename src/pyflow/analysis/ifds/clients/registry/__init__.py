"""Framework-aware rule pack registry.

Provides lazy-loaded, framework-aware call models for IFDS analyses.
Packs are JSON files in this directory, each describing sources, sinks,
sanitizers, nullness, and typestate behavior for a specific framework.
"""

from .loader import (
    Registry,
    RuleMetadata,
    RulePackValidationError,
    ValidationIssue,
    load_registry,
    validate_registry,
    validate_rule_pack_data,
)

__all__ = [
    "Registry",
    "RuleMetadata",
    "RulePackValidationError",
    "ValidationIssue",
    "load_registry",
    "validate_registry",
    "validate_rule_pack_data",
]
