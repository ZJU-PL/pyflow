"""Defensive, pointer-based capability analysis for Python projects."""

from .analysis import DefensiveCapabilityAnalysis
from .escape import CapabilityEscapeEvent, EscapeKind
from .effects import ExternalEffectKind, ExternalEffectSummary
from .defaults import default_capability_registry
from .model import (
    CapabilityAnalysisResult,
    CapabilityDiagnostic,
    CapabilityFinding,
    CapabilityOperation,
    CapabilityReportKind,
    SourceLocation,
)
from .registry import CapabilityPattern, CapabilityRegistry
from .runtime import (
    CapabilityViolation,
    RuntimeCapabilityEvent,
    RuntimeCapabilityGuard,
    RuntimeCapabilityPolicy,
    capability_for_audit_event,
    install_runtime_guard,
)

__all__ = [
    "CapabilityAnalysisResult",
    "CapabilityDiagnostic",
    "CapabilityFinding",
    "CapabilityEscapeEvent",
    "CapabilityOperation",
    "CapabilityPattern",
    "CapabilityRegistry",
    "CapabilityViolation",
    "CapabilityReportKind",
    "DefensiveCapabilityAnalysis",
    "EscapeKind",
    "ExternalEffectKind",
    "ExternalEffectSummary",
    "RuntimeCapabilityEvent",
    "RuntimeCapabilityGuard",
    "RuntimeCapabilityPolicy",
    "SourceLocation",
    "default_capability_registry",
    "capability_for_audit_event",
    "install_runtime_guard",
]
