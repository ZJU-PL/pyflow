"""Static target discovery, input synthesis, and project scanning."""

from .catalog import FunctionTarget, ParameterTarget, discover_targets
from .inputgen import InputSynthesisResult, InputSynthesizer
from .scan import (
    FunctionScanResult,
    ProjectScanResult,
    ScanAttempt,
    ScanStatus,
    scan_project,
)

__all__ = [
    "FunctionScanResult",
    "FunctionTarget",
    "InputSynthesisResult",
    "InputSynthesizer",
    "ParameterTarget",
    "ProjectScanResult",
    "ScanAttempt",
    "ScanStatus",
    "discover_targets",
    "scan_project",
]
