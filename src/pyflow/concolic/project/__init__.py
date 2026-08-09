"""Static target discovery, input synthesis, and project scanning."""

from .catalog import FunctionTarget, ParameterTarget, discover_targets
from .inputgen import InputSynthesisResult, InputSynthesizer
from .operations import OperationCatalog, OperationSupport, OperationUse, discover_operations
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
    "OperationCatalog",
    "OperationSupport",
    "OperationUse",
    "ParameterTarget",
    "ProjectScanResult",
    "ScanAttempt",
    "ScanStatus",
    "discover_targets",
    "discover_operations",
    "scan_project",
]
