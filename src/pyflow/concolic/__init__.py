"""Concolic test-input generation for small, pure Python functions.

The public entry point is :func:`explore_file`.  The implementation keeps the
concrete and symbolic executions together, so each newly solved path is
replayed as an ordinary set of Python values.
"""

from .catalog import FunctionTarget, ParameterTarget, discover_targets
from .corpus import minimize_runs
from .engine import explore_file
from .inputgen import InputSynthesisResult, InputSynthesizer
from .project_scan import (
    FunctionScanResult,
    ProjectScanResult,
    ScanAttempt,
    ScanStatus,
    scan_project,
)
from .pytestgen import PytestGenerationResult, generate_pytest
from .replay import ReplayResult, ReplayStatus, replay_runs
from .runtime import (
    BranchCoverage,
    ContractCounterexample,
    CoverageSnapshot,
    ExecutionOutcome,
    ExplorationResult,
    ExplorationStatistics,
    OutcomeKind,
    RunRecord,
    SourceLocation,
)

__all__ = [
    "BranchCoverage",
    "ContractCounterexample",
    "CoverageSnapshot",
    "ExecutionOutcome",
    "ExplorationResult",
    "ExplorationStatistics",
    "FunctionScanResult",
    "FunctionTarget",
    "InputSynthesisResult",
    "InputSynthesizer",
    "OutcomeKind",
    "ParameterTarget",
    "ProjectScanResult",
    "PytestGenerationResult",
    "ReplayResult",
    "ReplayStatus",
    "RunRecord",
    "ScanAttempt",
    "ScanStatus",
    "SourceLocation",
    "discover_targets",
    "explore_file",
    "generate_pytest",
    "minimize_runs",
    "replay_runs",
    "scan_project",
]
