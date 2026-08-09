"""Concolic test-input generation for small, pure Python functions.

The public entry point is :func:`explore_file`.  The implementation keeps the
concrete and symbolic executions together, so each newly solved path is
replayed as an ordinary set of Python values.
"""

from .artifacts import (
    PytestGenerationResult,
    ReplayResult,
    ReplayStatus,
    generate_pytest,
    minimize_runs,
    replay_runs,
)
from .core.runtime import (
    BranchCoverage,
    ConcolicError,
    ContractCounterexample,
    CoverageSnapshot,
    ExecutionOutcome,
    ExplorationResult,
    ExplorationStatistics,
    OutcomeKind,
    RunRecord,
    SourceLocation,
)
from .exploration import explore_file
from .project import (
    FunctionScanResult,
    FunctionTarget,
    InputSynthesisResult,
    InputSynthesizer,
    ParameterTarget,
    ProjectScanResult,
    ScanAttempt,
    ScanStatus,
    discover_targets,
    scan_project,
)

__all__ = [
    "BranchCoverage",
    "ConcolicError",
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
