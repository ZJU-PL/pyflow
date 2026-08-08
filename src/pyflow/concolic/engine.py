"""Public concolic exploration API.

The AST executor is implemented across focused internal modules.  This module
is retained as the stable import location for callers that previously imported
``pyflow.concolic.engine``.
"""

from .executor import (
    ConcolicError,
    ContractCounterexample,
    ExplorationResult,
    RunRecord,
    explore_file,
)

__all__ = [
    "ConcolicError",
    "ContractCounterexample",
    "ExplorationResult",
    "RunRecord",
    "explore_file",
]
