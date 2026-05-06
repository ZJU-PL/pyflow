"""
DSE (Dynamic Symbolic Execution) for FP Reduction.

This module provides comprehensive DSE capabilities:

1. **Concolic Execution** (concolic.py): Trace validation for bug reproduction
2. **Path Condition Tracking** (path_condition.py): Full DSE with Z3 constraints
3. **Value Flow Analysis** (value_flow.py): Richer value flow + path sensitivity
4. **Selective Concolic** (selective_concolic.py): Targeted path exploration
5. **Hybrid Execution** (hybrid.py): Combining concrete and symbolic

Key FP Reduction Techniques:
- **Infeasible Path Pruning**: SAT(path_condition ∧ bug_condition) = UNSAT → FP
- **Value Flow Guards**: Guards propagate through assignments and operations
- **Path-Sensitive Analysis**: Track guards per CFG path (lighter than full DSE)
- **Type-Based Filtering**: `self` is never None by construction
"""

from .concolic import ConcreteExecutor, TraceValidator, DSEResult
from .selective_concolic import SelectiveConcolicExecutor, SelectiveConcolicTrace
from .hybrid import ConcolicReplayOracle
from .lockstep import run_lockstep, LockstepResult

# New DSE modules for FP reduction
from .path_condition import (
    SymbolicValue,
    PathCondition,
    SymbolicState,
    DSEExecutor,
    run_dse_analysis,
)
from .value_flow import (
    FlowKind,
    ValueFlowEdge,
    ValueFlowGraph,
    ValueFlowAnalyzer,
    FunctionReturnSemantics,
    ContainerOperationSemantics,
    PathGuardState,
    PathSensitiveGuardAnalyzer,
    FlowEnrichedGuardState,
)

__all__ = [
    # Original exports
    "ConcreteExecutor",
    "TraceValidator",
    "DSEResult",
    "SelectiveConcolicExecutor",
    "SelectiveConcolicTrace",
    "ConcolicReplayOracle",
    "run_lockstep",
    "LockstepResult",
    
    # Path condition tracking
    "SymbolicValue",
    "PathCondition",
    "SymbolicState",
    "DSEExecutor",
    "run_dse_analysis",
    
    # Value flow analysis
    "FlowKind",
    "ValueFlowEdge",
    "ValueFlowGraph",
    "ValueFlowAnalyzer",
    "FunctionReturnSemantics",
    "ContainerOperationSemantics",
    "PathGuardState",
    "PathSensitiveGuardAnalyzer",
    "FlowEnrichedGuardState",
]
