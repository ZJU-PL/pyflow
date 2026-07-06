"""CFG: control-flow graph for bytecode, including exception table edges."""

from .control_flow import (
    ControlFlowGraph,
    BasicBlock,
    ExceptionRegion,
    EdgeType,
    GuardFact,
    GuardAnalyzer,
    ExceptionCatchAnalyzer,
    build_cfg,
    analyze_guards,
    print_cfg,
)

from .dataflow import (
    GuardState,
    GuardDataflowAnalysis,
    TypeState,
    TypeStateAnalysis,
    BoundsInfo,
    BoundsAnalysis,
    ReachingDefinitionsAnalysis,
    IntraprocAnalysisResult,
    run_intraprocedural_analysis,
)

from .loop_analysis import (
    LoopInfo,
    extract_loops,
    identify_loop_pattern,
)

__all__ = [
    # Control flow
    'ControlFlowGraph',
    'BasicBlock',
    'ExceptionRegion',
    'EdgeType',
    'GuardFact',
    'GuardAnalyzer',
    'ExceptionCatchAnalyzer',
    'build_cfg',
    'analyze_guards',
    'print_cfg',
    # Dataflow
    'GuardState',
    'GuardDataflowAnalysis',
    'TypeState',
    'TypeStateAnalysis',
    'BoundsInfo',
    'BoundsAnalysis',
    'ReachingDefinitionsAnalysis',
    'IntraprocAnalysisResult',
    'run_intraprocedural_analysis',
    # Loop analysis
    'LoopInfo',
    'extract_loops',
    'identify_loop_pattern',
]
