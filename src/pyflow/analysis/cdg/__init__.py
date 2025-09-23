"""
Control Dependence Graph (CDG) analysis for PyFlow.

This module provides functionality to construct and analyze Control Dependence Graphs
from Control Flow Graphs. A CDG represents the control dependencies between nodes,
showing which nodes control the execution of other nodes.

The CDG is constructed using dominance frontiers and is useful for:
- Program slicing
- Data flow analysis
- Program understanding
- ...
"""

from .graph import CDGNode, CDGEdge, ControlDependenceGraph
from .construction import CDGConstructor, construct_cdg, analyze_control_dependencies
from .dump import CDGDumper, dump_cdg, dump_cdg_to_directory

__all__ = [
    'CDGNode',
    'CDGEdge', 
    'ControlDependenceGraph',
    'CDGConstructor',
    'construct_cdg',
    'analyze_control_dependencies',
    'CDGDumper',
    'dump_cdg',
    'dump_cdg_to_directory'
]
