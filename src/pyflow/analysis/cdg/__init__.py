"""
Control Dependence Graph (CDG) analysis for PyFlow.

This module provides functionality to construct and analyze Control Dependence Graphs
from Control Flow Graphs. A Control Dependence Graph represents the control
dependencies between nodes in a program, showing which nodes control the execution
of other nodes.

**Control Dependence Definition:**
A node B is control dependent on node A if:
1. There exists a path from A to B
2. A does not post-dominate B (there's a path from A to exit that bypasses B)
3. All paths from A to B pass through some node that post-dominates B

In simpler terms: B is control dependent on A if A's decision (e.g., in an if/while)
determines whether B executes.

**Construction Algorithm:**
The CDG is constructed using dominance frontiers:
- The dominance frontier of node X is the set of nodes Y where X dominates a
  predecessor of Y, but X does not strictly dominate Y
- Control dependencies are derived from dominance frontiers: if Y is in the
  dominance frontier of X, then Y is control dependent on X

**Use Cases:**
- Program slicing: Extract code that affects a specific variable or statement
- Data flow analysis: Understand how control flow affects data flow
- Program understanding: Visualize control relationships
- Debugging: Identify which control decisions affect problematic code
- Optimization: Understand control dependencies for better optimization

**Module Structure:**
- graph.py: Core data structures (CDGNode, CDGEdge, ControlDependenceGraph)
- construction.py: Algorithms for building CDG from CFG
- dump.py: Visualization and serialization utilities
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
