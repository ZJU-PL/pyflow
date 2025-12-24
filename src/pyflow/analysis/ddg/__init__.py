"""
Data Dependence Graph (DDG) for PyFlow.

This package provides data dependence graph construction on top of the
existing dataflowIR and SSA infrastructure. A Data Dependence Graph
represents data dependencies between operations in a program, showing
which operations produce data that is consumed by other operations.

**Data Dependence Definition:**
A data dependence exists between two operations if:
1. One operation (def) produces a value
2. Another operation (use) consumes that value
3. The use operation depends on the def operation's result

**Graph Structure:**
- **Nodes**: Represent operations (ops) and storage locations (slots)
- **Edges**: Represent dependencies:
  - Def-use edges: Operation defines a slot, another operation uses it
  - Memory edges: Memory dependencies (RAW, WAR, WAW hazards)

**Construction:**
The DDG is built from dataflowIR graphs by:
1. Indexing all operations and slots from the dataflow graph
2. Connecting def-use pairs (operations that define slots to operations that use them)
3. Adding memory dependencies for heap operations (conservative analysis)

**Use Cases:**
- Program slicing: Find all operations that affect a specific value
- Dependency analysis: Understand data flow relationships
- Optimization: Identify independent operations for parallelization
- Debugging: Trace data flow to find sources of incorrect values
- Dead code elimination: Find unused definitions

**Module Structure:**
- graph.py: Core data structures (DDGNode, DDGEdge, DataDependenceGraph)
- construction.py: Algorithms for building DDG from dataflowIR
- dump.py: Visualization and serialization utilities
"""

from .graph import DataDependenceGraph, DDGNode, DDGEdge
from .construction import construct_ddg, DDGConstructor
from .dump import dump_ddg, DDGDumper, dump_ddg_to_directory

__all__ = [
    "DataDependenceGraph",
    "DDGNode",
    "DDGEdge",
    "DDGConstructor",
    "construct_ddg",
    "DDGDumper",
    "dump_ddg",
    "dump_ddg_to_directory",
]


