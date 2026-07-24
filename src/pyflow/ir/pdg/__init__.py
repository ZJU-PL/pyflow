"""
Program Dependence Graph (PDG) analysis for PyFlow.

This package provides a production-ready intraprocedural Program Dependence Graph
library built on top of PyFlow's existing IRs.

A PDG is a directed graph that combines:
- **Control dependences** (from Control Dependence Graph / CDG): which control-flow
  decisions determine whether a statement executes.
- **Data dependences** (def-use): which definitions provide values that are used
  by other statements.

This implementation is designed to work directly from PyFlow's CFG while
reusing PyFlow's other graph analyses:
- control dependences come from the CDG built over the CFG
- data dependences come from the DDG built over dataflow IR and projected back
  onto PDG statement/condition nodes
- a narrow AST def-use fallback remains for statement forms that the current
  DDG does not model directly

Typical use cases:
- Program slicing (backward/forward slices)
- Impact analysis ("what can affect this statement?")
- Dependency queries for optimization and security analysis

Module structure:
- graph.py: Core data structures (PDGNode, PDGEdge, ProgramDependenceGraph)
- construction.py: Algorithms for building PDGs from CFGs (and optionally SSA)
- dump.py: Visualization/serialization utilities (text, DOT, JSON)
"""

from .graph import PDGNode, PDGEdge, ProgramDependenceGraph
from .construction import PDGConstructor, construct_pdg
from .dump import PDGDumper, dump_pdg, dump_pdg_to_directory
from .cypher import (
    execute as execute_cypher,
    parse as parse_cypher,
    CypherSyntaxError,
    CypherExecutionError,
)

__all__ = [
    "PDGNode",
    "PDGEdge",
    "ProgramDependenceGraph",
    "PDGConstructor",
    "construct_pdg",
    "PDGDumper",
    "dump_pdg",
    "dump_pdg_to_directory",
    "execute_cypher",
    "parse_cypher",
    "CypherSyntaxError",
    "CypherExecutionError",
]
