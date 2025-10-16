"""
Call graph extraction for Python code.

This module provides call graph analysis with two algorithm options:
- ast_based: Fast, lightweight AST-based analysis (default)
- pycg: More sophisticated analysis using PyCG (if available)

The module is organized into focused components:
- Core CallGraph class in machinery module
- Analysis algorithms in ast_based and pycg_based modules
- Output formats in formats module
"""

from .constraint_based import (
    extract_call_graph_constraint as extract_call_graph,
    analyze_file_constraint as analyze_file,
)
from .pycg_based import extract_call_graph_pycg, analyze_file_pycg
from .formats import generate_text_output, generate_dot_output, generate_json_output
from ...machinery.callgraph import CallGraph, CallGraphError

__all__ = [
    "extract_call_graph",
    "analyze_file",
    "extract_call_graph_pycg",
    "analyze_file_pycg",
    "extract_call_graph",
    "analyze_file",
    "CallGraph",
    "CallGraphError",
    "generate_text_output",
    "generate_dot_output",
    "generate_json_output",
]
