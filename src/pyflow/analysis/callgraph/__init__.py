"""
Simple call graph extraction for Python code.

This module provides straightforward call graph analysis with two algorithm options:
- simple: Fast, lightweight AST-based analysis (default)
- pycg: More sophisticated analysis using PyCG (if available)

The module is organized into focused components:
- Core CallGraph class in machinery module
- Analysis types in types module
- Output formats in formats module
"""

from .simple import extract_call_graph, analyze_file
from .pycg_based import extract_call_graph_pycg, analyze_file_pycg
from .types import SimpleFunction, CallGraphData
from .formats import generate_text_output, generate_dot_output, generate_json_output
from ...machinery.callgraph import CallGraph, CallGraphError

__all__ = [
    "extract_call_graph",
    "analyze_file",
    "extract_call_graph_pycg",
    "analyze_file_pycg",
    "SimpleFunction",
    "CallGraphData",
    "CallGraph",
    "CallGraphError",
    "generate_text_output",
    "generate_dot_output",
    "generate_json_output",
]
