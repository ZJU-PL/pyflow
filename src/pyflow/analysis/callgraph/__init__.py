"""
Call graph extraction for Python code.

This module provides call graph analysis with multiple algorithm options:
- ast_based: Fast, lightweight AST-based analysis
- pycg: More sophisticated analysis using PyCG (if available)
- constraint_based: Original constraint solver (may be unavailable in OSS build)

The module is organized into focused components:
- Core CallGraph class in machinery module
- Analysis algorithms in ast_based and pycg_based modules
- Output formats in formats module
"""

# Prefer the more precise constraint-based implementation when available.
# If it's missing (e.g. in lightweight installs), fall back to the PyCG-backed
# implementation, which relies on the external `pycg` package. As a final
# fallback, use the minimal AST-based implementation so basic functionality
# still works even without optional dependencies.
try:
    from .constraint_based import (
        extract_call_graph_constraint as extract_call_graph,
        analyze_file_constraint as analyze_file,
    )
except ModuleNotFoundError:
    try:
        from .pycg_based import (
            extract_call_graph_pycg as extract_call_graph,
            analyze_file_pycg as analyze_file,
        )
    except (ModuleNotFoundError, ImportError):
        from .ast_based import extract_call_graph, analyze_file

from .pycg_based import extract_call_graph_pycg, analyze_file_pycg
from .formats import generate_text_output, generate_dot_output, generate_json_output
from ...machinery.callgraph import CallGraph, CallGraphError

__all__ = [
    "extract_call_graph",
    "analyze_file",
    "extract_call_graph_pycg",
    "analyze_file_pycg",
    "CallGraph",
    "CallGraphError",
    "generate_text_output",
    "generate_dot_output",
    "generate_json_output",
]
