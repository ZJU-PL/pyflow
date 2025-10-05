"""PyFlow - A static compiler for Python.

PyFlow is a comprehensive static analysis and compilation tool for Python code.
It provides various analysis capabilities including control flow analysis,
data flow analysis, inter-procedural analysis, constraint-based analysis,
shape analysis, and optimization passes.

Key Features:
    - Control Flow Graph (CFG) construction and analysis
    - Data Flow Analysis with configurable meet functions
    - Inter-procedural Analysis (IPA) for context-sensitive analysis
    - Constraint-based Analysis (CPA) using constraint solving
    - Shape analysis for data structures
    - Call graph construction with multiple algorithms
    - Dead code elimination and other optimizations
    - Bytecode decompilation capabilities

Copyright (c) 2025 rainoftime
Licensed under the Apache License, Version 2.0
"""

__version__ = "0.1.0"
__author__ = "rainoftime"
__email__ = "rainoftime@gmail.com"

# Import main components for easy access
from .application.program import Program
from .application.pipeline import Pipeline
from .application.context import Context

__all__ = [
    "Program",
    "Pipeline", 
    "Context",
    "__version__",
    "__author__",
    "__email__",
]
