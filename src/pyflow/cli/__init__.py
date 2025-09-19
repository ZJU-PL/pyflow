"""
PyFlow CLI tools.

This package contains command-line tools for PyFlow:
- analysis: Run static analysis and optimization on Python code
- callgraph: Build and visualize call graphs
- Both functionalities are unified in the analysis module
"""

from .main import main

__all__ = ["main"]
