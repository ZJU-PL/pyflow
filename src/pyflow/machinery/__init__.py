"""
Lightweight machinery helpers used by the high-level analysis packages.

Only a very small subset of the original PyFlow machinery module is required
for the OSS-friendly call graph tooling, so we re-create the minimal API
surface that the analysis layer expects.
"""

from .callgraph import CallGraph, CallGraphError

__all__ = ["CallGraph", "CallGraphError"]

