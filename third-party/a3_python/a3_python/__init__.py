"""
A³: Advanced Automated Analysis for Python

Stateful, Continuous Python Semantics + Barrier-Certificate Verifier

A program analysis toolchain that produces:
1. BUG: model-checked reachable unsafe state with concrete counterexample trace
2. SAFE: proof (barrier certificate / inductive invariant) of unreachability
3. UNKNOWN: neither proof nor counterexample

No heuristics. Grounded in Python→Z3 heap/transition/barrier model.
"""

from importlib.metadata import version as _pkg_version, PackageNotFoundError

try:
    __version__: str = _pkg_version("a3-python")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"
