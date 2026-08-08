"""Concolic test-input generation for small, pure Python functions.

The public entry point is :func:`explore_file`.  The implementation keeps the
concrete and symbolic executions together, so each newly solved path is
replayed as an ordinary set of Python values.
"""

from .engine import ContractCounterexample, ExplorationResult, RunRecord, explore_file

__all__ = ["ContractCounterexample", "ExplorationResult", "RunRecord", "explore_file"]
