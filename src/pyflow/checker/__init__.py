# Security checker for pyflow
# NOTE: Current, the security checker does not use the facilities in pyflow.
from .pattern.core.manager import SecurityManager
from .pattern.core.config import SecurityConfig
from .pattern.core.issue import Issue, Cwe
from .ast_dataflow import StaticBugFinder, BugFinderConfig

__all__ = [
    "SecurityManager",
    "SecurityConfig",
    "Issue",
    "Cwe",
    "StaticBugFinder",
    "BugFinderConfig",
]

"""
Security checker and analysis-backed bug finder for PyFlow.

- pattern: Pattern-based AST matching for security checks (Bandit-style)
- ast_dataflow: Interprocedural taint dataflow over the Python AST.
"""
