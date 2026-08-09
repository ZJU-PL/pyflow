"""Security checkers built on PyFlow's syntax and semantic engines.

Specialized semantic checkers are exposed from ``checker.class_pollution``
and ``checker.capability``; the top-level package keeps its lightweight legacy
exports for pattern and AST-dataflow clients.
"""

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
