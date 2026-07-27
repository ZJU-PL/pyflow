"""
Static bug finder built on PyFlow analyses.

  core/     - session, runner, manager, issue, detector base
  detectors/ - AST dataflow taint detection
"""

from .core import (
    Issue,
    Cwe,
    StaticBugFinder,
    BugFinderConfig,
    ASTDataflowManager,
)

__all__ = [
    "StaticBugFinder",
    "BugFinderConfig",
    "ASTDataflowManager",
    "Issue",
    "Cwe",
]
