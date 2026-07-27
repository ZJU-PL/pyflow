"""
Core infrastructure for the AST dataflow checker.

This package holds shared types, session/context, runner, manager,
and the detector base used by concrete detectors in ast_dataflow.detectors.
"""

from .issue import Issue, Cwe
from .context import AnalysisSession
from .runner import StaticBugFinder, BugFinderConfig
from .manager import ASTDataflowManager
from .base import Detector, run_detectors

__all__ = [
    "Issue",
    "Cwe",
    "AnalysisSession",
    "StaticBugFinder",
    "BugFinderConfig",
    "ASTDataflowManager",
    "Detector",
    "run_detectors",
]
