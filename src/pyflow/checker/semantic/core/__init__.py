"""
Core infrastructure for the semantic checker.

This package holds shared types, session/context, runner, manager,
and the detector base used by concrete detectors in semantic.detectors.
"""

from .issue import Issue, Cwe
from .context import AnalysisSession
from .runner import StaticBugFinder, BugFinderConfig
from .manager import SemanticManager
from .base import Detector, run_detectors

__all__ = [
    "Issue",
    "Cwe",
    "AnalysisSession",
    "StaticBugFinder",
    "BugFinderConfig",
    "SemanticManager",
    "Detector",
    "run_detectors",
]
