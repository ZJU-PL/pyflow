"""
Static bug finder built on top of PyFlow analyses.

This package houses a modular, analysis-backed engine that runs the PyFlow
pipeline (IPA/CPA/lifetime, etc.) and feeds semantic facts into focused
detectors (taint, misuse, resource handling, etc.).
"""

from .issue import Issue, Cwe
from .runner import StaticBugFinder, BugFinderConfig

__all__ = ["StaticBugFinder", "BugFinderConfig", "Issue", "Cwe"]
