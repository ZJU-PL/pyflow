

# Security checker for pyflow
# NOTE: Current, the security checker does not use the facilities in pyflow.
from .simple.core.manager import SecurityManager
from .simple.core.config import SecurityConfig
from .simple.core.issue import Issue, Cwe
from .bugfinder import StaticBugFinder, BugFinderConfig, BugInstance, Severity

__all__ = [
    "SecurityManager",
    "SecurityConfig",
    "Issue",
    "Cwe",
    "StaticBugFinder",
    "BugFinderConfig",
    "BugInstance",
    "Severity",
]

"""
Security checker and analysis-backed bug finder for PyFlow.

- simple: Lightweight AST/security checks (Bandit-style)
- bugfinder: Modular, analysis-backed engine leveraging PyFlow's IPA/CPA, store
  graph, shape, and lifetime analyses for taint/resource/escape detection.
"""
