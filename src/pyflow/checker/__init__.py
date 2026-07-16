# Security checker for pyflow
# NOTE: Current, the security checker does not use the facilities in pyflow.
from .pattern.core.manager import SecurityManager
from .pattern.core.config import SecurityConfig
from .pattern.core.issue import Issue, Cwe
from .quality import (
    BaselineStore,
    BareSuppressionWarning,
    GuardInfo,
    SuppressionDirective,
    apply_guard_aware_demotion,
    apply_taint_aware_demotion,
    confidence_level,
    find_security_guards,
    is_suppressed,
    is_guarded,
    issue_fingerprint,
    parse_suppressions,
    score_confidence,
)
from .semantic import StaticBugFinder, BugFinderConfig

__all__ = [
    "SecurityManager",
    "SecurityConfig",
    "Issue",
    "Cwe",
    "BaselineStore",
    "BareSuppressionWarning",
    "GuardInfo",
    "SuppressionDirective",
    "apply_guard_aware_demotion",
    "apply_taint_aware_demotion",
    "confidence_level",
    "find_security_guards",
    "is_guarded",
    "is_suppressed",
    "issue_fingerprint",
    "parse_suppressions",
    "score_confidence",
    "StaticBugFinder",
    "BugFinderConfig",
]

"""
Security checker and analysis-backed bug finder for PyFlow.

- pattern: Pattern-based AST matching for security checks (Bandit-style)
- semantic: Semantic analysis-backed engine leveraging PyFlow's IPA/CPA, store
  graph, shape, and lifetime analyses for taint/resource/escape detection.
"""
