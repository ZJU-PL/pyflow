"""Issue types for the analysis-backed bug finder.

This module re-exports the common Issue and Cwe classes from pattern checker
to ensure semantic checker uses the same bug reporting format.
"""

# Re-export pattern checker's Issue and Cwe classes for consistency
from ..pattern.core.issue import Cwe, Issue

__all__ = ["Issue", "Cwe"]
