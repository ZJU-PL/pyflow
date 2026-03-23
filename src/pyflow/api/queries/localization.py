"""
Compatibility layer for task-oriented localization queries.
"""

from ._models import LocalizationCandidate, ProgramSlice
from .tasks.code_localization import LocalizationQueries

__all__ = ["LocalizationQueries", "LocalizationCandidate", "ProgramSlice"]
