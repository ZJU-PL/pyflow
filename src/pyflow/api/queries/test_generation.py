"""
Compatibility layer for task-oriented test generation queries.
"""

from ._models import FunctionTestProfile, TestScenario
from .tasks.test_generation import TestGenerationQueries

__all__ = ["TestGenerationQueries", "FunctionTestProfile", "TestScenario"]
