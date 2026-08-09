"""Relational Python class-pollution analysis."""

from .analysis import (
    ClassPollutionAnalysisResult,
    ClassPollutionConfiguration,
    ClassPollutionFinding,
    ClassPollutionProblem,
    DEFAULT_OPERATIONS,
    ReflectiveOperationModel,
    ZERO_CLASS_POLLUTION,
    analyze_class_pollution,
)
from .api import run_class_pollution_analysis
from .domain import (
    ExpressionPollutionFact,
    GADGET_PATH_COMPONENTS,
    KeyLanguage,
    KeyLanguageKind,
    MAGIC_PATH_COMPONENTS,
    ObjectPathStep,
    PollutionFact,
    PollutionOrigin,
    PollutionRole,
)

__all__ = [
    "ClassPollutionAnalysisResult",
    "ClassPollutionConfiguration",
    "ClassPollutionFinding",
    "ClassPollutionProblem",
    "DEFAULT_OPERATIONS",
    "ExpressionPollutionFact",
    "GADGET_PATH_COMPONENTS",
    "KeyLanguage",
    "KeyLanguageKind",
    "MAGIC_PATH_COMPONENTS",
    "ObjectPathStep",
    "PollutionFact",
    "PollutionOrigin",
    "PollutionRole",
    "ReflectiveOperationModel",
    "ZERO_CLASS_POLLUTION",
    "analyze_class_pollution",
    "run_class_pollution_analysis",
]
