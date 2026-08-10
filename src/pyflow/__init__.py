"""PyFlow - Static Analysis Framework for Python."""

__version__ = "0.1.1"
__author__ = "rainoftime"
__email__ = "rainoftime@gmail.com"

# Import main components for easy access
from .application.program import Program
from .application.pipeline import Pipeline
from .application.context import Context
from .api.queries import IpaFunctionSummary, QueryComponents, create_query_components

__all__ = [
    "Program",
    "Pipeline",
    "Context",
    "QueryComponents",
    "create_query_components",
    "IpaFunctionSummary",
    "__version__",
    "__author__",
    "__email__",
]
