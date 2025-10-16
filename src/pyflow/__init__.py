"""PyFlow - Static Analysis Framework for Python.
"""

__version__ = "0.1.0"
__author__ = "rainoftime"
__email__ = "rainoftime@gmail.com"

# Import main components for easy access
from .application.program import Program
from .application.pipeline import Pipeline
from .application.context import Context

__all__ = [
    "Program",
    "Pipeline", 
    "Context",
    "__version__",
    "__author__",
    "__email__",
]
