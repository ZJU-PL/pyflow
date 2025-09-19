"""
PyFlow - A static compiler for Python

PyFlow is a static analysis and compilation tool for Python code.
It provides various analysis capabilities including control flow analysis,
data flow analysis, and optimization passes.

Copyright (c) 2007-2011 Nick Bray
Licensed under the Apache License, Version 2.0
"""

__version__ = "0.1.0"
__author__ = "Nick Bray"
__email__ = "ncbray@gmail.com"

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
