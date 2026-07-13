"""
AST tools package for PyFlow.

This package provides utilities for working with AST nodes, including
annotations, pretty printing, origin tracking, symbolic rewriting,
decorator detection, and focused AST visitors.
"""

from .annotation import Annotation
from . import astpprint
from .complexity import mccabe_complexity
from .decorators import extract_decorator_name, has_decorator
from .visitors import (
    AssertVisitor,
    ReturnVisitor,
    YieldVisitor,
    contains_assert,
    contains_yield,
    get_return_info,
)

__all__ = [
    "Annotation",
    "AssertVisitor",
    "ReturnVisitor",
    "YieldVisitor",
    "astpprint",
    "contains_assert",
    "contains_yield",
    "extract_decorator_name",
    "get_return_info",
    "has_decorator",
    "mccabe_complexity",
]
