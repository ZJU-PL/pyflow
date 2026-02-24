"""
Entry point declarations for PyFlow analysis.

This module provides data structures for declaring and representing
program entry points and class interfaces in the PyFlow analysis framework.

Classes:
    ClassDeclaration: Declares a class with its initialization, attributes, and methods.
    EntryPoint: Represents a callable entry point with argument information.
    InterfaceDeclaration: Aggregates function and class declarations into analyzable interfaces.
    ArgumentWrapper: Base class for argument wrappers.
    InstanceWrapper: Wrapper for type objects (for creating instances).
    ExistingWrapper: Wrapper for existing Python objects (constants, functions).
    NullWrapper: Wrapper representing a missing/null argument.
"""

from .declaration import ClassDeclaration, InterfaceDeclaration
from .entry_point import EntryPoint
from .wrappers import (
    ArgumentWrapper,
    ExistingWrapper,
    InstanceWrapper,
    NullWrapper,
    nullWrapper,
)

__all__ = [
    "ClassDeclaration",
    "InterfaceDeclaration",
    "EntryPoint",
    "ArgumentWrapper",
    "InstanceWrapper",
    "ExistingWrapper",
    "NullWrapper",
    "nullWrapper",
]
