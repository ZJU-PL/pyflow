"""
Stub generation system for pyflow static analysis.

This package provides a comprehensive stub generation system that creates
Python function stubs for built-in operations, standard library functions,
and C extension functions that cannot be directly analyzed. Stubs enable
static analysis of code that uses these operations by providing abstract
representations of their behavior.

The stub system consists of:
- StubCollector: Main class for collecting and registering stubs
- LLTranslator: Translates low-level operations to pyflow AST
- std/: Standard library stub generators for various modules

Stubs are used throughout pyflow to:
- Analyze built-in operations (arithmetic, comparisons, etc.)
- Handle standard library functions (math, os, json, etc.)
- Support constant folding and static evaluation
- Provide abstract models for C extension functions

Key concepts:
- Low-level functions: Operations that manipulate objects at a low level
- Interpreter functions: Functions that implement Python semantics
- Primitive functions: Functions that are treated as atomic operations
- Descriptive functions: Functions with detailed behavior descriptions
"""

from __future__ import absolute_import

from . import std
from . import stubcollector

# Main entry point for stub generation
makeStubs = stubcollector.makeStubs
