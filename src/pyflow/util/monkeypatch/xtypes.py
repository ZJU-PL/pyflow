"""
Extended types module with additional type definitions.

This module provides type objects that are not directly available in Python's
standard types module but are needed for static analysis. These include
descriptor types, iterator types, and type categories used throughout pyflow
for type checking and stub generation.
"""

from types import *

# Extended "types"
# Includes some important types not available elsewhere.

# A descriptor that produces builtin methods.
# MethodDescriptorType represents descriptors for built-in methods like str.count
# These are different from regular method descriptors and need special handling
# in static analysis and stub generation.
MethodDescriptorType = type(str.__dict__["count"])

# Wraps a slot in a type object.
# WrapperDescriptorType represents descriptors that wrap C-level slot functions,
# such as __add__, __str__, etc. These are used for operator overloading and
# special methods in built-in types.
WrapperDescriptorType = type(str.__dict__["__add__"])


# Iterator types for different Python iterables
# These are used to identify and handle different iterator types in static analysis
TupleIteratorType = type(iter(()))
ListIteratorType = type(iter([]))
XRangeIteratorType = type(iter(range(1)))


# Types that require stub generation for static analysis
# These types have C-level implementations that need Python stubs to be analyzed
TypeNeedsStub = (MethodDescriptorType, WrapperDescriptorType, BuiltinFunctionType)

# Types that require hidden stubs (not exposed in public API)
# These are internal implementation details that still need stubs for analysis
TypeNeedsHiddenStub = (MethodDescriptorType, WrapperDescriptorType)


# Types that represent constant values in Python
# These are immutable types that can be treated as constants during analysis
# Used for constant folding and value propagation
ConstantTypes = set((str, int, float, type(None), bool, CodeType))
# Note: "NoneType" is not a valid type name in Python 3.8+, so we use type(None) instead.