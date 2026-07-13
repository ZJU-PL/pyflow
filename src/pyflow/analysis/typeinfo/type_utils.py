"""Provides utilities when working with types.

Migrated from Pynguin (pynguin.utils.type_utils).
SPDX-FileCopyrightText: 2019–2026 Pynguin Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import enum
import inspect
import numbers
import types
import typing
from inspect import isclass
from typing import TYPE_CHECKING, Any

from typing_inspect import get_origin

from pyflow.util.orderedset import OrderedSet

if TYPE_CHECKING:
    from collections.abc import Callable

    from pyflow.analysis.typeinfo.typesystem import InferredSignature

PRIMITIVES = OrderedSet([int, str, bytes, bool, float, complex])
COLLECTIONS = OrderedSet([list, set, tuple, dict])
IGNORABLE_TYPES = OrderedSet(["builtins.generator", "builtins.async_generator"])


def is_primitive_type(typ: type | None) -> bool:
    """Check if the given type is a primitive.

    Args:
        typ: a given type

    Returns:
        Whether the type is a primitive type
    """
    return typ in PRIMITIVES


def is_collection_type(typ: type | None) -> bool:
    """Check if the given type is a collection type.

    Args:
        typ: a given type

    Returns:
        Whether the type is a collection type
    """
    return typ in COLLECTIONS or get_origin(typ) in COLLECTIONS


def is_ignorable_type(typ: type) -> bool:
    """Check if the given type is ignorable.

    These are types that are exposed as a runtime type, although they are not
    directly usable.

    Args:
        typ: a given type

    Returns:
        Whether the type is ignorable
    """
    return f"{typ.__module__}.{typ.__name__}" in IGNORABLE_TYPES


def is_none_type(typ: type | None) -> bool:
    """Is the given type NoneType?

    Args:
        typ: a type to check

    Returns:
        Whether or not the given type is NoneType
    """
    return typ is type(None)


def is_numeric(value: Any) -> bool:
    """Check if the given value is numeric.

    Args:
        value: an arbitrary value

    Returns:
        Whether or not the given value is numeric
    """
    return isinstance(value, numbers.Number)


def is_string(value: Any) -> bool:
    """Check if the given value is a string.

    Args:
        value: an arbitrary value

    Returns:
        Whether or not the given value is a string
    """
    return isinstance(value, str)


def is_bytes(value: Any) -> bool:
    """Check if the given value is a bytes or bytearray.

    Args:
        value: an arbitrary value

    Returns:
        Whether or not the given value is of type bytes or bytearray
    """
    return isinstance(value, bytes | bytearray)


def is_list(typ: type) -> bool:
    """Check if the given value is a list.

    Args:
        typ: a type

    Returns:
        Whether the given value is of type list.
    """
    return typ is list


def is_set(typ: type) -> bool:
    """Check if the given value is a set.

    Args:
        typ: a type

    Returns:
        Whether the given value is of type set.
    """
    return typ is set


def is_dict(typ: type) -> bool:
    """Check if the given value is a dict.

    Args:
        typ: a type

    Returns:
        Whether the given value is of type dict.
    """
    return typ is dict


def is_tuple(typ: type) -> bool:
    """Check if the given value is a tuple.

    Args:
        typ: a type

    Returns:
        Whether the given value is of type tuple.
    """
    return typ is tuple


def is_enum(value: Any) -> bool:
    """Check if the given value is an enum.

    Args:
        value: an arbitrary value

    Returns:
        Whether the given value is of type enum.
    """
    return issubclass(value, enum.Enum)


def is_assertable(obj: Any, recursion_depth: int = 0) -> bool:
    """Returns whether we can generate an assertion using an exact comparison value.

    Args:
        obj: The object to check for assertability.
        recursion_depth: Avoid endless recursion for nested structures.

    Returns:
        True, if we can assert on the given value.
    """
    if recursion_depth > 4:
        return False
    if isinstance(obj, float):
        return False

    tp_ = type(obj)
    if is_enum(tp_) or is_primitive_type(tp_) or is_none_type(tp_):
        return True
    if is_set(tp_) or is_list(tp_) or is_tuple(tp_):
        return all(is_assertable(elem, recursion_depth + 1) for elem in obj)
    if is_dict(tp_):
        return all(
            is_assertable(key, recursion_depth + 1)
            and is_assertable(value, recursion_depth + 1)
            for key, value in obj.items()
        )
    return False


def get_class_that_defined_method(method: object) -> object | None:
    """Retrieves the class that defines a method.

    Taken from https://stackoverflow.com/a/25959545/4293396

    Args:
        method: The method

    Returns:
        The class that defines the method
    """
    if inspect.ismethod(method):
        assert isinstance(method, types.MethodType)
        for cls in inspect.getmro(method.__self__.__class__):
            if cls.__dict__.get(method.__name__) is method:
                return cls
        method = method.__func__
    if inspect.isfunction(method):
        assert isinstance(method, types.FunctionType)
        module = inspect.getmodule(method)
        attribute_name = method.__qualname__.split(".<locals>", 1)[0].rsplit(".", 1)[0]
        if not hasattr(module, attribute_name):
            return None
        cls = getattr(module, attribute_name)
        if isinstance(cls, type):
            return cls
    return getattr(method, "__objclass__", None)


def get_method_for_signature(method: Callable) -> Callable:
    """Get the object of the given method if it is a non-Python __init__ method.

    Args:
         method: The method to check.

    Returns:
        The original method if it is not a non-Python __init__ method, otherwise the
        object of the __init__ method.
    """
    method_for_signature = method
    if method_for_signature.__name__.startswith("__init__"):
        clazz = get_class_that_defined_method(method_for_signature)
        is_python = True
        try:
            inspect.getsource(method_for_signature)
        except Exception:
            is_python = False
        if not is_python:
            method_for_signature = clazz
    return method_for_signature


def is_optional_parameter(inf_sig: InferredSignature, parameter_name: str) -> bool:
    """Returns, whether a parameter is optional.

    Args:
        inf_sig: the inferred signature
        parameter_name: the name of the parameter

    Returns:
        Whether or not this parameter is optional.
    """
    parameter: inspect.Parameter = inf_sig.signature.parameters[parameter_name]
    return (
        parameter.kind == inspect.Parameter.VAR_POSITIONAL
        or parameter.kind == inspect.Parameter.VAR_KEYWORD
        or parameter.default is not inspect.Parameter.empty
    )


def is_arg_or_kwarg(inf_sig: InferredSignature, parameter_name: str) -> bool:
    """Returns, whether a parameter is *args or **kwarg.

    Args:
        inf_sig: the inferred signature
        parameter_name: the name of the parameter

    Returns:
        Whether this parameter is *arg or **kwarg.
    """
    parameter: inspect.Parameter = inf_sig.signature.parameters[parameter_name]
    return (
        parameter.kind == inspect.Parameter.VAR_POSITIONAL
        or parameter.kind == inspect.Parameter.VAR_KEYWORD
    )


def given_exception_matches(err, exc) -> bool:
    """Returns whether a raised exception matches an exception class.

    Args:
        err: The raised exception
        exc: The matching exception class

    Returns:
        True, iff the exception matches.
    """
    if err is None or exc is None:
        return False
    if not isclass(err):
        err = type(err)
    return issubclass(err, exc)


def string_distance(string1: str, string2: str) -> float:
    """Returns the distance between two strings.

    Args:
        string1: first string
        string2: second string

    Returns:
        A normalised distance in [0,1].
    """
    if string1 == string2:
        return 0.0

    min_length = min(len(string1), len(string2))
    max_length = max(len(string1), len(string2))
    differences: float = max_length - min_length

    for pos in range(min_length):
        if string1[pos] != string2[pos]:
            difference = abs(ord(string1[pos]) - ord(string2[pos]))
            differences += difference / (difference + 1.0)

    return differences


def string_lt_distance(string1: str, string2: str) -> int:
    """Returns the strict ordered distance between two strings."""
    if string1 < string2:
        return 0

    min_length = min(len(string1), len(string2))

    for pos in range(min_length):
        if string1[pos] > string2[pos]:
            return ord(string1[pos]) - ord(string2[pos]) + 1

    return 1


def string_le_distance(string1: str, string2: str) -> int:
    """Returns the ordered distance between two strings."""
    if string1 <= string2:
        return 0

    min_length = min(len(string1), len(string2))

    for pos in range(min_length):
        if string1[pos] > string2[pos]:
            return ord(string1[pos]) - ord(string2[pos])

    return 1
