"""Conservative exception-name reasoning shared by CFG consumers."""

import builtins

from . import ast


def exception_type_names(expression):
    if isinstance(expression, ast.Local) and expression.name:
        return (expression.name,)
    if isinstance(expression, ast.GetGlobal):
        return exception_type_names(expression.name)
    if isinstance(expression, ast.Existing):
        value = getattr(expression.object, "pyobj", None)
        if isinstance(value, str):
            return (value,)
        values = value if isinstance(value, tuple) else (value,)
        return tuple(
            item.__name__
            for item in values
            if isinstance(item, type) and issubclass(item, BaseException)
        )
    if isinstance(expression, ast.BuildTuple):
        return tuple(name for item in expression.args for name in exception_type_names(item))
    return ()


def exception_matches(raised, handled):
    """Return True/False for known relationships, None for unknown classes."""
    raised_leaf, handled_leaf = raised.rsplit(".", 1)[-1], handled.rsplit(".", 1)[-1]
    if raised_leaf == handled_leaf:
        return True
    raised_type = getattr(builtins, raised_leaf, None)
    handled_type = getattr(builtins, handled_leaf, None)
    if (
        isinstance(raised_type, type)
        and isinstance(handled_type, type)
        and issubclass(raised_type, BaseException)
        and issubclass(handled_type, BaseException)
    ):
        return issubclass(raised_type, handled_type)
    return None


def handler_match(raised_types, handler_type):
    handled_types = exception_type_names(handler_type)
    if not raised_types or not handled_types:
        return None
    results = [
        exception_matches(raised, handled) for raised in raised_types for handled in handled_types
    ]
    if all(result is False for result in results):
        return False
    if all(
        any(exception_matches(raised, handled) is True for handled in handled_types)
        for raised in raised_types
    ):
        return True
    return None
