"""
Decorator detection and name extraction utilities for AST nodes.

Provides helpers for checking whether a function or method has specific
decorators and for extracting a canonical name string from a decorator
expression node.
"""

from __future__ import annotations

import ast
from typing import Iterable, Optional

__all__ = [
    "extract_decorator_name",
    "has_decorator",
]

ASTFunctionDef = ast.AsyncFunctionDef | ast.FunctionDef


def has_decorator(
    func: ASTFunctionDef,
    decorators: str | Iterable[str],
) -> bool:
    """Check whether a function node has one or more specific decorators.

    Performs a simple name-based match against ``decorator_list``.
    Supports both plain names (``@login_required``) and dotted names
    (``@auth.login_required``).

    Args:
        func: The function or async function AST node.
        decorators: A single decorator name or a collection of names.
            A match is found if *any* name in the collection matches.

    Returns:
        ``True`` if at least one of the requested decorators is present.
    """
    if isinstance(decorators, str):
        decorators = (decorators,)

    for decorator in func.decorator_list:
        name = extract_decorator_name(decorator)
        if name is not None and name in decorators:
            return True
    return False


def extract_decorator_name(expr: ast.expr) -> Optional[str]:
    """Extract a canonical string name from a decorator expression.

    Handles ``ast.Name`` (``@login_required`` → ``"login_required"``),
    ``ast.Attribute`` (``@auth.login_required`` → ``"auth.login_required"``),
    and returns ``None`` for complex expressions such as calls
    (``@login_required(role="admin")``).

    Args:
        expr: The decorator expression AST node.

    Returns:
        The extracted name string, or ``None`` if the expression does not
        correspond to a simple name or dotted name.
    """
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        if isinstance(expr.value, ast.Name):
            return f"{expr.value.id}.{expr.attr}"
        return expr.attr
    return None
