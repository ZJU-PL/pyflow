"""
Focused AST visitors for common pattern-detection tasks.

Provides small, single-responsibility visitors that answer specific
questions about an AST subtree without pulling in heavy analysis logic:

* Whether a function contains ``yield`` / ``yield from`` (generator).
* Whether a function contains ``return`` / bare ``return``.
* Whether a function contains ``assert`` statements.
"""

from __future__ import annotations

import ast

__all__ = [
    "YieldVisitor",
    "ReturnVisitor",
    "AssertVisitor",
    "contains_yield",
    "get_return_info",
    "contains_assert",
]


class YieldVisitor(ast.NodeVisitor):
    """Visitor that detects ``yield`` and ``yield from`` statements.

    By default it does **not** recurse into nested functions or classes,
    which is the correct behaviour when checking whether *this* function
    is itself a generator.
    """

    def __init__(self) -> None:
        self.found_yield: bool = False
        self.found_yield_from: bool = False

    def visit_Yield(self, node: ast.Yield) -> None:  # noqa: N802
        self.found_yield = True

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:  # noqa: N802
        self.found_yield_from = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        pass  # Don't recurse into nested functions.

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef
    ) -> None:
        pass

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        pass


class ReturnVisitor(ast.NodeVisitor):
    """Visitor that detects ``return`` statements.

    Also identifies bare (value-less) returns.
    Does **not** recurse into nested functions or classes.
    """

    def __init__(self) -> None:
        self.has_return: bool = False
        self.has_empty_return: bool = False

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        self.has_return = True
        if node.value is None:
            self.has_empty_return = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        pass

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef
    ) -> None:
        pass

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        pass


class AssertVisitor(ast.NodeVisitor):
    """Visitor that detects ``assert`` statements.

    Does **not** recurse into nested functions or classes.
    """

    def __init__(self) -> None:
        self.asserts: list[ast.Assert] = []

    def visit_Assert(self, node: ast.Assert) -> None:  # noqa: N802
        self.asserts.append(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        pass

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef
    ) -> None:
        pass

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        pass


# ---- High-level convenience helpers ---------------------------------------


def contains_yield(node: ast.AST) -> bool:
    """Check whether *node* (typically a function def) contains a yield expression.

    Does not descend into nested function/class bodies, so this determines
    whether the outer function is a generator.

    Args:
        node: The AST node to inspect (e.g. ``ast.FunctionDef``).

    Returns:
        ``True`` if a ``yield`` or ``yield from`` is found in the top-level body.
    """
    visitor = YieldVisitor()
    _visit_top_level(visitor, node)
    return visitor.found_yield or visitor.found_yield_from


def get_return_info(
    node: ast.AST,
) -> tuple[bool, bool]:
    """Return ``(has_return, has_empty_return)`` for *node*.

    Does not descend into nested function/class bodies.

    Args:
        node: The AST node to inspect.

    Returns:
        A 2-tuple ``(has_return, has_empty_return)``.
    """
    visitor = ReturnVisitor()
    _visit_top_level(visitor, node)
    return visitor.has_return, visitor.has_empty_return


def contains_assert(node: ast.AST) -> bool:
    """Check whether *node* contains ``assert`` statements.

    Does not descend into nested function/class bodies.

    Args:
        node: The AST node to inspect.

    Returns:
        ``True`` if an ``assert`` is found.
    """
    visitor = AssertVisitor()
    _visit_top_level(visitor, node)
    return len(visitor.asserts) > 0


# ---- Internal helpers -----------------------------------------------------


def _visit_top_level(visitor: ast.NodeVisitor, node: ast.AST) -> None:
    """Drive the visitor over the top-level statements of *node*.

    Handles ``ast.FunctionDef``, ``ast.AsyncFunctionDef``, and
    ``ast.Lambda`` specially by visiting their body/expression directly
    so that the visitor's ``visit_FunctionDef`` / ``visit_ClassDef``
    guards prevent descending into nested scopes.
    """
    if isinstance(node, ast.Lambda):
        visitor.visit(node.body)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for stmt in node.body:
            visitor.visit(stmt)
    else:
        visitor.visit(node)
