"""Helpers for discovering module-scope imports in Python syntax."""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator


def iter_module_imports(
    statements: Iterable[ast.stmt],
) -> Iterator[ast.Import | ast.ImportFrom]:
    """Yield imports reachable at module scope.

    Imports used only for annotations are routinely placed under
    ``if TYPE_CHECKING:`` or conditional ``try`` blocks.  Annotation resolution
    needs those names even though they are not executed at runtime.  Nested
    function and class bodies are excluded: their imports have local scope.
    """

    for statement in statements:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            yield statement
        elif isinstance(statement, ast.If):
            yield from iter_module_imports(statement.body)
            yield from iter_module_imports(statement.orelse)
        elif isinstance(statement, ast.Try):
            yield from iter_module_imports(statement.body)
            for handler in statement.handlers:
                yield from iter_module_imports(handler.body)
            yield from iter_module_imports(statement.orelse)
            yield from iter_module_imports(statement.finalbody)
