"""Small, explicit factory return models for security call resolution.

These models establish receiver identity; a method name alone never does.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from typing import Mapping

CALL_RETURN_TYPES = {
    "sqlite3.connect": "sqlite3.Connection",
    "sqlite3.Connection": "sqlite3.Connection",
    "sqlite3.Connection.cursor": "sqlite3.Cursor",
    "sqlite3.Cursor": "sqlite3.Cursor",
    "psycopg2.connect": "psycopg2.connection",
    "psycopg2.connection.cursor": "psycopg2.cursor",
    "MySQLdb.connect": "MySQLdb.connection",
    "MySQLdb.connection.cursor": "MySQLdb.cursor",
    "pymysql.connect": "pymysql.Connection",
    "pymysql.Connection.cursor": "pymysql.cursor",
}


def ast_receiver_bindings(function: ast.AST, imports: Mapping[str, str]) -> dict[str, str]:
    """Resolve unambiguous local factories without guessing parameter types.

    Multiple writes and parameter shadowing deliberately invalidate a binding.
    Nested functions have independent locals and are not traversed.
    """
    writes: dict[str, list[ast.AST | None]] = defaultdict(list)

    def visit(node: ast.AST) -> None:
        if node is not function and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            if hasattr(node, "name"):
                writes[node.name].append(None)
            return
        if isinstance(node, ast.arg):
            writes[node.arg].append(None)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name):
                        writes[child.id].append(node.value if child is target else None)
            if node.value is not None:
                visit(node.value)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            writes[node.id].append(None)
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(function)
    bindings = {name: value for name, value in imports.items() if name not in writes}

    def resolve(expr: ast.AST | None, active: frozenset[str]) -> str | None:
        if isinstance(expr, ast.Name):
            if expr.id in bindings:
                return bindings[expr.id]
            values = writes.get(expr.id, ())
            if expr.id in active or len(values) != 1:
                return None
            return resolve(values[0], active | {expr.id})
        if isinstance(expr, ast.Attribute):
            base = resolve(expr.value, active)
            return f"{base}.{expr.attr}" if base else None
        if isinstance(expr, ast.Call):
            return CALL_RETURN_TYPES.get(resolve(expr.func, active) or "")
        return None

    for name in writes:
        value = resolve(ast.Name(id=name), frozenset())
        if value:
            bindings[name] = value
    return bindings
