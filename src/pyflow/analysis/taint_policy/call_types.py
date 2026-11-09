"""Small, explicit factory return models for security call resolution.

These models establish receiver identity; a method name alone never does.
"""

from __future__ import annotations

import ast
from collections import Counter, defaultdict
from typing import Mapping

CALL_RETURN_TYPES = {
    "pypika.functions.Cast": "pypika.terms.Term",
    "tarfile.open": "tarfile.TarFile",
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


def ast_factory_return_types(module: ast.Module, imports: Mapping[str, str]) -> dict[str, str]:
    """Infer simple local wrappers around known library factories.

    Only a single, final return is accepted. Other return paths and decorators
    can change the result and must not be used as receiver type evidence.
    """
    returns: dict[str, str] = {}
    definitions = [node for node in module.body if isinstance(node, ast.FunctionDef)]
    name_counts = Counter(node.name for node in definitions)
    for function in definitions:
        if name_counts[function.name] != 1 or function.decorator_list:
            continue
        if not function.body or not isinstance(function.body[-1], ast.Return):
            continue
        if any(
            isinstance(node, ast.Return)
            for statement in function.body[:-1]
            for node in ast.walk(statement)
        ):
            continue
        bindings = ast_receiver_bindings(function, imports)
        result = function.body[-1].value
        if isinstance(result, ast.Name):
            result_type = bindings.get(result.id)
        elif isinstance(result, ast.Call):

            def call_name(expression: ast.AST) -> str | None:
                if isinstance(expression, ast.Name):
                    return bindings.get(expression.id)
                if isinstance(expression, ast.Attribute):
                    base = call_name(expression.value)
                    return f"{base}.{expression.attr}" if base else None
                return None

            result_type = CALL_RETURN_TYPES.get(call_name(result.func) or "")
        else:
            result_type = None
        if result_type:
            returns[function.name] = result_type
    return returns


def ast_receiver_bindings(
    function: ast.AST,
    imports: Mapping[str, str],
    factory_returns: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Resolve unambiguous local factories without guessing parameter types.

    Multiple writes and parameter shadowing deliberately invalidate a binding.
    Nested functions have independent locals and are not traversed.
    """
    writes: dict[str, list[ast.AST | None]] = defaultdict(list)

    def bound_names(target: ast.AST):
        if isinstance(target, ast.Name):
            yield target.id
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                yield from bound_names(element)
        elif isinstance(target, ast.Starred):
            yield from bound_names(target.value)

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
                for name in bound_names(target):
                    writes[name].append(node.value if isinstance(target, ast.Name) else None)
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
            callee = resolve(expr.func, active)
            if callee is None and isinstance(expr.func, ast.Name) and expr.func.id not in writes:
                local_type = (factory_returns or {}).get(expr.func.id)
                if local_type is not None:
                    return local_type
            return CALL_RETURN_TYPES.get(callee or "")
        return None

    # An unbound library method call carries receiver type evidence for its
    # explicit first argument (e.g. TarFile.getnames(archive)).
    receiver_methods = {
        "tarfile.TarFile.getnames": "tarfile.TarFile",
        "tarfile.TarFile.getmembers": "tarfile.TarFile",
    }
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Name):
            receiver_type = receiver_methods.get(resolve(node.func, frozenset()) or "")
            name = node.args[0].id
            if receiver_type and writes.get(name) == [None]:
                bindings[name] = receiver_type

    for name in writes:
        value = resolve(ast.Name(id=name), frozenset())
        if value:
            bindings[name] = value
    return bindings
