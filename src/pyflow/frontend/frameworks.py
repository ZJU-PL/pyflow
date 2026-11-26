"""Recognize declared HTTP request boundaries in source files."""

import ast
import warnings

from pyflow.language.modules.imports import base_name_from_expr

_FRAMEWORK_HINTS = ("Flask", "Blueprint", "Quart", "FastAPI", "APIRouter")


def _import_aliases(tree):
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def http_entry_functions(sources):
    """Recognize HTTP handlers without treating arbitrary library APIs as inputs."""
    factories = {
        "flask.Flask",
        "flask.Blueprint",
        "quart.Quart",
        "quart.Blueprint",
        "fastapi.FastAPI",
        "fastapi.APIRouter",
    }
    routes = {"route", "get", "post", "put", "delete", "patch", "options", "head", "websocket"}
    entries = set()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        for filename, source in sources.items():
            # Any call resolving to one of the known factory classes must mention
            # the class name either in an import or directly in the call expression.
            if not any(hint in source for hint in _FRAMEWORK_HINTS):
                continue
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            aliases = _import_aliases(tree)
            applications = set()
            for statement in tree.body:
                if not isinstance(statement, ast.Assign):
                    continue
                targets = {
                    target.id for target in statement.targets if isinstance(target, ast.Name)
                }
                applications.difference_update(targets)
                if not isinstance(statement.value, ast.Call):
                    continue
                spelling = base_name_from_expr(statement.value.func)
                if not spelling:
                    continue
                head, sep, tail = spelling.partition(".")
                qualified = aliases.get(head, head) + (sep + tail if sep else "")
                if qualified in factories:
                    applications.update(targets)

            if not applications:
                continue

            def visit(node, parents=()):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    parents = (*parents, node.name)
                    for decorator in getattr(node, "decorator_list", ()):
                        call = decorator.func if isinstance(decorator, ast.Call) else decorator
                        if (
                            isinstance(call, ast.Attribute)
                            and call.attr in routes
                            and isinstance(call.value, ast.Name)
                            and call.value.id in applications
                        ):
                            entries.add((filename, ".".join(parents)))
                for child in ast.iter_child_nodes(node):
                    visit(child, parents)

            visit(tree)
    return entries
