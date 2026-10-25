"""Recognize declared HTTP request boundaries in source files."""

import ast


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
    for filename, source in sources.items():
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        aliases = _import_aliases(tree)
        applications = set()
        for statement in tree.body:
            if not isinstance(statement, ast.Assign):
                continue
            targets = {target.id for target in statement.targets if isinstance(target, ast.Name)}
            applications.difference_update(targets)
            if not isinstance(statement.value, ast.Call):
                continue
            spelling = ast.unparse(statement.value.func)
            head, sep, tail = spelling.partition(".")
            qualified = aliases.get(head, head) + (sep + tail if sep else "")
            if qualified in factories:
                applications.update(targets)

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
