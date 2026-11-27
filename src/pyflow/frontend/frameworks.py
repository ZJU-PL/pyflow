"""Recognize declared HTTP request boundaries in source files."""

import ast
import warnings

from pyflow.language.modules.imports import base_name_from_expr

_FRAMEWORK_HINTS = ("Flask", "Blueprint", "Quart", "FastAPI", "APIRouter", "Starlette", "Router")


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


def _resolve_factory_name(expr, aliases):
    spelling = base_name_from_expr(expr)
    if not spelling:
        return None
    head, sep, tail = spelling.partition(".")
    return aliases.get(head, head) + (sep + tail if sep else "")


def http_entry_functions(sources):
    """Recognize HTTP handlers without treating arbitrary library APIs as inputs."""
    factories = {
        "flask.Flask",
        "flask.Blueprint",
        "flask.blueprints.Blueprint",
        "quart.Quart",
        "quart.Blueprint",
        "fastapi.FastAPI",
        "fastapi.APIRouter",
        "fastapi.routing.APIRouter",
        "starlette.applications.Starlette",
        "starlette.routing.Router",
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

            def is_factory_annotation(annotation):
                if annotation is None:
                    return False
                if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
                    head, sep, tail = annotation.value.partition(".")
                    qualified = aliases.get(head, head) + (sep + tail if sep else "")
                    return qualified in factories
                return _resolve_factory_name(annotation, aliases) in factories

            def update_applications(stmt, apps):
                if isinstance(stmt, ast.Assign):
                    targets = {t.id for t in stmt.targets if isinstance(t, ast.Name)}
                    apps.difference_update(targets)
                    if (
                        isinstance(stmt.value, ast.Call)
                        and _resolve_factory_name(stmt.value.func, aliases) in factories
                    ):
                        apps.update(targets)
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    target_name = stmt.target.id
                    apps.discard(target_name)
                    if (
                        isinstance(stmt.value, ast.Call)
                        and _resolve_factory_name(stmt.value.func, aliases) in factories
                    ) or is_factory_annotation(stmt.annotation):
                        apps.add(target_name)

            def scan_statements(stmts, inherited_apps, parents):
                # Copy inherited app bindings so local reassignments stay scoped
                # to the enclosing function/class while factory functions such as
                # ``def create_app(): app = Flask(__name__)`` are recognized.
                apps = set(inherited_apps)
                for stmt in stmts:
                    update_applications(stmt, apps)
                    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        func_parents = (*parents, stmt.name)
                        for decorator in stmt.decorator_list:
                            call = decorator.func if isinstance(decorator, ast.Call) else decorator
                            if (
                                isinstance(call, ast.Attribute)
                                and call.attr in routes
                                and isinstance(call.value, ast.Name)
                                and call.value.id in apps
                            ):
                                entries.add((filename, ".".join(func_parents)))
                        func_apps = set(apps)
                        for arg in (
                            *stmt.args.posonlyargs,
                            *stmt.args.args,
                            *stmt.args.kwonlyargs,
                        ):
                            if is_factory_annotation(arg.annotation):
                                func_apps.add(arg.arg)
                            else:
                                func_apps.discard(arg.arg)
                        scan_statements(stmt.body, func_apps, func_parents)
                    elif isinstance(stmt, ast.ClassDef):
                        class_parents = (*parents, stmt.name)
                        for decorator in stmt.decorator_list:
                            call = decorator.func if isinstance(decorator, ast.Call) else decorator
                            if (
                                isinstance(call, ast.Attribute)
                                and call.attr in routes
                                and isinstance(call.value, ast.Name)
                                and call.value.id in apps
                            ):
                                entries.add((filename, ".".join(class_parents)))
                        scan_statements(stmt.body, apps, class_parents)
                    elif isinstance(
                        stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)
                    ):
                        # Branch-level assignments (e.g. ``if cond: app = FastAPI()``)
                        # bind into the current scope in Python.
                        sub_apps = scan_statements(stmt.body, apps, parents)
                        apps.update(sub_apps)
                        orelse = getattr(stmt, "orelse", ())
                        if orelse:
                            apps.update(scan_statements(orelse, apps, parents))
                    elif isinstance(stmt, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                        apps.update(scan_statements(stmt.body, apps, parents))
                        for handler in stmt.handlers:
                            apps.update(scan_statements(handler.body, apps, parents))
                        if stmt.orelse:
                            apps.update(scan_statements(stmt.orelse, apps, parents))
                        if stmt.finalbody:
                            apps.update(scan_statements(stmt.finalbody, apps, parents))
                    elif hasattr(ast, "Match") and isinstance(stmt, ast.Match):
                        for case in stmt.cases:
                            apps.update(scan_statements(case.body, apps, parents))
                return apps

            scan_statements(tree.body, set(), ())
    return entries
