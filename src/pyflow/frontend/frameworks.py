"""Recognize declared HTTP and framework entry boundaries in source files."""

from __future__ import annotations

import ast
from collections.abc import Iterable
import warnings

from pyflow.language.modules.imports import base_name_from_expr
from pyflow.language.modules.workspace import iter_all_import_nodes
from pyflow.model.library_models import LibraryModelRegistry, default_library_models


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in iter_all_import_nodes(tree):
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


def framework_entry_functions(
    sources,
    *,
    entrypoint_kinds: Iterable[str] = ("http",),
    registry: LibraryModelRegistry | None = None,
):
    """Recognize framework entry handlers declared via the shared model registry."""
    models = registry or default_library_models()
    factories = models.factory_classes(entrypoint_kinds=entrypoint_kinds)
    routes = models.decorator_methods(entrypoint_kinds=entrypoint_kinds)
    hints = models.hint_tokens(entrypoint_kinds=entrypoint_kinds)
    # Also detect standalone entrypoint decorators (e.g. @click.command, @celery.shared_task).
    allowed_kinds = frozenset(entrypoint_kinds)
    standalone_decorators = frozenset(
        qname
        for dec in models.all_decorators()
        if dec.behavior == "entrypoint" and dec.entrypoint_kind in allowed_kinds
        for qname in dec.qualified_names
    )
    standalone_hints = tuple(dict.fromkeys(q.rsplit(".", 1)[-1] for q in standalone_decorators))
    all_hints = (*hints, *standalone_hints)

    entries = set()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        for filename, source in sources.items():
            # Any call resolving to a modeled factory/decorator must mention one of its tokens.
            if all_hints and not any(hint in source for hint in all_hints):
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

            def is_entry_decorator(decorator, apps):
                call = decorator.func if isinstance(decorator, ast.Call) else decorator
                if (
                    isinstance(call, ast.Attribute)
                    and call.attr in routes
                    and isinstance(call.value, ast.Name)
                    and call.value.id in apps
                ):
                    return True
                if standalone_decorators:
                    resolved = _resolve_factory_name(call, aliases)
                    if resolved in standalone_decorators:
                        return True
                return False

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
                        if any(is_entry_decorator(dec, apps) for dec in stmt.decorator_list):
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
                        if any(is_entry_decorator(dec, apps) for dec in stmt.decorator_list):
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


def http_entry_functions(sources):
    """Recognize HTTP handlers without treating arbitrary library APIs as inputs."""
    return framework_entry_functions(sources, entrypoint_kinds=("http",))
