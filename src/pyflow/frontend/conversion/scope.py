"""Pure lexical-scope discovery for Python AST conversion."""

from __future__ import annotations

import ast
from collections.abc import Sequence


def collect_direct_scope_directives(
    body_nodes: Sequence[ast.AST],
) -> tuple[set[str], set[str]]:
    global_names: set[str] = set()
    nonlocal_names: set[str] = set()

    class DirectiveVisitor(ast.NodeVisitor):
        def visit_Global(self, node: ast.Global) -> None:
            global_names.update(node.names)

        def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
            nonlocal_names.update(node.names)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

    visitor = DirectiveVisitor()
    for statement in body_nodes:
        visitor.visit(statement)
    return global_names, nonlocal_names


def collect_scope_names(
    body_nodes: Sequence[ast.AST],
) -> tuple[set[str], set[str]]:
    """Collect names bound and loaded directly in one lexical scope."""

    bound: set[str] = set()
    loaded: set[str] = set()

    class ScopeVisitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                bound.add(node.id)
            else:
                loaded.add(node.id)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            bound.add(node.name)
            for decorator in node.decorator_list:
                self.visit(decorator)
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self.visit(default)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            bound.add(node.name)
            for base in node.bases:
                self.visit(base)
            for keyword in node.keywords:
                self.visit(keyword.value)
            for decorator in node.decorator_list:
                self.visit(decorator)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                bound.add(alias.asname or alias.name.split(".")[0])

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            for alias in node.names:
                if alias.name != "*":
                    bound.add(alias.asname or alias.name)

    visitor = ScopeVisitor()
    for statement in body_nodes:
        visitor.visit(statement)
    return bound, loaded


def direct_child_captures(
    body_nodes: Sequence[ast.AST],
    parent_bound: set[str],
) -> set[str]:
    """Find parent bindings captured by direct child functions."""

    captures: set[str] = set()

    class ChildVisitor(ast.NodeVisitor):
        def _visit_function(self, node) -> None:
            child_bound, child_loaded = collect_scope_names(list(node.body))
            child_globals, child_nonlocals = collect_direct_scope_directives(
                list(node.body)
            )
            child_bound.update(
                argument.arg
                for argument in (
                    *getattr(node.args, "posonlyargs", ()),
                    *getattr(node.args, "args", ()),
                    *getattr(node.args, "kwonlyargs", ()),
                )
            )
            if getattr(node.args, "vararg", None) is not None:
                child_bound.add(node.args.vararg.arg)
            if getattr(node.args, "kwarg", None) is not None:
                child_bound.add(node.args.kwarg.arg)
            candidates = (child_loaded - child_bound - child_globals) | child_nonlocals
            captures.update(candidates & parent_bound)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

    visitor = ChildVisitor()
    for statement in body_nodes:
        visitor.visit(statement)
    return captures


def collect_descendant_scope_directives(
    body_nodes: Sequence[ast.AST],
) -> tuple[set[str], set[str]]:
    """Collect global/nonlocal directives declared in descendant functions."""

    global_names: set[str] = set()
    nonlocal_names: set[str] = set()

    def walk(nodes: Sequence[ast.AST]) -> None:
        for statement in nodes:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                direct_global, direct_nonlocal = collect_direct_scope_directives(
                    list(statement.body)
                )
                global_names.update(direct_global)
                nonlocal_names.update(direct_nonlocal)
                walk(list(statement.body))
                continue
            if isinstance(
                statement,
                (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith),
            ):
                walk(list(getattr(statement, "body", ()) or ()))
                walk(list(getattr(statement, "orelse", ()) or ()))
                continue
            if isinstance(statement, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                walk(list(getattr(statement, "body", ()) or ()))
                for handler in getattr(statement, "handlers", ()) or ():
                    walk(list(getattr(handler, "body", ()) or ()))
                walk(list(getattr(statement, "orelse", ()) or ()))
                walk(list(getattr(statement, "finalbody", ()) or ()))
                continue
            if hasattr(ast, "Match") and isinstance(statement, ast.Match):
                for case in getattr(statement, "cases", ()) or ():
                    walk(list(getattr(case, "body", ()) or ()))

    walk(body_nodes)
    return global_names, nonlocal_names


__all__ = [
    "collect_descendant_scope_directives",
    "collect_direct_scope_directives",
    "collect_scope_names",
    "direct_child_captures",
]
