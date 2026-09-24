"""Pure lexical-scope discovery for Python AST conversion."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class _MutableScopeFacts:
    global_names: set[str] = field(default_factory=set)
    nonlocal_names: set[str] = field(default_factory=set)
    bound: set[str] = field(default_factory=set)
    loaded: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class FunctionBodyAnalysis:
    """Facts needed before converting one function body."""

    global_names: frozenset[str]
    nonlocal_names: frozenset[str]
    bound: frozenset[str]
    loaded: frozenset[str]
    descendant_global_names: frozenset[str]
    descendant_nonlocal_names: frozenset[str]
    child_capture_candidates: tuple[frozenset[str], ...]
    has_zero_arg_super: bool
    has_yield: bool

    def direct_child_captures(self, parent_bound: set[str]) -> set[str]:
        captures: set[str] = set()
        for candidates in self.child_capture_candidates:
            captures.update(candidates & parent_bound)
        return captures


def _argument_names(arguments: ast.arguments) -> set[str]:
    names = {
        argument.arg
        for argument in (
            *getattr(arguments, "posonlyargs", ()),
            *getattr(arguments, "args", ()),
            *getattr(arguments, "kwonlyargs", ()),
        )
    }
    if getattr(arguments, "vararg", None) is not None:
        names.add(arguments.vararg.arg)
    if getattr(arguments, "kwarg", None) is not None:
        names.add(arguments.kwarg.arg)
    return names


def analyze_function_body(body_nodes: Sequence[ast.AST]) -> FunctionBodyAnalysis:
    """Collect function pre-conversion facts in one recursive traversal.

    The legacy implementation independently walked a function for direct
    scope names, descendant directives, child captures, zero-argument
    ``super()``, and ``yield``.  This scanner retains those collectors'
    lexical-boundary behavior while visiting each relevant AST subtree once.
    """

    root = _MutableScopeFacts()
    direct_children: list[_MutableScopeFacts] = []
    descendant_global: set[str] = set()
    descendant_nonlocal: set[str] = set()
    has_zero_arg_super = False
    has_yield = False

    def zero_only(node: ast.AST | None) -> None:
        nonlocal has_zero_arg_super
        if node is None:
            return
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "super"
            and not node.args
            and not node.keywords
        ):
            has_zero_arg_super = True
        for child in ast.iter_child_nodes(node):
            zero_only(child)

    def scan_arguments_for_zero(arguments: ast.arguments) -> None:
        for argument in (
            *getattr(arguments, "posonlyargs", ()),
            *getattr(arguments, "args", ()),
            *getattr(arguments, "kwonlyargs", ()),
        ):
            zero_only(getattr(argument, "annotation", None))
        if getattr(arguments, "vararg", None) is not None:
            zero_only(getattr(arguments.vararg, "annotation", None))
        if getattr(arguments, "kwarg", None) is not None:
            zero_only(getattr(arguments.kwarg, "annotation", None))

    def scan_function(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        facts: _MutableScopeFacts | None,
        *,
        in_descendant: bool,
        allow_direct_child: bool,
    ) -> None:
        if facts is not None:
            facts.bound.add(node.name)
            # Defaults and decorators execute in the enclosing lexical scope.
            # The legacy direct-child collector deliberately does not descend
            # into these expressions, hence ``allow_direct_child=False``.
            for expression in (
                *node.decorator_list,
                *node.args.defaults,
                *(
                    default
                    for default in node.args.kw_defaults
                    if default is not None
                ),
            ):
                scan(
                    expression,
                    facts,
                    in_descendant=in_descendant,
                    allow_direct_child=False,
                    yield_enabled=False,
                )
        else:
            for expression in (
                *node.decorator_list,
                *node.args.defaults,
                *(
                    default
                    for default in node.args.kw_defaults
                    if default is not None
                ),
            ):
                zero_only(expression)

        scan_arguments_for_zero(node.args)
        zero_only(getattr(node, "returns", None))
        for type_param in getattr(node, "type_params", ()):
            zero_only(type_param)

        if facts is root and allow_direct_child:
            child_facts = _MutableScopeFacts()
            child_facts.bound.update(_argument_names(node.args))
            direct_children.append(child_facts)
        else:
            child_facts = None
        for statement in node.body:
            scan(
                statement,
                child_facts,
                in_descendant=True,
                allow_direct_child=False,
                yield_enabled=False,
            )

    def scan_class(
        node: ast.ClassDef,
        facts: _MutableScopeFacts | None,
        *,
        in_descendant: bool,
        yield_enabled: bool,
    ) -> None:
        if facts is not None:
            facts.bound.add(node.name)
            for expression in (
                *node.bases,
                *(keyword.value for keyword in node.keywords),
                *node.decorator_list,
            ):
                scan(
                    expression,
                    facts,
                    in_descendant=in_descendant,
                    allow_direct_child=False,
                    yield_enabled=yield_enabled,
                )
        else:
            for expression in (
                *node.bases,
                *(keyword.value for keyword in node.keywords),
                *node.decorator_list,
            ):
                zero_only(expression)
        for type_param in getattr(node, "type_params", ()):
            zero_only(type_param)
        # Class bodies are opaque to lexical scope/capture discovery, but the
        # previous super() probe walked them recursively.
        for statement in node.body:
            zero_only(statement)

    def scan(
        node: ast.AST | None,
        facts: _MutableScopeFacts | None,
        *,
        in_descendant: bool,
        allow_direct_child: bool,
        yield_enabled: bool,
    ) -> None:
        nonlocal has_zero_arg_super, has_yield
        if node is None:
            return
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "super"
            and not node.args
            and not node.keywords
        ):
            has_zero_arg_super = True
        if yield_enabled and isinstance(node, (ast.Yield, ast.YieldFrom)):
            has_yield = True

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scan_function(
                node,
                facts,
                in_descendant=in_descendant,
                allow_direct_child=allow_direct_child,
            )
            return
        if isinstance(node, ast.ClassDef):
            scan_class(
                node,
                facts,
                in_descendant=in_descendant,
                yield_enabled=yield_enabled,
            )
            return
        if isinstance(node, ast.Lambda):
            # Lambda defaults/annotations are ignored by the old lexical
            # collectors but remain visible to the broad super() probe.
            for default in (*node.args.defaults, *node.args.kw_defaults):
                zero_only(default)
            scan_arguments_for_zero(node.args)
            if facts is root and allow_direct_child:
                child_facts = _MutableScopeFacts()
                child_facts.bound.update(_argument_names(node.args))
                direct_children.append(child_facts)
                scan(
                    node.body,
                    child_facts,
                    in_descendant=in_descendant,
                    allow_direct_child=False,
                    yield_enabled=False,
                )
            else:
                zero_only(node.body)
            return

        if isinstance(node, ast.Global):
            if facts is not None:
                facts.global_names.update(node.names)
            if in_descendant:
                descendant_global.update(node.names)
            return
        if isinstance(node, ast.Nonlocal):
            if facts is not None:
                facts.nonlocal_names.update(node.names)
            if in_descendant:
                descendant_nonlocal.update(node.names)
            return
        if isinstance(node, ast.Name) and facts is not None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                facts.bound.add(node.id)
            else:
                facts.loaded.add(node.id)
            return
        if isinstance(node, ast.Import) and facts is not None:
            for alias in node.names:
                facts.bound.add(alias.asname or alias.name.split(".")[0])
            return
        if isinstance(node, ast.ImportFrom) and facts is not None:
            for alias in node.names:
                if alias.name != "*":
                    facts.bound.add(alias.asname or alias.name)
            return
        if isinstance(node, ast.ExceptHandler) and facts is not None and node.name:
            facts.bound.add(node.name)
        if isinstance(node, ast.MatchAs) and facts is not None and node.name:
            facts.bound.add(node.name)
        if isinstance(node, ast.MatchStar) and facts is not None and node.name:
            facts.bound.add(node.name)
        if isinstance(node, ast.MatchMapping) and facts is not None and node.rest:
            facts.bound.add(node.rest)

        for child in ast.iter_child_nodes(node):
            scan(
                child,
                facts,
                in_descendant=in_descendant,
                allow_direct_child=allow_direct_child,
                yield_enabled=yield_enabled,
            )

    for statement in body_nodes:
        scan(
            statement,
            root,
            in_descendant=False,
            allow_direct_child=True,
            yield_enabled=True,
        )

    child_candidates = []
    for child in direct_children:
        candidates = (
            child.loaded - child.bound - child.global_names
        ) | child.nonlocal_names
        child_candidates.append(frozenset(candidates))
    return FunctionBodyAnalysis(
        frozenset(root.global_names),
        frozenset(root.nonlocal_names),
        frozenset(root.bound),
        frozenset(root.loaded),
        frozenset(descendant_global),
        frozenset(descendant_nonlocal),
        tuple(child_candidates),
        has_zero_arg_super,
        has_yield,
    )


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


def collect_function_scope(
    body_nodes: Sequence[ast.AST],
) -> tuple[set[str], set[str], set[str], set[str]]:
    """Collect direct scope directives and names in a single traversal.

    This is the combined equivalent of running ``collect_direct_scope_directives``
    and ``collect_scope_names`` over the same ``body_nodes``.  The two collectors
    share the same traversal scope (top-level statements of one lexical scope,
    stopping at nested function/class/lambda bodies) and neither can observe
    ``global``/``nonlocal`` directives inside the expression-only regions the
    other visits (decorators, defaults, bases, keywords), so merging them is
    result-identical.

    Returns ``(global_names, nonlocal_names, bound, loaded)``.
    """

    global_names: set[str] = set()
    nonlocal_names: set[str] = set()
    bound: set[str] = set()
    loaded: set[str] = set()

    class ScopeVisitor(ast.NodeVisitor):
        def visit_Global(self, node: ast.Global) -> None:
            global_names.update(node.names)

        def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
            nonlocal_names.update(node.names)

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

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.name:
                bound.add(node.name)
            if node.type is not None:
                self.visit(node.type)
            for statement in node.body:
                self.visit(statement)

        def visit_MatchAs(self, node: ast.MatchAs) -> None:
            if node.name:
                bound.add(node.name)
            if node.pattern is not None:
                self.visit(node.pattern)

        def visit_MatchStar(self, node: ast.MatchStar) -> None:
            if node.name:
                bound.add(node.name)

        def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
            if node.rest:
                bound.add(node.rest)
            for key in node.keys:
                self.visit(key)
            for pattern in node.patterns:
                self.visit(pattern)

    visitor = ScopeVisitor()
    for statement in body_nodes:
        visitor.visit(statement)
    return global_names, nonlocal_names, bound, loaded


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

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.name:
                bound.add(node.name)
            if node.type is not None:
                self.visit(node.type)
            for statement in node.body:
                self.visit(statement)

        def visit_MatchAs(self, node: ast.MatchAs) -> None:
            if node.name:
                bound.add(node.name)
            if node.pattern is not None:
                self.visit(node.pattern)

        def visit_MatchStar(self, node: ast.MatchStar) -> None:
            if node.name:
                bound.add(node.name)

        def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
            if node.rest:
                bound.add(node.rest)
            for key in node.keys:
                self.visit(key)
            for pattern in node.patterns:
                self.visit(pattern)

    visitor = ScopeVisitor()
    for statement in body_nodes:
        visitor.visit(statement)
    return bound, loaded


def direct_child_captures(
    body_nodes: Sequence[ast.AST],
    parent_bound: set[str],
    *,
    scope_names: Callable[
        [Sequence[ast.AST]], tuple[set[str], set[str]]
    ] = collect_scope_names,
    scope_directives: Callable[
        [Sequence[ast.AST]], tuple[set[str], set[str]]
    ] = collect_direct_scope_directives,
) -> set[str]:
    """Find parent bindings captured by direct child functions."""

    captures: set[str] = set()

    class ChildVisitor(ast.NodeVisitor):
        def _visit_function(self, node) -> None:
            child_bound, child_loaded = scope_names(node.body)
            child_globals, child_nonlocals = scope_directives(node.body)
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
            child_bound, child_loaded = scope_names([node.body])
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
            captures.update((child_loaded - child_bound) & parent_bound)

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


def body_contains_zero_arg_super(body_nodes: Sequence[ast.AST]) -> bool:
    """Return True if any ``super()`` call with no arguments appears in ``body_nodes``.

    Equivalent to ``any(... for statement in body_nodes for candidate in
    ast.walk(statement))`` but performs a single breadth-first walk over the
    whole body instead of one walk per statement.
    """
    from collections import deque

    queue = deque(body_nodes)
    while queue:
        candidate = queue.popleft()
        if (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Name)
            and candidate.func.id == "super"
            and not candidate.args
            and not candidate.keywords
        ):
            return True
        queue.extend(ast.iter_child_nodes(candidate))
    return False


__all__ = [
    "FunctionBodyAnalysis",
    "analyze_function_body",
    "body_contains_zero_arg_super",
    "collect_descendant_scope_directives",
    "collect_direct_scope_directives",
    "collect_function_scope",
    "collect_scope_names",
    "direct_child_captures",
]
