"""Control-flow metadata and suspension discovery for resumable execution."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Iterable

from .runtime import FunctionNode


@dataclass(frozen=True)
class _SuspensionPoint:
    value: Any
    node: ast.AST
    kind: str = "yield"


@dataclass(frozen=True)
class _ResumableCFGPoint:
    identifier: int
    line: int
    kind: str


@dataclass(frozen=True)
class _ResumableCFG:
    """Control-flow graph used to identify and resume suspension points."""

    points: tuple[_ResumableCFGPoint, ...]
    edges: tuple[tuple[int, int, str], ...]
    entry: int
    exit: int
    node_points: dict[int, int]

    @classmethod
    def from_function(
        cls, function: FunctionNode | ast.GeneratorExp
    ) -> "_ResumableCFG":
        return _ResumableCFGBuilder().build(function)

    def point_for(self, node: ast.AST) -> int | None:
        return self.node_points.get(id(node))


class _ResumableCFGBuilder:
    def __init__(self) -> None:
        self.points: list[_ResumableCFGPoint] = []
        self.edges: list[tuple[int, int, str]] = []
        self.node_points: dict[int, int] = {}

    def _point(self, node: ast.AST | None, kind: str) -> int:
        identifier = len(self.points)
        self.points.append(
            _ResumableCFGPoint(
                identifier,
                getattr(node, "lineno", 0) if node is not None else 0,
                kind,
            )
        )
        if node is not None:
            self.node_points[id(node)] = identifier
        return identifier

    def build(self, function: FunctionNode | ast.GeneratorExp) -> _ResumableCFG:
        entry = self._point(function, "entry")
        exit_point = self._point(None, "exit")
        if isinstance(function, ast.GeneratorExp):
            body_entry = self._point(function, "generator_expression")
            self.edges.extend(
                ((entry, body_entry, "normal"), (body_entry, exit_point, "exhausted"))
            )
        else:
            body_entry = self._block(function.body, exit_point)
            self.edges.append((entry, body_entry, "normal"))
        return _ResumableCFG(
            tuple(self.points),
            tuple(self.edges),
            entry,
            exit_point,
            dict(self.node_points),
        )

    def _block(self, statements: Iterable[ast.stmt], successor: int) -> int:
        next_point = successor
        for statement in reversed(tuple(statements)):
            next_point = self._statement(statement, next_point)
        return next_point

    def _statement(self, statement: ast.stmt, successor: int) -> int:
        point = self._point(statement, type(statement).__name__)
        suspensions = [
            node
            for node in ast.walk(statement)
            if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await))
        ]
        for suspension in suspensions:
            suspension_point = self._point(suspension, type(suspension).__name__)
            self.edges.append((point, suspension_point, "suspend"))
            self.edges.append((suspension_point, successor, "resume"))
        if isinstance(statement, ast.If):
            body = self._block(statement.body, successor)
            orelse = self._block(statement.orelse, successor)
            self.edges.extend(((point, body, "true"), (point, orelse, "false")))
        elif isinstance(statement, (ast.While, ast.For, ast.AsyncFor)):
            body = self._block(statement.body, point)
            orelse = self._block(statement.orelse, successor)
            self.edges.extend(((point, body, "body"), (point, orelse, "exit")))
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            body = self._block(statement.body, successor)
            self.edges.append((point, body, "enter"))
        elif isinstance(statement, ast.Try) or (
            hasattr(ast, "TryStar") and isinstance(statement, ast.TryStar)
        ):
            final_entry = self._block(statement.finalbody, successor)
            normal_entry = self._block(statement.orelse, final_entry)
            body = self._block(statement.body, normal_entry)
            self.edges.append((point, body, "try"))
            for index, handler in enumerate(statement.handlers):
                handler_entry = self._block(handler.body, final_entry)
                self.edges.append((point, handler_entry, f"except:{index}"))
        elif isinstance(statement, ast.Match):
            for index, case in enumerate(statement.cases):
                case_entry = self._block(case.body, successor)
                self.edges.append((point, case_entry, f"case:{index}"))
            self.edges.append((point, successor, "no_match"))
        elif not suspensions:
            self.edges.append((point, successor, "normal"))
        return point


class _SuspensionFinder(ast.NodeVisitor):
    found = False

    def visit_Yield(self, node: ast.Yield) -> None:  # noqa: N802
        self.found = True

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:  # noqa: N802
        self.found = True

    def visit_Await(self, node: ast.Await) -> None:  # noqa: N802
        self.found = True

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:  # noqa: N802
        self.found = True

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:  # noqa: N802
        self.found = True

    def visit_comprehension(self, node: ast.comprehension) -> None:
        if node.is_async:
            self.found = True
            return
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        return


def _contains_suspension(node: ast.AST) -> bool:
    if isinstance(
        node, (ast.Yield, ast.YieldFrom, ast.Await, ast.AsyncFor, ast.AsyncWith)
    ):
        return True
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        if any(generator.is_async for generator in node.generators):
            return True
    finder = _SuspensionFinder()
    for child in ast.iter_child_nodes(node):
        finder.visit(child)
        if finder.found:
            return True
    return finder.found


def _has_yield(function: FunctionNode) -> bool:
    class Finder(ast.NodeVisitor):
        found = False

        def visit_Yield(self, node):  # noqa: N802
            self.found = True

        def visit_YieldFrom(self, node):  # noqa: N802
            self.found = True

        def visit_FunctionDef(self, node):  # noqa: N802
            return

        def visit_AsyncFunctionDef(self, node):  # noqa: N802
            return

        def visit_Lambda(self, node):  # noqa: N802
            return

    finder = Finder()
    for statement in function.body:
        finder.visit(statement)
    return finder.found
