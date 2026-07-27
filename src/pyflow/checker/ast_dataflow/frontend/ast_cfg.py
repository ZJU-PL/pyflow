"""Structured source-AST control-flow graph construction.

This frontend exists for lightweight sessions that do not carry PyFlow IR.  A
separate adapter will expose the repository's richer IR CFG through the same
solver API.  Compound statements are represented by explicit branch edges;
their bodies are never executed sequentially in one shared visitor state.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import cast

from ..solver import CFGEdge, ControlFlowGraph, EdgeKind

_TRY_STAR = getattr(ast, "TryStar", None)


def _is_try_statement(statement: ast.AST) -> bool:
    return isinstance(statement, ast.Try) or (
        _TRY_STAR is not None and isinstance(statement, _TRY_STAR)
    )


class ASTNodeKind(str, Enum):
    ENTRY = "entry"
    EXIT = "exit"
    STATEMENT = "statement"
    BRANCH = "branch"
    LOOP = "loop"
    MATCH = "match"
    TRY = "try"
    HANDLER_DISPATCH = "handler-dispatch"
    RETURN = "return"
    RAISE = "raise"
    BREAK = "break"
    CONTINUE = "continue"


@dataclass(frozen=True)
class ASTCFGNode:
    procedure: str
    index: int
    kind: ASTNodeKind
    syntax: ast.AST | None = field(default=None, compare=False, hash=False, repr=False)

    @property
    def line(self) -> int | None:
        line = getattr(self.syntax, "lineno", None)
        return line if isinstance(line, int) else None


@dataclass(frozen=True)
class ASTControlFlowGraph:
    graph: ControlFlowGraph[ASTCFGNode]
    normal_exit: ASTCFGNode
    function: ast.FunctionDef | ast.AsyncFunctionDef


class ASTCFGBuilder:
    """Build a conservative, statement-level CFG for one Python function."""

    def __init__(self, procedure: str) -> None:
        self.procedure = procedure
        self._next_index = 0
        self._nodes: list[ASTCFGNode] = []
        self._edges: list[CFGEdge[ASTCFGNode]] = []

    def build(
        self, function: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> ASTControlFlowGraph:
        self._next_index = 0
        self._nodes = []
        self._edges = []
        entry = self._new(ASTNodeKind.ENTRY)
        normal_exit = self._new(ASTNodeKind.EXIT)
        body_entry = self._build_block(function.body, normal_exit)
        self._connect(entry, body_entry)
        graph = ControlFlowGraph(
            entry=entry,
            nodes=frozenset(self._nodes),
            edges=tuple(dict.fromkeys(self._edges)),
        )
        return ASTControlFlowGraph(graph, normal_exit, function)

    def _new(self, kind: ASTNodeKind, syntax: ast.AST | None = None) -> ASTCFGNode:
        node = ASTCFGNode(self.procedure, self._next_index, kind, syntax)
        self._next_index += 1
        self._nodes.append(node)
        return node

    def _connect(
        self, source: ASTCFGNode, target: ASTCFGNode, kind: EdgeKind = EdgeKind.NORMAL
    ) -> None:
        self._edges.append(CFGEdge(source, target, kind))

    def _build_block(
        self,
        statements: list[ast.stmt],
        continuation: ASTCFGNode,
        *,
        break_target: ASTCFGNode | None = None,
        continue_target: ASTCFGNode | None = None,
        exception_target: ASTCFGNode | None = None,
    ) -> ASTCFGNode:
        current = continuation
        for statement in reversed(statements):
            current = self._build_statement(
                statement,
                current,
                break_target=break_target,
                continue_target=continue_target,
                exception_target=exception_target,
            )
        return current

    def _build_statement(
        self,
        statement: ast.stmt,
        continuation: ASTCFGNode,
        *,
        break_target: ASTCFGNode | None,
        continue_target: ASTCFGNode | None,
        exception_target: ASTCFGNode | None,
    ) -> ASTCFGNode:
        if isinstance(statement, ast.If):
            branch = self._new(ASTNodeKind.BRANCH, statement)
            body = self._build_block(
                statement.body,
                continuation,
                break_target=break_target,
                continue_target=continue_target,
                exception_target=exception_target,
            )
            alternate = self._build_block(
                statement.orelse,
                continuation,
                break_target=break_target,
                continue_target=continue_target,
                exception_target=exception_target,
            )
            self._connect(branch, body, EdgeKind.TRUE)
            self._connect(branch, alternate, EdgeKind.FALSE)
            return branch

        if isinstance(statement, (ast.While, ast.For, ast.AsyncFor)):
            loop = self._new(ASTNodeKind.LOOP, statement)
            alternate = self._build_block(
                statement.orelse,
                continuation,
                break_target=break_target,
                continue_target=continue_target,
                exception_target=exception_target,
            )
            body = self._build_block(
                statement.body,
                loop,
                break_target=continuation,
                continue_target=loop,
                exception_target=exception_target,
            )
            self._connect(loop, body, EdgeKind.TRUE)
            self._connect(loop, alternate, EdgeKind.FALSE)
            if exception_target is not None:
                self._connect(loop, exception_target, EdgeKind.EXCEPTION)
            return loop

        if isinstance(statement, ast.Match):
            match = self._new(ASTNodeKind.MATCH, statement)
            if not statement.cases:
                self._connect(match, continuation)
            for case in statement.cases:
                case_entry = self._build_block(
                    case.body,
                    continuation,
                    break_target=break_target,
                    continue_target=continue_target,
                    exception_target=exception_target,
                )
                self._connect(match, case_entry, EdgeKind.NORMAL)
            if exception_target is not None:
                self._connect(match, exception_target, EdgeKind.EXCEPTION)
            return match

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            node = self._new(ASTNodeKind.STATEMENT, statement)
            body = self._build_block(
                statement.body,
                continuation,
                break_target=break_target,
                continue_target=continue_target,
                exception_target=exception_target,
            )
            self._connect(node, body)
            if exception_target is not None:
                self._connect(node, exception_target, EdgeKind.EXCEPTION)
            return node

        if _is_try_statement(statement):
            return self._build_try(
                statement,
                continuation,
                break_target=break_target,
                continue_target=continue_target,
                outer_exception_target=exception_target,
            )

        if isinstance(statement, ast.Return):
            node = self._new(ASTNodeKind.RETURN, statement)
            if exception_target is not None:
                self._connect(node, exception_target, EdgeKind.EXCEPTION)
            return node

        if isinstance(statement, ast.Raise):
            node = self._new(ASTNodeKind.RAISE, statement)
            if exception_target is not None:
                self._connect(node, exception_target, EdgeKind.EXCEPTION)
            return node

        if isinstance(statement, ast.Break):
            node = self._new(ASTNodeKind.BREAK, statement)
            if break_target is not None:
                self._connect(node, break_target, EdgeKind.BREAK)
            return node

        if isinstance(statement, ast.Continue):
            node = self._new(ASTNodeKind.CONTINUE, statement)
            if continue_target is not None:
                self._connect(node, continue_target, EdgeKind.CONTINUE)
            return node

        node = self._new(ASTNodeKind.STATEMENT, statement)
        self._connect(node, continuation)
        if exception_target is not None:
            self._connect(node, exception_target, EdgeKind.EXCEPTION)
        return node

    def _build_try(
        self,
        statement: ast.AST,
        continuation: ASTCFGNode,
        *,
        break_target: ASTCFGNode | None,
        continue_target: ASTCFGNode | None,
        outer_exception_target: ASTCFGNode | None,
    ) -> ASTCFGNode:
        statement = cast(ast.Try, statement)
        try_node = self._new(ASTNodeKind.TRY, statement)
        finally_entry = self._build_block(
            statement.finalbody,
            continuation,
            break_target=break_target,
            continue_target=continue_target,
            exception_target=outer_exception_target,
        )
        normal_after_body = self._build_block(
            statement.orelse,
            finally_entry,
            break_target=break_target,
            continue_target=continue_target,
            exception_target=outer_exception_target,
        )

        handler_dispatch: ASTCFGNode | None = None
        if statement.handlers:
            handler_dispatch = self._new(ASTNodeKind.HANDLER_DISPATCH, statement)
            for handler in statement.handlers:
                handler_entry = self._build_block(
                    handler.body,
                    finally_entry,
                    break_target=break_target,
                    continue_target=continue_target,
                    exception_target=outer_exception_target,
                )
                self._connect(handler_dispatch, handler_entry, EdgeKind.EXCEPTION)
            if outer_exception_target is not None:
                self._connect(
                    handler_dispatch, outer_exception_target, EdgeKind.EXCEPTION
                )

        body_entry = self._build_block(
            statement.body,
            normal_after_body,
            break_target=break_target,
            continue_target=continue_target,
            exception_target=handler_dispatch or outer_exception_target,
        )
        self._connect(try_node, body_entry)
        return try_node


def find_function(
    tree: ast.AST, name: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ):
            return node
    return None
