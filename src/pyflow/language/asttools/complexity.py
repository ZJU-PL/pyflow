"""
McCabe cyclomatic complexity analysis for Python ASTs.

The implementation is adapted from the ``mccabe`` library
(https://github.com/PyCQA/mccabe), released by Florent Xicluna,
Tarek Ziade, and Ned Batchelder under the Expat License.

Original copyright notice:
Copyright © <year> Ned Batchelder
Copyright © 2011-2013 Tarek Ziade <tarek@ziade.org>
Copyright © 2013 Florent Xicluna <florent.xicluna@gmail.com>
"""

from __future__ import annotations

import ast
from abc import ABC
from ast import iter_child_nodes
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


__all__ = [
    "mccabe_complexity",
]


class _ASTVisitor(ABC):
    """Performs a preorder walk of the AST, dispatching to ``visit*`` methods."""

    def __init__(self):
        self.node = None
        self.visitor = None
        self._cache = {}

    def default(self, node: ast.AST) -> None:
        for child in iter_child_nodes(node):
            self.dispatch(child)

    def dispatch(self, node: ast.AST):
        self.node = node
        klass = node.__class__
        meth = self._cache.get(klass)
        if meth is None:
            class_name = klass.__name__
            meth = getattr(self.visitor, "visit" + class_name, self.default)
            self._cache[klass] = meth
        return meth(node)

    def preorder(self, tree: ast.AST, visitor: _ASTVisitor):
        self.visitor = visitor
        self.dispatch(tree)

    visit = dispatch


@dataclass(unsafe_hash=True, frozen=True)
class _PathNode:
    name: str


class _PathGraph:
    """Tracks control-flow edges for a single function/scope."""

    def __init__(self, name, entity, lineno, column=0):
        self.name = name
        self.entity = entity
        self.lineno = lineno
        self.column = column
        self.nodes = defaultdict(list)

    def connect(self, node_1: _PathNode, node_2: _PathNode) -> None:
        self.nodes[node_1].append(node_2)
        self.nodes[node_2] = []

    def complexity(self) -> int:
        """McCabe cyclomatic complexity = edges - nodes + 2."""
        num_edges = sum(len(n) for n in self.nodes.values())
        num_nodes = len(self.nodes)
        return num_edges - num_nodes + 2


class _PathGraphingAstVisitor(_ASTVisitor):
    """AST visitor that builds path graphs and computes complexity."""

    def __init__(self):
        super().__init__()
        self.class_name = ""
        self.graphs = {}
        self.graph = None
        self.tail = None

    def reset(self):
        self.graph = None
        self.tail = None

    def dispatch_list(self, node_list: Sequence[ast.AST]) -> None:
        for node in node_list:
            self.dispatch(node)

    def visitFunctionDef(  # noqa: N802
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        entity = node.name
        name = f"{node.lineno}:{node.col_offset}: {entity}"

        if self.graph is not None:
            # nested function
            path_node = self.__append_path_node(name)
            assert path_node is not None  # tail must be set inside a function
            self.tail = path_node
            self.dispatch_list(node.body)
            bottom = _PathNode("")
            self.graph.connect(self.tail, bottom)
            self.graph.connect(path_node, bottom)
            self.tail = bottom
        else:
            self.graph = _PathGraph(name, entity, node.lineno, node.col_offset)
            path_node = _PathNode(name)
            self.tail = path_node
            self.dispatch_list(node.body)
            self.graphs[f"{self.class_name}{node.name}"] = self.graph
            self.reset()

    visitAsyncFunctionDef = visitFunctionDef  # noqa: N815

    def __append_path_node(self, name: str) -> _PathNode | None:
        if not self.tail:
            return None
        assert self.graph is not None
        path_node = _PathNode(name)
        self.graph.connect(self.tail, path_node)
        self.tail = path_node
        return path_node

    def visitSimpleStatement(self, node: ast.stmt) -> None:  # noqa: N802
        name = f"Stmt {node.lineno}"
        self.__append_path_node(name)

    def default(self, node: ast.AST, *args) -> None:
        if isinstance(node, ast.stmt):
            self.visitSimpleStatement(node)
        else:
            super().default(node, *args)

    def visitLoop(self, node: ast.AsyncFor | ast.For | ast.While) -> None:  # noqa: N802
        name = f"Loop {node.lineno}"
        self.__subgraph(node, name)

    visitAsyncFor = visitFor = visitWhile = visitLoop  # noqa: N815

    def visitIf(self, node: ast.If) -> None:  # noqa: N802
        name = f"If {node.lineno}"
        self.__subgraph(node, name)

    def __subgraph(self, node, name, extra_blocks=()):
        if self.graph is None:
            # module-level control flow (not inside a function)
            self.graph = _PathGraph(name, name, node.lineno, node.col_offset)
            path_node: _PathNode | None = _PathNode(name)
            self.__subgraph_parse(node, path_node, extra_blocks)
            self.graphs[f"{self.class_name}{name}"] = self.graph
            self.reset()
        else:
            path_node = self.__append_path_node(name)
            self.__subgraph_parse(node, path_node, extra_blocks)

    def __subgraph_parse(self, node, path_node, extra_blocks):
        loose_ends = []
        self.tail = path_node
        self.dispatch_list(node.body)
        loose_ends.append(self.tail)
        for extra in extra_blocks:
            self.tail = path_node
            self.dispatch_list(extra.body)
            loose_ends.append(self.tail)
        if node.orelse:
            self.tail = path_node
            self.dispatch_list(node.orelse)
            loose_ends.append(self.tail)
        else:
            loose_ends.append(path_node)
        if path_node:
            bottom = _PathNode("")
            assert self.graph is not None
            for loose_end in loose_ends:
                self.graph.connect(loose_end, bottom)
            self.tail = bottom

    def visitTryExcept(self, node: ast.Try) -> None:  # noqa: N802
        name = f"TryExcept {node.lineno}"
        self.__subgraph(node, name, extra_blocks=node.handlers)

    visitTry = visitTryExcept  # noqa: N815

    def visitWith(self, node: ast.With | ast.AsyncWith) -> None:  # noqa: N802
        name = f"With {node.lineno}"
        self.__append_path_node(name)
        self.dispatch_list(node.body)

    visitAsyncWith = visitWith  # noqa: N815


def mccabe_complexity(tree: ast.AST) -> int:
    """Compute the total McCabe cyclomatic complexity for an AST.

    Sums the complexity of every function / method / top-level branch found
    in the tree.  A function with no branches has complexity 1; each
    ``if``, ``while``, ``for``, ``except``, ``with``, ``and`` / ``or``
    adds 1.

    Args:
        tree: The parsed AST (e.g. from ``ast.parse``).

    Returns:
        The total cyclomatic complexity.
    """
    visitor = _PathGraphingAstVisitor()
    visitor.preorder(tree, visitor)
    return sum(graph.complexity() for graph in visitor.graphs.values())
