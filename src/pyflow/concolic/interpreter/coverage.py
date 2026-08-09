"""Source-level coverage collection for interpreted AST execution."""

from __future__ import annotations

import ast
from typing import Any

from ..runtime import (
    BranchCoverage,
    CoverageSnapshot,
    SourceLocation,
    _Branch,
    _ModuleValue,
)


class _CoverageMixin:
    _current_module: _ModuleValue | None
    _covered_nodes: set[SourceLocation]
    _covered_branches: set[BranchCoverage]
    path: list[_Branch]

    def _source_location(self, node: ast.AST | None) -> SourceLocation | None:
        if node is None or not hasattr(node, "lineno"):
            return None
        module = self._current_module
        path = str(module.path) if module is not None else "<unknown>"
        line = int(node.lineno)
        column = int(getattr(node, "col_offset", 0))
        return SourceLocation(
            path=path,
            line=line,
            column=column,
            end_line=int(getattr(node, "end_lineno", line)),
            end_column=int(getattr(node, "end_col_offset", column)),
            node_kind=type(node).__name__,
        )

    def _cover_node(self, node: ast.AST) -> None:
        location = self._source_location(node)
        if location is not None:
            self._covered_nodes.add(location)

    def _record_branch(
        self,
        expression: Any,
        taken: bool,
        node: ast.AST | None,
        kind: str = "condition",
    ) -> None:
        location = self._source_location(node)
        self.path.append(_Branch(expression, taken, location, kind))
        self._covered_branches.add(BranchCoverage(location, kind, taken))

    def _coverage_snapshot(self) -> CoverageSnapshot:
        return CoverageSnapshot(
            frozenset(self._covered_nodes),
            frozenset(self._covered_branches),
        )
