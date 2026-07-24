"""Value objects and AST helpers for the Code Property Graph."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, Optional, Set
from pyflow.ir.pdg.graph import PDGNode
from pyflow.language.python import ast as py_ast


class CPGEdgeKind(str, Enum):
    """Edge kinds in a Code Property Graph.

    The first two (``CONTROL``, ``DATA``) are passed through from the PDG.
    The remaining six are structural edges added by the CPG.
    """

    CONTROL = "control"
    DATA = "data"
    AST_CHILD = "AST_CHILD"
    CFG_NEXT = "CFG_NEXT"
    CFG_BRANCH_TRUE = "CFG_BRANCH_TRUE"
    CFG_BRANCH_FALSE = "CFG_BRANCH_FALSE"
    CFG_EXCEPT = "CFG_EXCEPT"
    CALL = "CALL"
    RETURN_EDGE = "RETURN_EDGE"


_PDG_KINDS: Set[CPGEdgeKind] = {CPGEdgeKind.CONTROL, CPGEdgeKind.DATA}
_CFG_KINDS: Set[CPGEdgeKind] = {
    CPGEdgeKind.CFG_NEXT,
    CPGEdgeKind.CFG_BRANCH_TRUE,
    CPGEdgeKind.CFG_BRANCH_FALSE,
    CPGEdgeKind.CFG_EXCEPT,
}
_AST_KINDS: Set[CPGEdgeKind] = {CPGEdgeKind.AST_CHILD}
_CALL_KINDS: Set[CPGEdgeKind] = {CPGEdgeKind.CALL}
_RETURN_KINDS: Set[CPGEdgeKind] = {CPGEdgeKind.RETURN_EDGE}
_ALL_KINDS: Set[CPGEdgeKind] = (
    _PDG_KINDS | _CFG_KINDS | _AST_KINDS | _CALL_KINDS | _RETURN_KINDS
)


@dataclass
class CPGEdge:
    """A CPG edge between two PDG nodes, carrying a :class:`CPGEdgeKind`.

    ``label`` carries extra context: branch direction for CFG edges
    (``"true"`` / ``"false"``), variable name for data edges, callee name
    for CALL edges, or the empty string.
    """

    source: PDGNode
    target: PDGNode
    kind: CPGEdgeKind
    label: str = ""

    def __hash__(self) -> int:
        return hash((self.source.node_id, self.target.node_id, self.kind))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CPGEdge):
            return False
        return (
            self.source.node_id == other.source.node_id
            and self.target.node_id == other.target.node_id
            and self.kind == other.kind
        )

    def __repr__(self) -> str:
        return (
            f"CPGEdge({self.source.node_id} -> {self.target.node_id}, "
            f"{self.kind.value!r}, {self.label!r})"
        )


@dataclass
class CPGStats:
    """Statistics for a :class:`CodePropertyGraph`."""

    functions: int
    nodes: int
    edges: int
    edge_kinds: Dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class CPGNodeView:
    """Ansede-compatible read-only view over a PDG-backed CPG node."""

    node_id: int
    node_type: str
    lineno: int
    col: int = 0
    value: str = ""
    ast_node: Any = None
    func_name: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "lineno": self.lineno,
            "col": self.col,
            "value": self.value,
            "func_name": self.func_name,
            "meta": dict(self.meta),
        }


def _iter_ast_children(node: Any) -> Iterator[Any]:
    """Yield direct AST children of *node*, flattening lists."""
    if node is None:
        return
    for child in getattr(node, "children", lambda: ())():
        if isinstance(child, (list, tuple)):
            yield from (c for c in child if c is not None)
        elif child is not None:
            yield child


def _build_ast_parent_map(
    root: Any, *, pdg_ast_set: Optional[Set[int]] = None
) -> Dict[int, Any]:
    """Build a parent map from ``id(child)`` → *parent* for every AST node
    reachable from *root*.  When *pdg_ast_set* is provided, only nodes
    whose ``id()`` is in the set are recorded (speeds up PDG-targeted lookups).
    """
    parents: Dict[int, Any] = {}
    visited_codes: Set[int] = set()

    def walk(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, py_ast.Code):
            nid = id(node)
            if nid in visited_codes:
                return
            visited_codes.add(nid)
        if isinstance(node, py_ast.leafTypes):
            return
        for child in _iter_ast_children(node):
            cid = id(child)
            if pdg_ast_set is None or cid in pdg_ast_set:
                parents[cid] = node
            walk(child)

    walk(root)
    return parents


def _safe_type_name(node: Any) -> str:
    """Return ``type(node).__name__`` or ``"?"`` on failure."""
    try:
        return type(node).__name__
    except Exception:
        return "?"
