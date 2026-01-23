"""
Program Dependence Graph (PDG) data structures.

PDG nodes represent program points (entry/exit, CFG blocks, statements, and
branch conditions). PDG edges represent dependence relationships:
- "control": control dependences (execution of target depends on controller)
- "data": data dependences (values used by target are defined by source)

The graph stores bidirectional edges on nodes for efficient traversal and
provides common queries including reachability and program slicing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple


PDGEdgeKind = str  # "control" | "data" | ...
PDGNodeKind = str  # "entry" | "exit" | "block" | "stmt" | "cond" | ...


class PDGEdge:
    __slots__ = ("source", "target", "kind", "label")

    def __init__(self, source: "PDGNode", target: "PDGNode", kind: PDGEdgeKind, label: str = ""):
        self.source = source
        self.target = target
        self.kind = kind
        self.label = label

    def __repr__(self) -> str:
        return f"PDGEdge({self.source.node_id} -> {self.target.node_id}, {self.kind!r}, {self.label!r})"

    def __hash__(self) -> int:
        return hash((self.source.node_id, self.target.node_id, self.kind, self.label))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PDGEdge):
            return False
        return (
            self.source.node_id == other.source.node_id
            and self.target.node_id == other.target.node_id
            and self.kind == other.kind
            and self.label == other.label
        )


class PDGNode:
    __slots__ = ("node_id", "kind", "cfg_node", "ast_node", "label", "edges_in", "edges_out")

    def __init__(
        self,
        node_id: int,
        kind: PDGNodeKind,
        *,
        cfg_node: Any = None,
        ast_node: Any = None,
        label: str = "",
    ):
        self.node_id = node_id
        self.kind = kind
        self.cfg_node = cfg_node
        self.ast_node = ast_node
        self.label = label
        self.edges_in: Set[PDGEdge] = set()
        self.edges_out: Set[PDGEdge] = set()

    def add_edge_to(self, other: "PDGNode", kind: PDGEdgeKind, label: str = "") -> PDGEdge:
        edge = PDGEdge(self, other, kind, label)
        self.edges_out.add(edge)
        other.edges_in.add(edge)
        return edge

    def __repr__(self) -> str:
        return f"PDGNode({self.node_id},{self.kind})"

    def __hash__(self) -> int:
        return self.node_id

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PDGNode) and self.node_id == other.node_id


@dataclass(frozen=True)
class PDGStats:
    nodes: int
    edges: int
    node_kinds: Dict[str, int]
    edge_kinds: Dict[str, int]


class ProgramDependenceGraph:
    """
    A Program Dependence Graph (PDG) for a single function.

    The PDG maintains:
    - a flat node list (stable IDs)
    - edges stored on nodes (bidirectional)
    - indexes for looking up nodes by CFG or AST objects
    """

    __slots__ = (
        "nodes",
        "_id",
        "cfg",
        "entry",
        "exit_nodes",
        "_cfg_anchor",
        "_cfg_contents",
        "_ast_node_index",
    )

    def __init__(self, cfg: Any):
        self.cfg = cfg
        self.nodes: List[PDGNode] = []
        self._id = 0

        self.entry: Optional[PDGNode] = None
        self.exit_nodes: List[PDGNode] = []

        self._cfg_anchor: Dict[Any, PDGNode] = {}
        self._cfg_contents: Dict[Any, List[PDGNode]] = {}
        self._ast_node_index: Dict[Any, PDGNode] = {}

    def _new_id(self) -> int:
        nid = self._id
        self._id += 1
        return nid

    def add_node(
        self,
        kind: PDGNodeKind,
        *,
        cfg_node: Any = None,
        ast_node: Any = None,
        label: str = "",
    ) -> PDGNode:
        node = PDGNode(self._new_id(), kind, cfg_node=cfg_node, ast_node=ast_node, label=label)
        self.nodes.append(node)
        if ast_node is not None:
            self._ast_node_index[ast_node] = node
        return node

    def get_node(self, node_id: int) -> Optional[PDGNode]:
        if 0 <= node_id < len(self.nodes):
            n = self.nodes[node_id]
            if n.node_id == node_id:
                return n
        for n in self.nodes:
            if n.node_id == node_id:
                return n
        return None

    def nodes_of_kind(self, kind: PDGNodeKind) -> List[PDGNode]:
        return [n for n in self.nodes if n.kind == kind]

    def get_node_for_ast(self, ast_node: Any) -> Optional[PDGNode]:
        return self._ast_node_index.get(ast_node)

    def set_cfg_anchor(self, cfg_node: Any, anchor: PDGNode) -> None:
        self._cfg_anchor[cfg_node] = anchor

    def get_cfg_anchor(self, cfg_node: Any) -> Optional[PDGNode]:
        return self._cfg_anchor.get(cfg_node)

    def add_cfg_content(self, cfg_node: Any, node: PDGNode) -> None:
        self._cfg_contents.setdefault(cfg_node, []).append(node)

    def get_cfg_contents(self, cfg_node: Any) -> List[PDGNode]:
        return self._cfg_contents.get(cfg_node, [])

    def all_edges(self, *, kind: Optional[PDGEdgeKind] = None) -> List[PDGEdge]:
        edges: List[PDGEdge] = []
        for n in self.nodes:
            for e in n.edges_out:
                if kind is None or e.kind == kind:
                    edges.append(e)
        return edges

    def iter_edges(self, *, kind: Optional[PDGEdgeKind] = None) -> Iterator[PDGEdge]:
        for n in self.nodes:
            for e in n.edges_out:
                if kind is None or e.kind == kind:
                    yield e

    def stats(self) -> PDGStats:
        node_kinds: Dict[str, int] = {}
        for n in self.nodes:
            node_kinds[n.kind] = node_kinds.get(n.kind, 0) + 1

        edge_kinds: Dict[str, int] = {}
        edge_count = 0
        for e in self.all_edges():
            edge_count += 1
            edge_kinds[e.kind] = edge_kinds.get(e.kind, 0) + 1

        return PDGStats(nodes=len(self.nodes), edges=edge_count, node_kinds=node_kinds, edge_kinds=edge_kinds)

    def successors(self, node: PDGNode, *, kinds: Optional[Set[PDGEdgeKind]] = None) -> Set[PDGNode]:
        if kinds is None:
            return {e.target for e in node.edges_out}
        return {e.target for e in node.edges_out if e.kind in kinds}

    def predecessors(self, node: PDGNode, *, kinds: Optional[Set[PDGEdgeKind]] = None) -> Set[PDGNode]:
        if kinds is None:
            return {e.source for e in node.edges_in}
        return {e.source for e in node.edges_in if e.kind in kinds}

    def backward_slice(self, seeds: Sequence[PDGNode], *, kinds: Set[PDGEdgeKind] = frozenset(("data", "control"))) -> Set[PDGNode]:
        """
        Compute a backward slice (all nodes that can affect the seeds).
        """
        visited: Set[PDGNode] = set()
        worklist: List[PDGNode] = list(seeds)

        while worklist:
            current = worklist.pop()
            if current in visited:
                continue
            visited.add(current)
            for pred in self.predecessors(current, kinds=kinds):
                if pred not in visited:
                    worklist.append(pred)
        return visited

    def forward_slice(self, seeds: Sequence[PDGNode], *, kinds: Set[PDGEdgeKind] = frozenset(("data", "control"))) -> Set[PDGNode]:
        """
        Compute a forward slice (all nodes affected by the seeds).
        """
        visited: Set[PDGNode] = set()
        worklist: List[PDGNode] = list(seeds)

        while worklist:
            current = worklist.pop()
            if current in visited:
                continue
            visited.add(current)
            for succ in self.successors(current, kinds=kinds):
                if succ not in visited:
                    worklist.append(succ)
        return visited

    def induced_subgraph(self, keep: Set[PDGNode]) -> Tuple[Set[PDGNode], Set[PDGEdge]]:
        edges: Set[PDGEdge] = set()
        for n in keep:
            for e in n.edges_out:
                if e.target in keep:
                    edges.add(e)
        return keep, edges

    def cypher(self, query: str, *, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Execute an in-memory Cypher-like query against this PDG.

        Returns:
            List of records (dicts) as produced by `RETURN`.
        """
        from . import cypher as _cypher

        return _cypher.execute(self, query, params=params)
