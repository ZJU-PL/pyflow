"""Traversal, slicing, search, and serialization queries."""

from __future__ import annotations
from collections import deque
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set
from pyflow.ir.pdg.graph import PDGNode
from .model import (
    CPGEdge,
    CPGEdgeKind,
    CPGNodeView,
    CPGStats,
    _ALL_KINDS,
    _AST_KINDS,
    _CALL_KINDS,
    _CFG_KINDS,
)


class _GraphQueryMixin:
    """Internal mixin composed by CodePropertyGraph."""

    def successors(
        self,
        node: PDGNode,
        *,
        kinds: Optional[Set[CPGEdgeKind]] = None,
    ) -> Set[PDGNode]:
        """Return all successor nodes reachable via edges of the given
        *kinds* (or all kinds when *kinds* is ``None``).
        """
        self._ensure_built()
        if kinds is None:
            kinds = _ALL_KINDS
        edges = self._cpg_edges_out.get(node.node_id, ())
        return {e.target for e in edges if e.kind in kinds}

    def predecessors(
        self,
        node: PDGNode,
        *,
        kinds: Optional[Set[CPGEdgeKind]] = None,
    ) -> Set[PDGNode]:
        """Return all predecessor nodes reachable via edges of the given
        *kinds* (or all kinds when *kinds* is ``None``).
        """
        self._ensure_built()
        if kinds is None:
            kinds = _ALL_KINDS
        edges = self._cpg_edges_in.get(node.node_id, ())
        return {e.source for e in edges if e.kind in kinds}

    def ast_children(self, node: PDGNode) -> Set[PDGNode]:
        """Return the AST children of *node*."""
        return self.successors(node, kinds=_AST_KINDS)

    def ast_parent(self, node: PDGNode) -> Optional[PDGNode]:
        """Return the AST parent of *node*, if any."""
        self._ensure_built()
        edges = self._cpg_edges_in.get(node.node_id, ())
        for e in edges:
            if e.kind == CPGEdgeKind.AST_CHILD:
                return e.source
        return None

    def cfg_successors(
        self,
        node: PDGNode,
        *,
        kind: Optional[CPGEdgeKind] = None,
    ) -> Set[PDGNode]:
        """Return CFG successors of *node*.

        When *kind* is provided, filters to that specific CFG edge kind
        (e.g. ``CFG_BRANCH_TRUE``).  When ``None``, returns all CFG
        successors regardless of kind.
        """
        kset: Set[CPGEdgeKind]
        if kind is not None:
            kset = {kind}
        else:
            kset = _CFG_KINDS
        return self.successors(node, kinds=kset)

    def node_by_id(self, node_id: int) -> Optional[PDGNode]:
        """Return a node by ID, or ``None`` when it is not present."""
        self._ensure_built()
        for node in self.nodes():
            if node.node_id == node_id:
                return node
        return None

    def cfg_next(self, node_id: int) -> List[PDGNode]:
        """Ansede-compatible node-id based CFG successor helper."""
        node = self.node_by_id(node_id)
        if node is None:
            return []
        return list(self.cfg_successors(node))

    def callers(self, func_name: str) -> Set[PDGNode]:
        """Return PDG nodes (from other functions) that ``CALL`` this function."""
        self._ensure_built()
        pdg = self._pdgs.get(func_name)
        if pdg is None or pdg.entry is None:
            return set()
        tgt = pdg.entry
        edges = self._cpg_edges_in.get(tgt.node_id, ())
        return {e.source for e in edges if e.kind == CPGEdgeKind.CALL}

    def callees(self, node: PDGNode) -> Set[PDGNode]:
        """Return PDG nodes (in other functions) called from *node*."""
        return self.successors(node, kinds=_CALL_KINDS)

    def node_meta(self, node: PDGNode) -> Dict[str, Any]:
        """Return Ansede-style metadata for *node*."""
        self._ensure_built()
        return dict(self._node_meta.get(node.node_id, {}))

    def node_type(self, node: PDGNode) -> str:
        """Return the AST type name for *node* (e.g. ``"Assign"``, ``"Call"``).

        Falls back to ``node.kind`` when no AST node is attached.
        """
        return self.node_meta(node).get("node_type", node.kind)

    def node_lineno(self, node: PDGNode) -> int:
        """Return the source line number for *node*."""
        return self.node_meta(node).get("lineno", 0)

    def node_col(self, node: PDGNode) -> int:
        """Return the source column offset for *node*."""
        return self.node_meta(node).get("col", 0)

    def node_value(self, node: PDGNode) -> str:
        """Return a human-readable code snippet for *node*."""
        return self.node_meta(node).get("value", node.label or node.kind)

    def node_func_name(self, node: PDGNode) -> str:
        """Return the enclosing function name for *node*."""
        return self.node_meta(node).get("func_name", "")

    def node_to_dict(self, node: PDGNode) -> Dict[str, Any]:
        """Serialize *node* and its CPG metadata to a JSON-compatible dict.

        Mirrors Ansede's ``CPGNode.as_dict()`` but is richer — includes
        the underlying PDG fields (``kind``, ``label``) alongside the
        convenience accessors (``ast_type``, ``lineno``, ``col``, ``value``,
        ``func``).
        """
        self._ensure_built()
        meta = dict(self._node_meta.get(node.node_id, {}))
        return {
            "id": node.node_id,
            "kind": node.kind,
            "label": node.label,
            "ast_type": meta.get("node_type", node.kind),
            "lineno": meta.get("lineno", 0),
            "col": meta.get("col", 0),
            "value": meta.get("value", node.label or node.kind),
            "func": meta.get("func_name", ""),
            "meta": meta,
        }

    def node_view(self, node: PDGNode) -> CPGNodeView:
        """Return an Ansede-compatible node view for *node*."""
        meta = self.node_meta(node)
        return CPGNodeView(
            node_id=node.node_id,
            node_type=meta.get("node_type", node.kind),
            lineno=meta.get("lineno", 0),
            col=meta.get("col", 0),
            value=meta.get("value", node.label or node.kind),
            ast_node=node.ast_node,
            func_name=meta.get("func_name", ""),
            meta=meta,
        )

    def forward_slice_all(
        self,
        seeds: Sequence[PDGNode],
        *,
        kinds: Optional[Set[CPGEdgeKind]] = None,
    ) -> Set[PDGNode]:
        """Compute a forward slice through **all** layers of the CPG.

        Unlike :meth:`~pyflow.ir.pdg.graph.ProgramDependenceGraph.forward_slice`,
        this can follow ``CFG_NEXT``, ``CFG_BRANCH_*``, ``AST_CHILD``,
        and ``CALL`` edges in addition to PDG dependence edges.

        Parameters
        ----------
        seeds:
            Starting nodes.
        kinds:
            Edge kinds to traverse (default: ``DATA`` + ``CONTROL``).

        Returns
        -------
        Set[PDGNode]
            All nodes reachable via any forward edge in *kinds*.
        """
        self._ensure_built()
        if kinds is None:
            kinds = {CPGEdgeKind.DATA, CPGEdgeKind.CONTROL}
        visited: Set[PDGNode] = set()
        worklist: deque[PDGNode] = deque(seeds)
        while worklist:
            current = worklist.popleft()
            if current in visited:
                continue
            visited.add(current)
            for succ in self.successors(current, kinds=kinds):
                if succ not in visited:
                    worklist.append(succ)
        return visited

    def backward_slice_all(
        self,
        seeds: Sequence[PDGNode],
        *,
        kinds: Optional[Set[CPGEdgeKind]] = None,
    ) -> Set[PDGNode]:
        """Compute a backward slice through all layers (reverse of
        :meth:`forward_slice_all`).
        """
        self._ensure_built()
        if kinds is None:
            kinds = {CPGEdgeKind.DATA, CPGEdgeKind.CONTROL}
        visited: Set[PDGNode] = set()
        worklist: deque[PDGNode] = deque(seeds)
        while worklist:
            current = worklist.popleft()
            if current in visited:
                continue
            visited.add(current)
            for pred in self.predecessors(current, kinds=kinds):
                if pred not in visited:
                    worklist.append(pred)
        return visited

    def reachable(
        self,
        source: PDGNode,
        target: PDGNode,
        *,
        kinds: Optional[Set[CPGEdgeKind]] = None,
    ) -> bool:
        """Check whether *target* is reachable from *source* via edges
        of the specified *kinds* (all kinds when ``None``).
        """
        self._ensure_built()
        if kinds is None:
            kinds = _ALL_KINDS
        visited: Set[int] = set()
        queue: deque[PDGNode] = deque([source])
        while queue:
            current = queue.popleft()
            if current is target:
                return True
            if current.node_id in visited:
                continue
            visited.add(current.node_id)
            for succ in self.successors(current, kinds=kinds):
                if succ.node_id not in visited:
                    queue.append(succ)
        return False

    def is_in_try_block(self, node: PDGNode) -> bool:
        """Return ``True`` if the CFG block containing *node* has a
        ``CFG_EXCEPT`` edge leading out of it (indicating *node* is
        inside a ``try`` block body).
        """
        self._ensure_built()
        cfg_block = node.cfg_node
        if cfg_block is None:
            return False
        edges = self._cpg_edges_out.get(node.node_id, ())
        for e in edges:
            if e.kind == CPGEdgeKind.CFG_EXCEPT:
                return True
        # Also check the block anchor node if this is a stmt/cond node
        for pdg_candidate in self._pdgs.values():
            anchor = pdg_candidate.get_cfg_anchor(cfg_block)
            if anchor is not None:
                anchor_edges = self._cpg_edges_out.get(anchor.node_id, ())
                for e in anchor_edges:
                    if e.kind == CPGEdgeKind.CFG_EXCEPT:
                        return True
                break
        return False

    def find_nodes(
        self,
        *,
        kind: Optional[str] = None,
        label_contains: Optional[str] = None,
        func_name: Optional[str] = None,
        limit: int = 0,
    ) -> List[PDGNode]:
        """Return PDG nodes matching the given filters.

        Parameters
        ----------
        kind:
            Node kind to match (``"stmt"``, ``"cond"``, ``"entry"``, etc.).
        label_contains:
            Substring to search for in node labels.
        func_name:
            Restrict to nodes in a specific function.
        limit:
            Maximum results (0 = unlimited).
        """
        self._ensure_built()
        results: List[PDGNode] = []
        for node in self.nodes(func_name=func_name):
            if kind is not None and node.kind != kind:
                continue
            if label_contains is not None and label_contains not in (node.label or ""):
                continue
            results.append(node)
            if limit and len(results) >= limit:
                break
        return results

    def find_edges(
        self,
        *,
        kind: Optional[CPGEdgeKind] = None,
        source_id: Optional[int] = None,
        target_id: Optional[int] = None,
        label_contains: Optional[str] = None,
        limit: int = 0,
    ) -> List[CPGEdge]:
        """Return CPG edges matching the given filters."""
        self._ensure_built()
        results: List[CPGEdge] = []
        for e in self.all_edges(kinds={kind} if kind else None):
            if source_id is not None and e.source.node_id != source_id:
                continue
            if target_id is not None and e.target.node_id != target_id:
                continue
            if label_contains is not None and label_contains not in e.label:
                continue
            results.append(e)
            if limit and len(results) >= limit:
                break
        return results

    def path_between(
        self,
        source: PDGNode,
        target: PDGNode,
        *,
        kinds: Optional[Set[CPGEdgeKind]] = None,
        max_depth: int = 50,
    ) -> Optional[List[PDGNode]]:
        """Return a path from *source* to *target* via the given edge
        *kinds*, or ``None`` if no path exists.

        Uses BFS and returns the first-found shortest path.
        """
        self._ensure_built()
        if kinds is None:
            kinds = _ALL_KINDS
        visited: Set[int] = {source.node_id}
        parent: Dict[int, PDGNode] = {}
        queue: deque[PDGNode] = deque([source])
        depth = 0
        while queue and depth < max_depth:
            depth += 1
            for _ in range(len(queue)):
                cur = queue.popleft()
                if cur is target:
                    path: List[PDGNode] = [cur]
                    while cur is not source:
                        cur = parent[cur.node_id]
                        path.append(cur)
                    path.reverse()
                    return path
                for succ in self.successors(cur, kinds=kinds):
                    if succ.node_id not in visited:
                        visited.add(succ.node_id)
                        parent[succ.node_id] = cur
                        queue.append(succ)
        return None

    def nodes_touching(
        self,
        label_substring: str,
        *,
        func_name: Optional[str] = None,
    ) -> Set[PDGNode]:
        """Return all nodes whose data flow touches *label_substring*.

        Finds nodes where (a) the node label contains the substring, or
        (b) a reachable predecessor/successor via DATA edges has a label
        containing the substring.
        """
        self._ensure_built()
        seeds = self.find_nodes(label_contains=label_substring, func_name=func_name)
        if not seeds:
            return set()
        result: Set[PDGNode] = set(seeds)
        kinds: Set[CPGEdgeKind] = {CPGEdgeKind.DATA}
        for seed in seeds:
            result |= self.forward_slice_all([seed], kinds=kinds)
            result |= self.backward_slice_all([seed], kinds=kinds)
        return result

    def nodes(self, func_name: Optional[str] = None) -> Iterable[PDGNode]:
        """Iterate over all PDG nodes, optionally scoped to *func_name*.

        When *func_name* is ``None``, iterates nodes from every registered
        function in sorted name order.
        """
        self._ensure_built()
        names = [func_name] if func_name else sorted(self._pdgs.keys())
        for name in names:
            pdg = self._pdgs.get(name)
            if pdg is not None:
                yield from pdg.nodes

    def all_edges(
        self,
        *,
        kinds: Optional[Set[CPGEdgeKind]] = None,
    ) -> Iterator[CPGEdge]:
        """Iterate over all CPG edges, optionally filtered by *kinds*."""
        self._ensure_built()
        for edges in self._cpg_edges_out.values():
            for e in edges:
                if kinds is None or e.kind in kinds:
                    yield e

    def stats(self) -> CPGStats:
        """Return summary statistics."""
        self._ensure_built()
        edge_kinds: Dict[str, int] = {}
        total_edges = 0
        for e in self.all_edges():
            total_edges += 1
            k = e.kind.value
            edge_kinds[k] = edge_kinds.get(k, 0) + 1
        total_nodes = sum(len(pdg.nodes) for pdg in self._pdgs.values())
        return CPGStats(
            functions=len(self._pdgs),
            nodes=total_nodes,
            edges=total_edges,
            edge_kinds=edge_kinds,
        )

    @property
    def defs(self) -> Dict[str, List[PDGNode]]:
        """Map variable names to their defining PDG nodes.

        Derived from ``DATA`` edges whose ``label`` is the variable name
        and whose ``source`` is the definition site.
        """
        self._ensure_built()
        result: Dict[str, List[PDGNode]] = {}
        for e in self.all_edges(kinds={CPGEdgeKind.DATA}):
            if e.label:
                result.setdefault(e.label, []).append(e.source)
        return result

    @property
    def uses(self) -> Dict[str, List[PDGNode]]:
        """Map variable names to their using PDG nodes.

        Derived from ``DATA`` edges whose ``label`` is the variable name
        and whose ``target`` is the use site.
        """
        self._ensure_built()
        result: Dict[str, List[PDGNode]] = {}
        for e in self.all_edges(kinds={CPGEdgeKind.DATA}):
            if e.label:
                result.setdefault(e.label, []).append(e.target)
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the CPG to a JSON-compatible dict."""
        self._ensure_built()
        nodes: List[Dict[str, Any]] = []
        node_index: Dict[int, int] = {}  # PDG node_id → array index
        for pdg in self._pdgs.values():
            for n in pdg.nodes:
                node_index[n.node_id] = len(nodes)
                nodes.append(
                    {
                        "id": n.node_id,
                        "kind": n.kind,
                        "label": n.label,
                        "func": getattr(pdg.cfg, "codeName", lambda: "")() or "",
                        "meta": dict(self._node_meta.get(n.node_id, {})),
                    }
                )
        edges: List[Dict[str, Any]] = []
        for e in self.all_edges():
            edges.append(
                {
                    "source": e.source.node_id,
                    "target": e.target.node_id,
                    "kind": e.kind.value,
                    "label": e.label,
                }
            )
        defs_dict: Dict[str, List[int]] = {
            var: [n.node_id for n in ns] for var, ns in self.defs.items()
        }
        uses_dict: Dict[str, List[int]] = {
            var: [n.node_id for n in ns] for var, ns in self.uses.items()
        }
        return {
            "functions": list(self.functions),
            "construction_diagnostics": [
                dict(item) for item in self._construction_diagnostics
            ],
            "nodes": nodes,
            "edges": edges,
            "defs": defs_dict,
            "uses": uses_dict,
            "stats": {
                "functions": len(self._pdgs),
                "nodes": len(nodes),
                "edges": len(edges),
            },
        }

    def __repr__(self) -> str:
        st = self.stats() if self._built else None
        if st is not None:
            return (
                f"<CodePropertyGraph functions={st.functions} nodes={st.nodes}"
                f" edges={st.edges}>"
            )
        return f"<CodePropertyGraph functions={len(self._pdgs)} (not built)>"
