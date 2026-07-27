"""Core storage and lifecycle for the Code Property Graph."""

from __future__ import annotations
from collections import defaultdict
from typing import Any, Dict, List, MutableMapping, Set, Tuple
from pyflow.ir.pdg.graph import PDGNode, ProgramDependenceGraph
from .model import CPGEdge, CPGEdgeKind
from .assembly import _GraphAssemblyMixin
from .metadata import _GraphMetadataMixin
from .queries import _GraphQueryMixin


class CodePropertyGraph(_GraphAssemblyMixin, _GraphMetadataMixin, _GraphQueryMixin):
    """Unified graph composing PDG, CFG, AST, and call-graph layers."""

    __slots__ = (
        "_pdgs",
        "_call_graph",
        "_built",
        # Cross-layer indices (populated by build())
        "_cpg_edges_out",
        "_cpg_edges_in",
        "_ast_parent",
        "_cfg_forward_map",
        "_cfg_node_to_pdg",
        "_node_meta",
    )

    def __init__(self) -> None:
        self._pdgs: Dict[str, ProgramDependenceGraph] = {}
        self._call_graph: Any = None  # CallGraph instance (optional)

        # Lazily populated by build()
        # Dict-of-dicts (key=CPGEdge, value=None) preserves insertion order
        # for deterministic traversal while still dedup'ing via __hash__.
        self._built: bool = False
        self._cpg_edges_out: MutableMapping[int, Dict[CPGEdge, None]] = defaultdict(
            dict
        )
        self._cpg_edges_in: MutableMapping[int, Dict[CPGEdge, None]] = defaultdict(dict)
        self._ast_parent: Dict[int, int] = {}  # id(ast_child) → id(ast_parent)
        self._cfg_forward_map: Dict[Tuple[int, str], List[PDGNode]] = {}
        self._cfg_node_to_pdg: Dict[int, List[PDGNode]] = {}
        self._node_meta: Dict[int, Dict[str, Any]] = {}

    def add_function(self, name: str, pdg: ProgramDependenceGraph) -> None:
        """Register a function-level PDG.

        Parameters
        ----------
        name:
            Fully-qualified function name (used as the key in the ``pdgs``
            dict and as the source/target of ``CALL`` edges).
        pdg:
            An already-constructed :class:`ProgramDependenceGraph`.
        """
        self._pdgs[name] = pdg
        self._built = False

    def add_call_graph(self, call_graph: Any) -> None:
        """Attach a :class:`~pyflow.analysis.callgraph.callgraph.CallGraph`.

        Call graph edges are resolved lazily during :meth:`build`.
        """
        self._call_graph = call_graph
        self._built = False

    @property
    def pdgs(self) -> Dict[str, ProgramDependenceGraph]:
        """Registered PDGs keyed by function name."""
        return dict(self._pdgs)

    @property
    def functions(self) -> Tuple[str, ...]:
        """Sorted list of registered function names."""
        return tuple(sorted(self._pdgs.keys()))

    @property
    def funcs(self) -> Dict[str, int]:
        """Map ``func_name -> PDG entry-node-id`` for O(1) entry lookup.

        Used by the taint engine for lambda dispatch and getattr method
        resolution (avoids linear scans via :meth:`node_by_id`).
        """
        self._ensure_built()
        return {
            name: pdg.entry.node_id
            for name, pdg in self._pdgs.items()
            if pdg.entry is not None
        }

    def build(self) -> None:
        """(Re-)build all cross-layer indices.

        Idempotent — calling again after modifications will recompute
        every index from scratch.
        """
        self._ensure_unique_node_ids()
        self._cpg_edges_out.clear()
        self._cpg_edges_in.clear()
        self._ast_parent.clear()
        self._cfg_forward_map.clear()
        self._cfg_node_to_pdg.clear()
        self._node_meta.clear()

        # Collect all PDG nodes and their AST ids.
        pdg_ast_ids: Dict[str, Set[int]] = {}
        for fname, pdg in self._pdgs.items():
            ids: Set[int] = set()
            for node in pdg.nodes:
                if node.ast_node is not None:
                    ids.add(id(node.ast_node))
            pdg_ast_ids[fname] = ids

        for fname, pdg in self._pdgs.items():
            self._build_node_metadata(fname, pdg)
            self._build_source_statement_nodes(fname, pdg, pdg_ast_ids[fname])
            self._build_pdg_edges(pdg)
            self._build_ast_edges(pdg, pdg_ast_ids[fname])
            self._build_cfg_edges(fname, pdg)
            self._build_guard_metadata(pdg)
            self._build_phi_metadata(pdg)
            self._build_lambda_nodes(pdg)
            self._build_scope_edges(fname, pdg)
            self._build_import_edges(fname, pdg)
            self._build_collection_metadata(fname, pdg)
            self._build_async_metadata(fname, pdg)
            self._build_annassign_metadata(fname, pdg)
            self._build_delete_metadata(fname, pdg)
            self._build_raise_metadata(fname, pdg)
            self._build_assert_metadata(fname, pdg)
            self._build_try_metadata(fname, pdg)
            self._build_loop_metadata(fname, pdg)
            self._build_statement_metadata(fname, pdg)
            self._build_origin_ast_metadata(pdg)

        if self._call_graph is not None:
            self._build_call_edges()

        self._built = True

    def _ensure_unique_node_ids(self) -> None:
        """Promote function-local PDG IDs to graph-global stable IDs.

        PDGs number nodes independently from zero, while every CPG index is
        keyed by ``node_id``. Rebuild the PDG edge sets after renumbering
        because ``PDGEdge.__hash__`` depends on its endpoint IDs.
        """
        nodes = [node for pdg in self._pdgs.values() for node in pdg.nodes]
        ids = [node.node_id for node in nodes]
        if len(ids) == len(set(ids)):
            next_id = max(ids, default=-1) + 1
            for pdg in self._pdgs.values():
                pdg._id = max(pdg._id, next_id)
            return

        edges = []
        seen_edges: Set[int] = set()
        for node in nodes:
            for edge in tuple(node.edges_out):
                marker = id(edge)
                if marker not in seen_edges:
                    seen_edges.add(marker)
                    edges.append(edge)

        for node_id, node in enumerate(nodes):
            node.node_id = node_id
            node.edges_in.clear()
            node.edges_out.clear()

        for edge in edges:
            edge.source.edges_out.add(edge)
            edge.target.edges_in.add(edge)

        next_id = len(nodes)
        for pdg in self._pdgs.values():
            pdg._id = next_id

    def _promote_new_node_id(self, node: PDGNode, pdg: ProgramDependenceGraph) -> None:
        """Give a newly synthesized PDG node a graph-global ID."""
        other_ids = {
            existing.node_id
            for other_pdg in self._pdgs.values()
            for existing in other_pdg.nodes
            if existing is not node
        }
        if node.node_id in other_ids:
            node.node_id = max(other_ids, default=-1) + 1
        pdg._id = max(pdg._id, node.node_id + 1)

    def _ensure_built(self) -> None:
        if not self._built:
            self.build()

    def _add_edge(
        self,
        source: PDGNode,
        target: PDGNode,
        kind: CPGEdgeKind,
        label: str = "",
    ) -> CPGEdge:
        edge = CPGEdge(source, target, kind, label)
        # dict-key insertion dedupes via CPGEdge.__hash__/__eq__ while
        # preserving the order edges were added.
        self._cpg_edges_out[source.node_id][edge] = None
        self._cpg_edges_in[target.node_id][edge] = None
        return edge

    def _meta_for(self, node: PDGNode) -> Dict[str, Any]:
        return self._node_meta.setdefault(node.node_id, {})

    def _append_meta_entry(
        self, node: PDGNode, key: str, entry: Dict[str, Any]
    ) -> None:
        values = self._meta_for(node).setdefault(key, [])
        if entry not in values:
            values.append(entry)
