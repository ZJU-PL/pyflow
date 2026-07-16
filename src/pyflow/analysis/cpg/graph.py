"""
Code Property Graph (CPG) — unified multi-layered program graph.

A CPG composes the Program Dependence Graph (PDG), Control Flow Graph (CFG),
AST structure, and call graph into a single navigable graph.  It does **not**
duplicate data — every node is a :class:`~pyflow.analysis.pdg.graph.PDGNode`
and CPG edges are indexed alongside existing PDG edges.

Edge kinds
----------
The CPG adds four structural edge kinds to the PDG's ``control`` and ``data``
dependence edges:

* ``AST_CHILD``     — parent → child in the AST (derived from ``PDGNode.ast_node``)
* ``CFG_NEXT``      — sequential control-flow successor
* ``CFG_BRANCH_TRUE``  — true branch of a conditional
* ``CFG_BRANCH_FALSE`` — false branch of a conditional
* ``CFG_EXCEPT``    — exceptional control-flow path (error / fail)
* ``CALL``          — interprocedural caller → callee (via :class:`~pyflow.analysis.callgraph.callgraph.CallGraph`)

Architecture
------------
::

   CPG (unified query + traversal API)
    │
    ├── PDG (control + data dependences, per function)
    ├── CFG (control flow blocks + branches, embedded in PDG.cfg)
    ├── AST (parent/child structure, derived from PDGNode.ast_node)
    └── CallGraph (interprocedural callee edges)

Typical usage::

    from pyflow.analysis.pdg import construct_pdg
    from pyflow.analysis.cpg import CodePropertyGraph

    cpg = CodePropertyGraph()
    cpg.add_function("my_func", construct_pdg(cfg))
    cpg.add_call_graph(callgraph)

    # Navigation
    for child in cpg.ast_children(node):
        ...
    for succ in cpg.cfg_successors(node, kind="CFG_BRANCH_TRUE"):
        ...

    # Unified queries
    reached = cpg.forward_slice_all(seed, kinds=frozenset(("data", "CFG_NEXT")))
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.analysis.pdg.graph import PDGNode, ProgramDependenceGraph
from pyflow.language.python import ast as py_ast


# ── Edge kinds ───────────────────────────────────────────────────────────────


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


# Friendly aliases for sets of edge kinds.
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


# ── Data structures ──────────────────────────────────────────────────────────


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


# ── Internal helpers ─────────────────────────────────────────────────────────


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


# ── Main class ───────────────────────────────────────────────────────────────


class CodePropertyGraph:
    """Unified multi-layered program graph composing PDG, CFG, AST, and
    call graph.

    A :class:`CodePropertyGraph` is built incrementally:

    1. Add PDGs via :meth:`add_function`.
    2. Optionally add a call graph via :meth:`add_call_graph`.
    3. Call :meth:`build` (or use query methods which build lazily).
    4. Navigate with :meth:`successors`, :meth:`predecessors`, and
       the typed helpers (:meth:`ast_children`, :meth:`cfg_successors`,
       :meth:`callers`, :meth:`callees`).

    All structural edges are derived from existing data — the CPG does
    **not** duplicate PDG nodes or re-analyse source code.
    """

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
        self._cpg_edges_out: MutableMapping[int, Dict[CPGEdge, None]] = defaultdict(dict)
        self._cpg_edges_in: MutableMapping[int, Dict[CPGEdge, None]] = defaultdict(dict)
        self._ast_parent: Dict[int, int] = {}  # id(ast_child) → id(ast_parent)
        self._cfg_forward_map: Dict[Tuple[int, str], List[PDGNode]] = {}
        self._cfg_node_to_pdg: Dict[int, List[PDGNode]] = {}
        self._node_meta: Dict[int, Dict[str, Any]] = {}

    # ── Construction ─────────────────────────────────────────────────────

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

    # ── Build ────────────────────────────────────────────────────────────

    def build(self) -> None:
        """(Re-)build all cross-layer indices.

        Idempotent — calling again after modifications will recompute
        every index from scratch.
        """
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

    def _build_node_metadata(self, fname: str, pdg: ProgramDependenceGraph) -> None:
        """Populate Ansede-style node metadata without mutating ``PDGNode``."""
        for node in pdg.nodes:
            ast_node = node.ast_node
            meta = self._meta_for(node)
            # For block-anchors without an AST node, node.label ("Merge", "Switch",
            # "Yield") is more informative than node.kind ("block").
            if ast_node is not None:
                typed_name = _safe_type_name(ast_node)
            else:
                typed_name = node.label or node.kind
            meta.setdefault("node_type", typed_name)
            meta.setdefault("lineno", getattr(ast_node, "lineno", 0) or 0)
            meta.setdefault(
                "col",
                getattr(ast_node, "col", getattr(ast_node, "col_offset", 0)) or 0,
            )
            meta.setdefault(
                "value", self._ast_value(ast_node) or node.label or node.kind
            )
            meta.setdefault("func_name", fname)
            meta.setdefault("kind", node.kind)

    def _build_source_statement_nodes(
        self,
        fname: str,
        pdg: ProgramDependenceGraph,
        pdg_ast_ids: Set[int],
    ) -> None:
        """Backfill source statements lost during CFG/PDG lowering.

        The primary CPG model is still PDG-backed. This pass only adds explicit
        synthetic nodes for source AST constructs that are meaningful query
        targets but are commonly consumed by lowering, such as ``ClassDef`` or
        ``break``/``continue``.
        """
        code = getattr(pdg.cfg, "code", None)
        root = getattr(code, "ast", None)
        if root is None:
            return

        for ast_node in self._iter_source_statement_nodes(root):
            if not self._needs_synthetic_statement_node(ast_node):
                continue
            if pdg.get_node_for_ast(ast_node) is not None:
                continue

            label = self._ast_value(ast_node) or _safe_type_name(ast_node)
            node = pdg.add_node("stmt", ast_node=ast_node, label=label)
            pdg_ast_ids.add(id(ast_node))

            meta = self._meta_for(node)
            meta.setdefault("node_type", _safe_type_name(ast_node))
            meta.setdefault("lineno", getattr(ast_node, "lineno", 0) or 0)
            meta.setdefault(
                "col",
                getattr(ast_node, "col", getattr(ast_node, "col_offset", 0)) or 0,
            )
            meta.setdefault("value", label)
            meta.setdefault("func_name", fname)
            meta.setdefault("kind", node.kind)
            meta["synthetic_ast"] = True
            self._annotate_statement_meta(node)
            if pdg.entry is not None:
                self._add_edge(
                    pdg.entry,
                    node,
                    CPGEdgeKind.AST_CHILD,
                    f"synthetic:{_safe_type_name(ast_node)}",
                )

    @staticmethod
    def _iter_source_statement_nodes(root: Any) -> Iterator[Any]:
        seen: Set[int] = set()

        def walk(node: Any) -> Iterator[Any]:
            if node is None:
                return
            nid = id(node)
            if nid in seen:
                return
            seen.add(nid)
            if isinstance(node, py_ast.leafTypes):
                return
            yield node
            if isinstance(node, py_ast.FunctionDef):
                return
            for child in _iter_ast_children(node):
                yield from walk(child)

        yield from walk(root)

    @staticmethod
    def _needs_synthetic_statement_node(ast_node: Any) -> bool:
        node_type = _safe_type_name(ast_node)
        return (
            isinstance(
                ast_node,
                (
                    py_ast.ClassDef,
                    py_ast.Break,
                    py_ast.Continue,
                    py_ast.GlobalDecl,
                    py_ast.NonlocalDecl,
                    py_ast.TypeAlias,
                    py_ast.TryExceptFinally,
                    py_ast.Yield,
                    py_ast.YieldFrom,
                    py_ast.AsyncYield,
                    py_ast.Await,
                ),
            )
            or node_type in {"With", "AsyncWith", "Pass"}
        )

    def _annotate_statement_meta(self, node: PDGNode) -> None:
        ast_node = node.ast_node
        if ast_node is None:
            return
        meta = self._meta_for(node)
        node_type = type(ast_node).__name__

        if isinstance(ast_node, py_ast.ClassDef):
            meta["is_class_def"] = True
            meta["class_name"] = getattr(ast_node, "name", "")
        elif node_type in {"With", "AsyncWith"}:
            meta["is_with"] = True
            meta["is_async_with"] = node_type == "AsyncWith"
        elif isinstance(ast_node, (py_ast.Yield, py_ast.YieldFrom, py_ast.AsyncYield)):
            meta["is_yield"] = True
            meta["yield_kind"] = node_type
        elif isinstance(ast_node, py_ast.TryExceptFinally):
            meta["is_try_stmt"] = True
        elif isinstance(ast_node, py_ast.Await):
            meta["is_await"] = True
        elif isinstance(ast_node, py_ast.Break):
            meta["is_break"] = True
        elif isinstance(ast_node, py_ast.Continue):
            meta["is_continue"] = True
        elif isinstance(ast_node, py_ast.GlobalDecl):
            meta["is_global_decl"] = True
            meta["declared_name"] = self._ast_value(getattr(ast_node, "name", None))
        elif isinstance(ast_node, py_ast.NonlocalDecl):
            meta["is_nonlocal_decl"] = True
            meta["declared_name"] = self._ast_value(getattr(ast_node, "name", None))
        elif isinstance(ast_node, py_ast.TypeAlias):
            meta["is_type_alias"] = True
            meta["alias_name"] = getattr(ast_node, "name", "")
        elif node_type == "Pass":
            meta["is_pass"] = True

        cfg_node = getattr(node, "cfg_node", None)
        if isinstance(cfg_node, cfg_graph.Yield):
            meta["cfg_yield"] = True

    @staticmethod
    def _ast_value(ast_node: Any) -> str:
        if ast_node is None:
            return ""
        if hasattr(ast_node, "toStr"):
            try:
                return ast_node.toStr()
            except Exception:
                pass
        return str(ast_node)

    # ── PDG edge pass-through ────────────────────────────────────────────

    def _build_pdg_edges(self, pdg: ProgramDependenceGraph) -> None:
        """Mirror PDG ``control`` and ``data`` edges as CPG edges.

        When SSA is active, DATA edge labels carry the SSA-renamed variable
        name (e.g. ``"x_1"`` instead of ``"x"``).  This is detected by
        inspecting Merge-block phi nodes that carry ``"x_1"`` style names.
        """
        # Pre-scan: detect SSA versions from Merge phi nodes
        ssa_versions: Dict[str, str] = {}
        for node in pdg.nodes:
            if node.kind != "stmt" or node.ast_node is None:
                continue
            if hasattr(node.ast_node, "toStr"):
                s = node.ast_node.toStr()
                if "=" in s and "_" in s:
                    for part in s.replace(" ", "").split(";"):
                        if "=" in part and "_" in part.split("=")[0]:
                            lhs = part.split("=")[0]
                            if "_" in lhs:
                                base = lhs.rsplit("_", 1)[0]
                                ssa_versions[base] = lhs
        for node in pdg.nodes:
            for pe in node.edges_out:
                kind = CPGEdgeKind(pe.kind)
                label = pe.label
                if kind == CPGEdgeKind.DATA and label:
                    versioned = ssa_versions.get(label, label)
                    if versioned != label:
                        label = versioned
                    source_entry = {"var": label.rsplit("_", 1)[0], "name": label}
                    target_entry = {"var": label.rsplit("_", 1)[0], "name": label}
                    if "_" in label.rsplit(".", 1)[-1]:
                        suffix = label.rsplit("_", 1)[-1]
                        if suffix.isdigit():
                            source_entry["version"] = int(suffix)
                            target_entry["version"] = int(suffix)
                    self._append_meta_entry(pe.source, "ssa_defs", source_entry)
                    self._append_meta_entry(pe.target, "ssa_uses", target_entry)
                self._add_edge(pe.source, pe.target, kind, label)

    # ── AST structure edges ──────────────────────────────────────────────

    def _build_ast_edges(
        self, pdg: ProgramDependenceGraph, pdg_ast_ids: Set[int]
    ) -> None:
        """Derive AST_CHILD edges from ``PDGNode.ast_node`` references.

        For every PDG node with an ``ast_node``, walks the AST from the
        function root to find parent→child relationships where **both**
        parent and child are represented as PDG nodes.  Only AST links
        that have PDG representations get edges.
        """
        root = getattr(pdg.cfg, "code", None)
        if root is None:
            return

        parent_map = _build_ast_parent_map(root, pdg_ast_set=pdg_ast_ids)

        # Build a reverse index: id(ast_node) → PDGNode
        ast_to_pdg: Dict[int, PDGNode] = {}
        for node in pdg.nodes:
            if node.ast_node is not None:
                ast_to_pdg[id(node.ast_node)] = node

        for child_ast_id, parent_ast in parent_map.items():
            parent_ast_id = id(parent_ast)
            child_pdg = ast_to_pdg.get(child_ast_id)
            parent_pdg = ast_to_pdg.get(parent_ast_id)
            if child_pdg is None or parent_pdg is None:
                continue
            if child_pdg is parent_pdg:
                continue
            self._add_edge(
                parent_pdg,
                child_pdg,
                CPGEdgeKind.AST_CHILD,
                _safe_type_name(child_pdg.ast_node),
            )

    # ── CFG edges ────────────────────────────────────────────────────────

    def _build_cfg_edges(self, fname: str, pdg: ProgramDependenceGraph) -> None:
        """Derive CFG traversal edges from the CFG embedded in *pdg.cfg*.

        Maps CFG block successors to PDG anchor nodes, then creates
        ``CFG_NEXT``, ``CFG_BRANCH_TRUE``, ``CFG_BRANCH_FALSE``, and
        ``CFG_EXCEPT`` edges between PDG nodes representing the connected
        blocks.
        """
        cfg = pdg.cfg

        # Build an index: id(cfg_node) → [PDGNode, ...]
        for node in pdg.nodes:
            if node.cfg_node is not None:
                cid = id(node.cfg_node)
                self._cfg_node_to_pdg.setdefault(cid, []).append(node)

        # Walk reachable CFG blocks.
        entry_term = getattr(cfg, "entryTerminal", None)
        if entry_term is None:
            return

        reachable = self._reachable_cfg_blocks(entry_term)
        for block in reachable:
            src_anchors = self._cfg_node_to_pdg.get(id(block), [])
            if not src_anchors:
                continue
            src_pdg = src_anchors[0]  # Use the first anchor node as source

            for exit_name, target_block in block.next.items():
                tgt_anchors = self._cfg_node_to_pdg.get(id(target_block), [])
                if not tgt_anchors:
                    continue
                tgt_pdg = tgt_anchors[0]

                kind = self._classify_cfg_exit(exit_name)
                if kind is not None:
                    self._add_edge(src_pdg, tgt_pdg, kind, exit_name)

    @staticmethod
    def _classify_cfg_exit(exit_name: str) -> Optional[CPGEdgeKind]:
        """Map a CFG exit name to a :class:`CPGEdgeKind`."""
        if exit_name == "normal" or exit_name == "entry":
            return CPGEdgeKind.CFG_NEXT
        if exit_name == "true":
            return CPGEdgeKind.CFG_BRANCH_TRUE
        if exit_name == "false":
            return CPGEdgeKind.CFG_BRANCH_FALSE
        if exit_name in ("fail", "error", "yield"):
            return CPGEdgeKind.CFG_EXCEPT
        if isinstance(exit_name, int):
            # TypeSwitch case index → CFG_NEXT with label
            return CPGEdgeKind.CFG_NEXT
        return None

    @staticmethod
    def _reachable_cfg_blocks(
        entry: cfg_graph.CFGBlock,
    ) -> List[cfg_graph.CFGBlock]:
        """BFS from *entry* returning all reachable CFG blocks."""
        visited: Set[int] = set()
        order: List[cfg_graph.CFGBlock] = []
        queue: deque[cfg_graph.CFGBlock] = deque([entry])
        while queue:
            block = queue.popleft()
            bid = id(block)
            if bid in visited:
                continue
            visited.add(bid)
            order.append(block)
            for nxt in block.forward():
                if nxt is not None and id(nxt) not in visited:
                    queue.append(nxt)
        return order

    # ── Call graph edges ─────────────────────────────────────────────────

    def _build_call_edges(self) -> None:
        """Derive ``CALL`` and ``RETURN_EDGE`` edges from the registered
        ``CallGraph``.

        ``CALL`` edges link the caller's exit anchor to the callee's entry.
        ``RETURN_EDGE`` edges link the callee's exit back to the caller's
        exit (enabling bidirectional interprocedural traversal).
        """
        if self._call_graph is None:
            return
        for caller_name, callee_name in self._call_graph.edges():
            caller_pdg = self._pdgs.get(caller_name)
            callee_pdg = self._pdgs.get(callee_name)
            if caller_pdg is None or callee_pdg is None:
                continue
            caller_entry = caller_pdg.entry
            callee_entry = callee_pdg.entry
            caller_exit = (
                next((n for n in caller_pdg.exit_nodes), None) or caller_entry
            )
            callee_exit = (
                next((n for n in callee_pdg.exit_nodes), None) or callee_entry
            )
            call_site = (
                self._find_call_site_node(caller_pdg, callee_name) or caller_exit
            )
            if call_site is not None and callee_entry is not None:
                self._add_edge(call_site, callee_entry, CPGEdgeKind.CALL, callee_name)
            if callee_exit is not None and call_site is not None:
                self._add_edge(
                    callee_exit, call_site, CPGEdgeKind.RETURN_EDGE, caller_name
                )

    def _find_call_site_node(
        self, caller_pdg: ProgramDependenceGraph, callee_name: str
    ) -> Optional[PDGNode]:
        callee_tail = callee_name.rsplit(".", 1)[-1]
        for node in caller_pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            for call_name in self._walk_call_names(ast_node):
                if (
                    call_name == callee_name
                    or call_name == callee_tail
                    or call_name.endswith("." + callee_tail)
                ):
                    return node
        return None

    @classmethod
    def _walk_call_names(cls, ast_node: Any) -> Iterator[str]:
        if isinstance(ast_node, py_ast.Call):
            call_name = cls._resolve_call_name(ast_node)
            if call_name:
                yield call_name
        if isinstance(ast_node, py_ast.leafTypes):
            return
        if hasattr(ast_node, "children"):
            for child in ast_node.children():
                if isinstance(child, (list, tuple)):
                    for item in child:
                        if item is not None:
                            yield from cls._walk_call_names(item)
                elif child is not None:
                    yield from cls._walk_call_names(child)

    # ── Guard / Phi / Lambda metadata ────────────────────────────────────

    def _build_guard_metadata(self, pdg: ProgramDependenceGraph) -> None:
        """Detect ``isinstance`` guards in ``Switch.condition`` and mark the
        corresponding PDG anchor nodes with metadata consumed by the taint
        engine to strip taint on ``CFG_BRANCH_TRUE`` edges.
        """
        cfg = pdg.cfg
        entry_term = getattr(cfg, "entryTerminal", None)
        if entry_term is None:
            return
        for block in self._reachable_cfg_blocks(entry_term):
            if not isinstance(block, cfg_graph.Switch):
                continue
            cond = getattr(block, "condition", None)
            if cond is None:
                continue
            if not isinstance(cond, py_ast.Call):
                continue
            call_name = self._resolve_call_name(cond)
            if call_name != "isinstance":
                continue
            args = getattr(cond, "args", None)
            if args is None or len(args) < 1:
                continue
            first_arg = args[0]
            if not isinstance(first_arg, py_ast.Local):
                continue
            guarded_var = getattr(first_arg, "name", "") or str(first_arg)
            src_anchors = self._cfg_node_to_pdg.get(id(block), [])
            for anchor in src_anchors:
                if anchor.kind == "cond":
                    anchor.label = f"isinstance_guard:{guarded_var}"
                    meta = self._meta_for(anchor)
                    meta["isinstance_guard"] = True
                    meta["guarded_var"] = guarded_var
                    break

    @staticmethod
    def _resolve_call_name(call_node: Any) -> Optional[str]:
        if not isinstance(call_node, py_ast.Call):
            return None
        expr = getattr(call_node, "expr", None)
        if expr is None:
            return None
        if isinstance(expr, py_ast.Local):
            n = getattr(expr, "name", None)
            return str(n) if n is not None and isinstance(n, str) else None
        if hasattr(expr, "children"):
            parts: List[str] = []
            for child in expr.children():
                if isinstance(child, (list, tuple)) or child is None:
                    continue
                if isinstance(child, py_ast.Local):
                    n = getattr(child, "name", None)
                    if isinstance(n, str):
                        parts.append(n)
            return ".".join(parts) if parts else None
        return None

    def _build_phi_metadata(self, pdg: ProgramDependenceGraph) -> None:
        """Mark PDG nodes that correspond to Merge-block phi operations.

        Sets the node kind to ``"phi"`` and extracts the merged variable
        name into the node label.
        """
        cfg = pdg.cfg
        entry_term = getattr(cfg, "entryTerminal", None)
        if entry_term is None:
            return
        for block in self._reachable_cfg_blocks(entry_term):
            if not isinstance(block, cfg_graph.Merge):
                continue
            phis = getattr(block, "phi", [])
            if not phis:
                continue
            contents = pdg.get_cfg_contents(block)
            for n in contents:
                if n.kind == "stmt" and n.ast_node in phis:
                    n.kind = "phi"
                    if hasattr(n.ast_node, "toStr"):
                        s = n.ast_node.toStr().replace(" ", "")
                        if "=" in s:
                            var = s.split("=")[0]
                            if "_" in var:
                                n.label = var
                                base, _, suffix = var.rpartition("_")
                                meta = self._meta_for(n)
                                meta["node_type"] = "Phi"
                                meta["phi_vars"] = [base or var]
                                entry: Dict[str, Any] = {
                                    "var": base or var,
                                    "name": var,
                                }
                                if suffix.isdigit():
                                    entry["version"] = int(suffix)
                                self._append_meta_entry(n, "ssa_defs", entry)

    def _build_lambda_nodes(self, pdg: ProgramDependenceGraph) -> None:
        """Create synthetic PDG nodes for Lambda expressions discovered
        during AST traversal, with ``AST_CHILD`` edges from their parent.
        """
        for node in list(pdg.nodes):
            ast_node = node.ast_node
            if ast_node is None:
                continue
            if type(ast_node).__name__ != "Lambda":
                continue
            body = getattr(ast_node, "body", None)
            if body is None:
                continue
            lambda_label = f"<lambda@{getattr(ast_node, 'lineno', 0)}>"
            l_node = pdg.add_node(
                "entry", cfg_node=node.cfg_node, label=lambda_label,
            )
            self._node_meta[l_node.node_id] = {
                "node_type": "Lambda",
                "lineno": getattr(ast_node, "lineno", 0) or 0,
                "col": getattr(ast_node, "col", getattr(ast_node, "col_offset", 0))
                or 0,
                "value": lambda_label,
                "func_name": self._meta_for(node).get("func_name", ""),
                "kind": l_node.kind,
                "lambda_name": lambda_label,
            }
            self._add_edge(node, l_node, CPGEdgeKind.AST_CHILD, "lambda_body")
            for child in self._walk_ast_names(body):
                self._add_edge(l_node, node, CPGEdgeKind.DATA, child)
            self._add_edge(l_node, node, CPGEdgeKind.CFG_NEXT, "lambda_exit")

    @staticmethod
    def _walk_ast_names(node: Any) -> List[str]:
        names: List[str] = []
        if isinstance(node, py_ast.Local):
            n = getattr(node, "name", None)
            if n:
                names.append(n)
            return names
        if isinstance(node, py_ast.leafTypes):
            return names
        if hasattr(node, "children"):
            for child in node.children():
                if isinstance(child, (list, tuple)):
                    for item in child:
                        names.extend(
                            CodePropertyGraph._walk_ast_names(item)
                        )
                elif child is not None:
                    names.extend(
                        CodePropertyGraph._walk_ast_names(child)
                    )
        return names

    def _build_scope_edges(self, fname: str, pdg: ProgramDependenceGraph) -> None:
        """Create cross-scope DATA edges for ``global`` and ``nonlocal``
        declarations, linking the declaration node to prior definitions
        of the same variable name in enclosing/module scopes.
        """
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            var_name = ""
            scope_kind = ""
            if isinstance(ast_node, py_ast.GlobalDecl):
                scope_kind = "global"
                local = getattr(ast_node, "name", None)
                var_name = getattr(local, "name", "") or str(local or "")
            elif isinstance(ast_node, py_ast.NonlocalDecl):
                scope_kind = "nonlocal"
                local = getattr(ast_node, "name", None)
                var_name = getattr(local, "name", "") or str(local or "")
            else:
                continue
            if not var_name:
                continue
            meta = self._meta_for(node)
            meta["scope_decl"] = scope_kind
            meta["scope_var"] = var_name
            for other_fname, other_pdg in self._pdgs.items():
                if other_fname == fname and scope_kind != "global":
                    continue
                for other_node in other_pdg.nodes:
                    if other_node is node:
                        continue
                    for pe in other_node.edges_out:
                        if pe.kind == "data" and pe.label == var_name:
                            self._add_edge(
                                other_node,
                                node,
                                CPGEdgeKind.DATA,
                                label=f"{scope_kind}:{var_name}",
                            )

    def _build_import_edges(self, fname: str, pdg: ProgramDependenceGraph) -> None:
        """Create DATA edges from import statement nodes to downstream
        use sites that reference the imported name.

        In the pyflow AST, both ``import X`` and ``from X import Y``
        produce an ``Import`` expression node (distinguished by the
        ``fromlist`` field).  The imported name is stored in
        ``Import.name``; from-imports have a non-empty ``fromlist``.
        """
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            import_name = ""
            fromlist: Any = None
            if isinstance(ast_node, py_ast.Import):
                import_name = getattr(ast_node, "name", "") or ""
                fromlist = getattr(ast_node, "fromlist", None)
            else:
                continue
            if not import_name:
                continue
            local_name = import_name.split(".")[0] if import_name else ""
            meta = self._meta_for(node)
            meta["import_name"] = import_name
            meta["import_local"] = local_name
            meta["import_is_from"] = bool(fromlist)
            if fromlist:
                imported_names: List[str] = []
                if isinstance(fromlist, (list, tuple)):
                    for item in fromlist:
                        n = getattr(item, "name", None) or str(item or "")
                        if n:
                            imported_names.append(n)
                meta["import_from_names"] = imported_names
            for other_node in pdg.nodes:
                if other_node is node:
                    continue
                for pe in other_node.edges_in:
                    if (
                        pe.kind == "data"
                        and pe.label == local_name
                        and pe.source is not node
                    ):
                        self._add_edge(
                            node,
                            other_node,
                            CPGEdgeKind.DATA,
                            label=f"import:{local_name}",
                        )

    def _build_collection_metadata(
        self, fname: str, pdg: ProgramDependenceGraph
    ) -> None:
        """Annotate assignment nodes whose RHS is a collection literal
        (``BuildList``, ``BuildTuple``, ``BuildSet``, ``BuildMap``) with
        the names of elements, enabling the taint engine to propagate
        taint from elements into the collection.
        """
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            if not isinstance(ast_node, py_ast.Assign):
                continue
            rhs = getattr(ast_node, "expr", None)
            if rhs is None:
                continue
            element_names: List[str] = []
            if isinstance(rhs, py_ast.BuildList):
                element_names = self._extract_local_names_from_args(rhs)
            elif isinstance(rhs, py_ast.BuildTuple):
                element_names = self._extract_local_names_from_args(rhs)
            elif isinstance(rhs, py_ast.BuildSet):
                element_names = self._extract_local_names_from_args(rhs)
            elif isinstance(rhs, py_ast.BuildMap):
                element_names = self._extract_local_names_from_args(rhs)
            else:
                continue
            if element_names:
                meta = self._meta_for(node)
                meta["collection_of"] = element_names
                meta["collection_type"] = type(rhs).__name__

    @staticmethod
    def _extract_local_names_from_args(expr: Any) -> List[str]:
        names: List[str] = []
        args = getattr(expr, "args", None)
        if args is None:
            return names
        if isinstance(args, (list, tuple)):
            for arg in args:
                if isinstance(arg, py_ast.Local):
                    n = getattr(arg, "name", "")
                    if n:
                        names.append(n)
        return names

    def _build_async_metadata(
        self, fname: str, pdg: ProgramDependenceGraph
    ) -> None:
        """Mark nodes containing ``await`` expressions and nodes that
        represent lowered async constructs (``interpreter_aiter``,
        ``interpreter_aenter``, ``interpreter_aexit`` calls).
        """
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            if isinstance(ast_node, py_ast.Await):
                meta = self._meta_for(node)
                meta["async_await"] = True
                inner = getattr(ast_node, "expr", None)
                if isinstance(inner, py_ast.Local):
                    n = getattr(inner, "name", "")
                    if n:
                        meta["await_expr_var"] = n
                continue
            for child in _iter_ast_children(ast_node):
                if isinstance(child, py_ast.Await):
                    meta = self._meta_for(node)
                    meta["async_await"] = True
                    break
            call_name = self._resolve_call_name(ast_node) if isinstance(
                ast_node, py_ast.Call
            ) else None
            if call_name and call_name.startswith("interpreter_a"):
                meta = self._meta_for(node)
                meta["async_lowered"] = True
                meta["async_lowered_kind"] = call_name

    # ── Statement-type-specific metadata ────────────────────────────

    def _build_annassign_metadata(
        self, fname: str, pdg: ProgramDependenceGraph
    ) -> None:
        """Annotate AnnAssign nodes with the target variable name and
        annotation type string.
        """
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            if not isinstance(ast_node, py_ast.AnnAssign):
                continue
            meta = self._meta_for(node)
            meta["ann_assign"] = True
            target = getattr(ast_node, "target", None)
            if isinstance(target, py_ast.Local):
                meta["ann_target"] = getattr(target, "name", "") or ""
            ann = getattr(ast_node, "annotation", None)
            if ann is not None:
                meta["ann_type"] = _safe_type_name(ann)

    def _build_delete_metadata(
        self, fname: str, pdg: ProgramDependenceGraph
    ) -> None:
        """Annotate Delete nodes with the deleted variable name(s)."""
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            if not isinstance(ast_node, py_ast.Delete):
                continue
            meta = self._meta_for(node)
            meta["is_delete"] = True
            lcl = getattr(ast_node, "lcl", None)
            if isinstance(lcl, py_ast.Local):
                meta["deleted_var"] = getattr(lcl, "name", "") or ""

    def _build_raise_metadata(
        self, fname: str, pdg: ProgramDependenceGraph
    ) -> None:
        """Annotate Raise nodes with metadata about the raised exception."""
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            if not isinstance(ast_node, py_ast.Raise):
                continue
            meta = self._meta_for(node)
            meta["is_raise"] = True
            exc = getattr(ast_node, "exception", None)
            if isinstance(exc, py_ast.Local):
                meta["raise_var"] = getattr(exc, "name", "") or ""

    def _build_assert_metadata(
        self, fname: str, pdg: ProgramDependenceGraph
    ) -> None:
        """Annotate Assert nodes with metadata."""
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            if not isinstance(ast_node, py_ast.Assert):
                continue
            meta = self._meta_for(node)
            meta["is_assert"] = True

    def _build_try_metadata(
        self, fname: str, pdg: ProgramDependenceGraph
    ) -> None:
        """Annotate TryExceptFinally nodes with handler metadata."""
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            if not isinstance(ast_node, py_ast.TryExceptFinally):
                continue
            meta = self._meta_for(node)
            meta["is_try_stmt"] = True
            handlers_info = []
            for handler in (getattr(ast_node, "handlers", None) or ()):
                htype = getattr(handler, "type", None)
                hval = getattr(handler, "value", None)
                type_name = None
                if htype is not None:
                    if isinstance(htype, py_ast.Local):
                        type_name = getattr(htype, "name", None)
                    elif hasattr(htype, "toStr"):
                        type_name = str(htype.toStr())
                caught_var = None
                if hval is not None:
                    if isinstance(hval, py_ast.Local):
                        caught_var = getattr(hval, "name", None)
                handlers_info.append({
                    "type_name": type_name,
                    "caught_var": caught_var,
                })
            meta["handlers"] = handlers_info
            else_blk = getattr(ast_node, "else_", None)
            finally_blk = getattr(ast_node, "finally_", None)
            meta["has_else"] = (
                else_blk is not None and len(else_blk.blocks) > 0
            )
            meta["has_finally"] = (
                finally_blk is not None and len(finally_blk.blocks) > 0
            )

    def _build_loop_metadata(
        self, fname: str, pdg: ProgramDependenceGraph
    ) -> None:
        """Mark loop header PDG nodes and collect for-loop variable mappings."""
        cfg = pdg.cfg
        entry_term = getattr(cfg, "entryTerminal", None)
        if entry_term is None:
            return

        processed: Set[int] = set()
        on_stack: Set[int] = set()
        loop_cfg_blocks: Set[int] = set()

        def _dfs(block: cfg_graph.CFGBlock) -> None:
            bid = id(block)
            if bid in processed:
                if bid in on_stack:
                    loop_cfg_blocks.add(bid)
                return
            on_stack.add(bid)
            processed.add(bid)
            for child in block.forward():
                if child is not None:
                    _dfs(child)
            on_stack.discard(bid)

        _dfs(entry_term)

        if not loop_cfg_blocks:
            return

        for_loop_vars: List[Tuple[str, str]] = []
        code = getattr(cfg, "code", None)
        if code is not None:
            CodePropertyGraph._collect_for_loop_vars(code.ast, for_loop_vars)

        for node in pdg.nodes:
            cfg_node = getattr(node, "cfg_node", None)
            if cfg_node is not None and id(cfg_node) in loop_cfg_blocks:
                meta = self._meta_for(node)
                meta["loop_header"] = True
                if for_loop_vars:
                    meta["for_loop_vars"] = list(for_loop_vars)

    @staticmethod
    def _collect_for_loop_vars(
        suite: py_ast.Suite,
        result: List[Tuple[str, str]],
    ) -> None:
        for stmt in getattr(suite, "blocks", []):
            if isinstance(stmt, py_ast.For):
                iter_name = (
                    stmt.iterator.name
                    if isinstance(stmt.iterator, py_ast.Local) else ""
                )
                index_name = (
                    stmt.index.name
                    if isinstance(stmt.index, py_ast.Local) else ""
                )
                if iter_name and index_name:
                    result.append((iter_name, index_name))
                CodePropertyGraph._collect_for_loop_vars(stmt.body, result)
            elif hasattr(stmt, "body") and isinstance(
                getattr(stmt, "body", None), py_ast.Suite
            ):
                CodePropertyGraph._collect_for_loop_vars(
                    stmt.body, result
                )

    def _build_statement_metadata(
        self, fname: str, pdg: ProgramDependenceGraph
    ) -> None:
        """Best-effort metadata for AST kinds Ansede models explicitly.

        PyFlow lowers some stdlib AST constructs before the CPG layer sees
        them, so these annotations are intentionally opportunistic.
        """
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            self._annotate_statement_meta(node)

    def _build_origin_ast_metadata(
        self, pdg: ProgramDependenceGraph
    ) -> None:
        """Annotate PDG nodes with structural context from Suite.origin_ast.

        The CFGTransformer lowers structured AST nodes (For, While, Switch,
        TypeSwitch) into flat Suite blocks.  The ``origin_ast`` field on each
        Suite lets us recover that structure and tag PDG nodes with metadata
        such as ``is_loop_body`` or ``is_switch_branch``.
        """
        for node in pdg.nodes:
            cfg_node = getattr(node, "cfg_node", None)
            if cfg_node is None:
                continue
            if not isinstance(cfg_node, cfg_graph.Suite):
                continue
            origin = getattr(cfg_node, "origin_ast", None)
            if origin is None:
                continue
            meta = self._meta_for(node)
            if isinstance(origin, (py_ast.For, py_ast.While)):
                meta["is_loop_body"] = True
                meta["loop_kind"] = (
                    "for" if isinstance(origin, py_ast.For) else "while"
                )
            elif isinstance(origin, py_ast.Switch):
                meta["is_switch_branch"] = True
            elif isinstance(origin, py_ast.TypeSwitch):
                meta["is_type_switch_branch"] = True
            elif isinstance(origin, str):
                if origin in ("With", "AsyncWith"):
                    meta["is_with_body"] = True
                elif origin == "AugAssign":
                    meta["is_augassign"] = True
                elif origin == "Match":
                    meta["is_match"] = True

    # ── Navigation ───────────────────────────────────────────────────────

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

    # ── Typed navigation shortcuts ───────────────────────────────────────

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

    # ── Typed meta accessors (convenience wrappers over node_meta) ────

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

    # ── Unified queries ──────────────────────────────────────────────────

    def forward_slice_all(
        self,
        seeds: Sequence[PDGNode],
        *,
        kinds: Optional[Set[CPGEdgeKind]] = None,
    ) -> Set[PDGNode]:
        """Compute a forward slice through **all** layers of the CPG.

        Unlike :meth:`~pyflow.analysis.pdg.graph.ProgramDependenceGraph.forward_slice`,
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
        pdg = None
        for pdg_candidate in self._pdgs.values():
            anchor = pdg_candidate.get_cfg_anchor(cfg_block)
            if anchor is not None:
                anchor_edges = self._cpg_edges_out.get(anchor.node_id, ())
                for e in anchor_edges:
                    if e.kind == CPGEdgeKind.CFG_EXCEPT:
                        return True
                break
        return False

    # ── Query API ────────────────────────────────────────────────────────

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
        seeds = self.find_nodes(
            label_contains=label_substring, func_name=func_name
        )
        if not seeds:
            return set()
        result: Set[PDGNode] = set(seeds)
        kinds: Set[CPGEdgeKind] = {CPGEdgeKind.DATA}
        for seed in seeds:
            result |= self.forward_slice_all([seed], kinds=kinds)
            result |= self.backward_slice_all([seed], kinds=kinds)
        return result

    # ── Query helpers ────────────────────────────────────────────────────

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
                nodes.append({
                    "id": n.node_id,
                    "kind": n.kind,
                    "label": n.label,
                    "func": getattr(pdg.cfg, "codeName", lambda: "")() or "",
                    "meta": dict(self._node_meta.get(n.node_id, {})),
                })
        edges: List[Dict[str, Any]] = []
        for e in self.all_edges():
            edges.append({
                "source": e.source.node_id,
                "target": e.target.node_id,
                "kind": e.kind.value,
                "label": e.label,
            })
        defs_dict: Dict[str, List[int]] = {
            var: [n.node_id for n in ns]
            for var, ns in self.defs.items()
        }
        uses_dict: Dict[str, List[int]] = {
            var: [n.node_id for n in ns]
            for var, ns in self.uses.items()
        }
        return {
            "functions": list(self.functions),
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
