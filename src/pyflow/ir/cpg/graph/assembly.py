"""Structural CPG assembly from PDG, CFG, AST, and call-graph inputs."""

from __future__ import annotations
from collections import deque
from typing import Any, Dict, Iterator, List, Optional, Set
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.ir.pdg.graph import PDGNode, ProgramDependenceGraph
from pyflow.language.python import ast as py_ast
from .model import (
    CPGEdgeKind,
    _build_ast_parent_map,
    _iter_ast_children,
    _safe_type_name,
)


class _GraphAssemblyMixin:
    """Internal mixin composed by CodePropertyGraph."""

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
            self._promote_new_node_id(node, pdg)
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
        return isinstance(
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
        ) or node_type in {"With", "AsyncWith", "Pass"}

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

        # Materialize executable order inside each CFG block. PDG statement
        # nodes share their containing block as ``cfg_node``; without these
        # edges the CPG jumps from the block anchor directly to its successor
        # and graph analyses never execute the statements themselves.
        for anchors in self._cfg_node_to_pdg.values():
            local = [node for node in anchors if node in pdg.nodes]
            for source, target in zip(local, local[1:]):
                self._add_edge(source, target, CPGEdgeKind.CFG_NEXT, "statement")

        # Walk reachable CFG blocks.
        entry_term = getattr(cfg, "entryTerminal", None)
        if entry_term is None:
            return

        reachable = self._reachable_cfg_blocks(entry_term)
        for block in reachable:
            src_anchors = self._cfg_node_to_pdg.get(id(block), [])
            if not src_anchors:
                continue
            src_pdg = src_anchors[-1]

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
            caller_exit = next((n for n in caller_pdg.exit_nodes), None) or caller_entry
            callee_exit = next((n for n in callee_pdg.exit_nodes), None) or callee_entry
            call_site = (
                self._find_call_site_node(caller_pdg, callee_name) or caller_exit
            )
            if call_site is not None and callee_entry is not None:
                self._add_edge(call_site, callee_entry, CPGEdgeKind.CALL, callee_name)
            if callee_exit is not None and call_site is not None:
                self._add_edge(
                    callee_exit, call_site, CPGEdgeKind.RETURN_EDGE, caller_name
                )

    def _build_inferred_call_edges(self) -> None:
        """Add unambiguous intra-CPG call/return edges from call-site syntax.

        The optional repository call graph is often unavailable for a
        source-built, single-file CPG.  Local calls are nevertheless explicit
        in the PDG AST.  Resolving unique full or short names here gives every
        CPG client the same call/return supergraph and also preserves recursive
        self-edges, which the lightweight ``CallGraph`` intentionally omits.
        """

        by_short: Dict[str, List[str]] = {}
        for name in self._pdgs:
            by_short.setdefault(name.rsplit(".", 1)[-1], []).append(name)

        for caller_name, caller_pdg in self._pdgs.items():
            for call_site in caller_pdg.nodes:
                ast_node = call_site.ast_node
                if ast_node is None:
                    continue
                for raw_name in self._statement_call_names(ast_node):
                    candidates: List[str]
                    if raw_name in self._pdgs:
                        candidates = [raw_name]
                    else:
                        candidates = by_short.get(raw_name.rsplit(".", 1)[-1], [])
                    if len(candidates) != 1:
                        continue
                    callee_name = candidates[0]
                    callee_pdg = self._pdgs[callee_name]
                    callee_entry = callee_pdg.entry
                    if callee_entry is None:
                        continue
                    self._add_edge(
                        call_site, callee_entry, CPGEdgeKind.CALL, callee_name
                    )
                    for callee_exit in callee_pdg.exit_nodes:
                        self._add_edge(
                            callee_exit,
                            call_site,
                            CPGEdgeKind.RETURN_EDGE,
                            caller_name,
                        )

    def _find_call_site_node(
        self, caller_pdg: ProgramDependenceGraph, callee_name: str
    ) -> Optional[PDGNode]:
        callee_tail = callee_name.rsplit(".", 1)[-1]
        for node in caller_pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            for call_name in self._statement_call_names(ast_node):
                if (
                    call_name == callee_name
                    or call_name == callee_tail
                    or call_name.endswith("." + callee_tail)
                ):
                    return node
        return None

    @classmethod
    def _statement_call_names(cls, ast_node: Any) -> Iterator[str]:
        """Yield all calls owned by one PDG statement, excluding nested code."""

        if isinstance(ast_node, (py_ast.FunctionDef, py_ast.ClassDef)):
            return
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
                            yield from cls._statement_call_names(item)
                elif child is not None:
                    yield from cls._statement_call_names(child)
