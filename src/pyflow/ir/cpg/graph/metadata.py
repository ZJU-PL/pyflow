"""Specialized statement and origin metadata construction."""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.ir.pdg.graph import PDGNode, ProgramDependenceGraph
from pyflow.language.python import ast as py_ast
from .model import CPGEdgeKind, _iter_ast_children, _safe_type_name


class _GraphMetadataMixin:
    """Internal mixin composed by CodePropertyGraph."""

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
                "entry",
                cfg_node=node.cfg_node,
                label=lambda_label,
            )
            self._promote_new_node_id(l_node, pdg)
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
                        names.extend(_GraphMetadataMixin._walk_ast_names(item))
                elif child is not None:
                    names.extend(_GraphMetadataMixin._walk_ast_names(child))
        return names

    def _build_scope_edges(self, fname: str, pdg: ProgramDependenceGraph) -> None:
        """Create cross-scope DATA edges for ``global`` and ``nonlocal``
        declarations, linking the declaration node to prior definitions
        of the same variable name in enclosing/module scopes.
        """
        if not self._data_definitions_by_label:
            for other_fname, other_pdg in self._pdgs.items():
                for other_node in other_pdg.nodes:
                    for edge in other_node.edges_out:
                        if edge.kind == "data" and edge.label:
                            self._data_definitions_by_label.setdefault(
                                edge.label, []
                            ).append((other_fname, other_node))

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
            for other_fname, other_node in self._data_definitions_by_label.get(
                var_name, ()
            ):
                if other_fname == fname and scope_kind != "global":
                    continue
                if other_node is node:
                    continue
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
        data_users: Dict[str, Set[PDGNode]] = {}
        for candidate in pdg.nodes:
            for edge in candidate.edges_in:
                if edge.kind == "data" and edge.label:
                    data_users.setdefault(edge.label, set()).add(candidate)

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
            for other_node in data_users.get(local_name, ()):
                if other_node is node:
                    continue
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

    def _build_async_metadata(self, fname: str, pdg: ProgramDependenceGraph) -> None:
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
            call_name = (
                self._resolve_call_name(ast_node)
                if isinstance(ast_node, py_ast.Call)
                else None
            )
            if call_name and call_name.startswith("interpreter_a"):
                meta = self._meta_for(node)
                meta["async_lowered"] = True
                meta["async_lowered_kind"] = call_name

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

    def _build_delete_metadata(self, fname: str, pdg: ProgramDependenceGraph) -> None:
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

    def _build_raise_metadata(self, fname: str, pdg: ProgramDependenceGraph) -> None:
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

    def _build_assert_metadata(self, fname: str, pdg: ProgramDependenceGraph) -> None:
        """Annotate Assert nodes with metadata."""
        for node in pdg.nodes:
            ast_node = node.ast_node
            if ast_node is None:
                continue
            if not isinstance(ast_node, py_ast.Assert):
                continue
            meta = self._meta_for(node)
            meta["is_assert"] = True

    def _build_try_metadata(self, fname: str, pdg: ProgramDependenceGraph) -> None:
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
            for handler in getattr(ast_node, "handlers", None) or ():
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
                handlers_info.append(
                    {
                        "type_name": type_name,
                        "caught_var": caught_var,
                    }
                )
            meta["handlers"] = handlers_info
            else_blk = getattr(ast_node, "else_", None)
            finally_blk = getattr(ast_node, "finally_", None)
            meta["has_else"] = else_blk is not None and len(else_blk.blocks) > 0
            meta["has_finally"] = (
                finally_blk is not None and len(finally_blk.blocks) > 0
            )

    def _build_loop_metadata(self, fname: str, pdg: ProgramDependenceGraph) -> None:
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

        for_loop_vars: List[Tuple[str, str]] = []
        code = getattr(cfg, "code", None)
        if code is not None:
            self._collect_for_loop_vars(code.ast, for_loop_vars)

        for node in pdg.nodes:
            cfg_node = getattr(node, "cfg_node", None)
            ast_node = getattr(node, "ast_node", None)
            is_structured_for = isinstance(ast_node, py_ast.For)
            if isinstance(cfg_node, cfg_graph.ForIter):
                index = getattr(cfg_node, "index", None)
                index_name = getattr(index, "name", None)
                if index_name:
                    self._meta_for(node)["for_loop_index"] = index_name
            if (
                cfg_node is not None and id(cfg_node) in loop_cfg_blocks
            ) or is_structured_for:
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
                    if isinstance(stmt.iterator, py_ast.Local)
                    else ""
                )
                index_name = (
                    stmt.index.name if isinstance(stmt.index, py_ast.Local) else ""
                )
                if iter_name and index_name:
                    result.append((iter_name, index_name))
                _GraphMetadataMixin._collect_for_loop_vars(stmt.body, result)
            elif hasattr(stmt, "body") and isinstance(
                getattr(stmt, "body", None), py_ast.Suite
            ):
                _GraphMetadataMixin._collect_for_loop_vars(stmt.body, result)

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

    def _build_origin_ast_metadata(self, pdg: ProgramDependenceGraph) -> None:
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
                meta["loop_kind"] = "for" if isinstance(origin, py_ast.For) else "while"
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
