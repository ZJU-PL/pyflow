"""
Program Dependence Graph (PDG) construction.

Construction sources:
- Control dependences are derived from the CDG constructed from a CFG.
- Data dependences are derived from the DDG constructed from dataflow IR and
  projected back onto PDG statement/condition nodes. Mandatory shared IR
  semantics supply local def/use edges for nodes outside the dataflow IR.

This module focuses on intraprocedural PDGs (single function).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from pyflow.ir.cfg import expandphi, ssa
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.ir.cdg import construct_cdg
from pyflow.ir.ddg import construct_ddg
from pyflow.ir.core import SymbolKind, ValueId, ensure_code_indexed, index_cfg
from pyflow.ir.dataflow import convert
from pyflow.ir.dataflow import graph as df_graph
from pyflow.language.python import ast as py_ast

from .graph import ProgramDependenceGraph, PDGNode


@dataclass(frozen=True)
class PDGConstructionOptions:
    include_control: bool = True
    include_data: bool = True
    run_ssa: bool = False
    expand_phi: bool = True


def _safe_ast_label(node: Any) -> str:
    if node is None:
        return ""
    try:
        return type(node).__name__
    except Exception:
        return "AST"


def _safe_cfg_label(node: Any) -> str:
    try:
        return type(node).__name__
    except Exception:
        return "CFG"


def _flatten_children(child: Any, into: List[Any]) -> None:
    """Recursively flatten nested tuples/lists into *into*, skipping Nones."""
    if child is None:
        return
    if isinstance(child, (list, tuple)):
        for item in child:
            _flatten_children(item, into)
    else:
        into.append(child)


def _iter_ast_children(node: Any) -> List[Any]:
    children: List[Any] = []
    if isinstance(node, (list, tuple)):
        _flatten_children(node, children)
        return children
    if not hasattr(node, "children"):
        return children
    for child in node.children():
        _flatten_children(child, children)
    return children


def _build_ast_parent_map(root: Any) -> Dict[Any, Any]:
    parents: Dict[Any, Any] = {}
    visited_code: Set[py_ast.Code] = set()

    def walk(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, (list, tuple)):
            for child in _iter_ast_children(node):
                walk(child)
            return
        if isinstance(node, py_ast.Code):
            if node in visited_code:
                return
            visited_code.add(node)

        if isinstance(node, py_ast.leafTypes):
            return

        for child in _iter_ast_children(node):
            parents[child] = node
            walk(child)

    walk(root)
    return parents


class PDGConstructor:
    """
    Construct a PDG from a CFG.

    Notes on precision:
    - If `run_ssa=True`, the constructor mutates the provided CFG by applying
      SSA renaming and (optionally) phi expansion.
    - Without SSA, data dependences are conservative (all defs may reach all
      uses for a given local).
    """

    __slots__ = ("options",)

    def __init__(self, options: PDGConstructionOptions = PDGConstructionOptions()):
        self.options = options

    def construct_from_cfg(self, cfg: cfg_graph.Code) -> ProgramDependenceGraph:
        if self.options.run_ssa:
            ssa.evaluate(None, cfg)
            if self.options.expand_phi:
                expandphi.evaluate(None, cfg)

        pdg = ProgramDependenceGraph(cfg)

        # Node materialization
        reachable = self._reachable_cfg_nodes(cfg.entryTerminal)
        self._add_pdg_nodes(pdg, reachable)
        parent_map = _build_ast_parent_map(getattr(cfg, "code", None))

        # Edges
        if self.options.include_control:
            self._add_control_edges_from_cdg(pdg)

        if self.options.include_data:
            self._add_data_edges(pdg, parent_map)

        return pdg

    def _reachable_cfg_nodes(
        self, entry: cfg_graph.CFGBlock
    ) -> List[cfg_graph.CFGBlock]:
        visited: Set[cfg_graph.CFGBlock] = set()
        order: List[cfg_graph.CFGBlock] = []
        stack: List[cfg_graph.CFGBlock] = [entry]
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            order.append(node)
            for nxt in node.forward():
                if nxt is not None and nxt not in visited:
                    stack.append(nxt)
        return order

    def _add_pdg_nodes(
        self, pdg: ProgramDependenceGraph, cfg_nodes: Sequence[cfg_graph.CFGBlock]
    ) -> None:
        for cnode in cfg_nodes:
            # Always create a block/anchor node so control dependence wiring is stable
            if isinstance(cnode, cfg_graph.Entry):
                anchor = pdg.add_node(
                    "entry", cfg_node=cnode, label=_safe_cfg_label(cnode)
                )
                pdg.entry = anchor
            elif isinstance(cnode, cfg_graph.Exit):
                anchor = pdg.add_node(
                    "exit", cfg_node=cnode, label=_safe_cfg_label(cnode)
                )
                pdg.exit_nodes.append(anchor)
            else:
                anchor = pdg.add_node(
                    "block", cfg_node=cnode, label=_safe_cfg_label(cnode)
                )

            pdg.set_cfg_anchor(cnode, anchor)
            pdg.add_cfg_content(cnode, anchor)

            # Block contents at statement/condition granularity
            if isinstance(cnode, cfg_graph.Suite):
                for op in list(getattr(cnode, "ops", ())):
                    n = pdg.add_node(
                        "stmt", cfg_node=cnode, ast_node=op, label=_safe_ast_label(op)
                    )
                    pdg.add_cfg_content(cnode, n)
            elif isinstance(cnode, cfg_graph.Switch):
                cond = cnode.condition
                n = pdg.add_node(
                    "cond", cfg_node=cnode, ast_node=cond, label=_safe_ast_label(cond)
                )
                pdg.add_cfg_content(cnode, n)
                pdg.set_cfg_anchor(cnode, n)
            elif isinstance(cnode, cfg_graph.TypeSwitch):
                cond = cnode.original.conditional
                n = pdg.add_node(
                    "cond", cfg_node=cnode, ast_node=cond, label=_safe_ast_label(cond)
                )
                pdg.add_cfg_content(cnode, n)
                pdg.set_cfg_anchor(cnode, n)
            elif isinstance(cnode, cfg_graph.ForIter):
                iterator = cnode.iterator
                n = pdg.add_node(
                    "cond",
                    cfg_node=cnode,
                    ast_node=iterator,
                    label=_safe_ast_label(iterator),
                )
                pdg.add_cfg_content(cnode, n)
                pdg.set_cfg_anchor(cnode, n)
            elif isinstance(cnode, cfg_graph.Merge):
                for phi in list(getattr(cnode, "phi", ())):
                    n = pdg.add_node(
                        "stmt", cfg_node=cnode, ast_node=phi, label=_safe_ast_label(phi)
                    )
                    pdg.add_cfg_content(cnode, n)

    def _add_control_edges_from_cdg(self, pdg: ProgramDependenceGraph) -> None:
        cdg = construct_cdg(pdg.cfg)
        for edge in cdg.get_all_edges():
            controller_anchor = pdg.get_cfg_anchor(edge.source.cfg_node)
            if controller_anchor is None:
                continue

            for dependent in set(pdg.get_cfg_contents(edge.target.cfg_node)):
                if dependent is controller_anchor:
                    continue
                controller_anchor.add_edge_to(dependent, "control", edge.label)

    def _resolve_pdg_node_for_ast(
        self,
        pdg: ProgramDependenceGraph,
        ast_node: Any,
        parent_map: Dict[Any, Any],
    ) -> Optional[PDGNode]:
        node = ast_node
        while node is not None:
            pdg_node = pdg.get_node_for_ast(node)
            if pdg_node is not None:
                return pdg_node
            node = parent_map.get(node)
        return None

    def _resolve_pdg_node_for_ddg_op(
        self,
        pdg: ProgramDependenceGraph,
        ddg_node: Any,
        parent_map: Dict[Any, Any],
    ) -> Optional[PDGNode]:
        ir = ddg_node.ir_node
        if isinstance(ir, df_graph.Entry):
            return pdg.entry
        if isinstance(ir, df_graph.GenericOp):
            return self._resolve_pdg_node_for_ast(pdg, ir.op, parent_map)
        return None

    def _normalize_slot_label(self, slot: Any) -> str:
        names = getattr(slot, "names", None)
        if names:
            for local in names:
                if isinstance(local, py_ast.Local) and local.name is not None:
                    return local.name

        name = getattr(slot, "name", None)
        if isinstance(name, py_ast.Local):
            return name.name or "local"
        if isinstance(name, str):
            return name
        nested_name = getattr(name, "name", None)
        if isinstance(nested_name, str):
            return nested_name

        return repr(slot)

    def _ddg_edge_label(self, edge: Any) -> str:
        if edge.kind == "memory":
            if getattr(edge, "location", None) is not None:
                return f"{edge.label}@{edge.location!r}"
            return edge.label

        slot_node = None
        if getattr(edge.source, "category", None) == "slot":
            slot_node = edge.source
        elif getattr(edge.target, "category", None) == "slot":
            slot_node = edge.target

        if slot_node is not None:
            return self._normalize_slot_label(slot_node.ir_node)
        return edge.label

    def _add_data_edges_from_ddg(
        self,
        pdg: ProgramDependenceGraph,
        parent_map: Dict[Any, Any],
    ) -> Set[PDGNode]:
        root_code = getattr(pdg.cfg, "code", None)
        if root_code is None:
            return set()

        ddg = construct_ddg(convert.evaluateCode(None, root_code))
        op_to_pdg: Dict[Any, PDGNode] = {}
        backed_nodes: Set[PDGNode] = set()

        for ddg_node in ddg.nodes:
            if getattr(ddg_node, "category", None) != "op":
                continue
            pdg_node = self._resolve_pdg_node_for_ddg_op(pdg, ddg_node, parent_map)
            if pdg_node is not None:
                op_to_pdg[ddg_node] = pdg_node
                backed_nodes.add(pdg_node)

        for start_ddg, start_pdg in op_to_pdg.items():
            worklist: List[Tuple[Any, str]] = []
            seen: Set[Tuple[Any, str]] = set()

            for edge in start_ddg.edges_out:
                state = (edge.target, self._ddg_edge_label(edge))
                worklist.append(state)
                seen.add(state)

            while worklist:
                current, label = worklist.pop()
                current_pdg = op_to_pdg.get(current)

                if current_pdg is not None:
                    if current_pdg is not start_pdg:
                        start_pdg.add_edge_to(current_pdg, "data", label)
                    continue

                for edge in current.edges_out:
                    next_label = label or self._ddg_edge_label(edge)
                    state = (edge.target, next_label)
                    if state in seen:
                        continue
                    seen.add(state)
                    worklist.append(state)

        return backed_nodes

    def _add_semantic_data_edges(self, pdg: ProgramDependenceGraph) -> None:
        root_code = getattr(pdg.cfg, "code", None)
        if root_code is None:
            return
        catalog = ensure_code_indexed(root_code)
        # CFG transformation/revision and CDG construction already synchronize
        # this catalog.  Re-index only when a caller supplied a raw CFG that
        # has never been registered; rebuilding semantics here for every PDG
        # used to duplicate one of the most expensive construction passes.
        try:
            catalog.block_id(pdg.cfg.entryTerminal, root_code)
        except KeyError:
            index_cfg(catalog, pdg.cfg)
        procedure = catalog.procedure(root_code)

        var_to_defs: Dict[object, List[PDGNode]] = {}
        if pdg.entry is not None:
            for symbol in catalog.symbols:
                if (
                    symbol.id.scope == procedure.root_scope
                    and symbol.kind is SymbolKind.PARAMETER
                ):
                    var_to_defs.setdefault(symbol.id, []).append(pdg.entry)
                    for value in catalog.values:
                        if value.id.symbol == symbol.id and value.definition is None:
                            var_to_defs.setdefault(value.id, []).append(pdg.entry)

        node_uses: Dict[PDGNode, tuple[object, ...]] = {}
        for node in pdg.nodes:
            if node.ast_node is None:
                continue
            try:
                semantics = catalog.semantics.operation(
                    catalog.node_id(node.ast_node, root_code)
                )
            except KeyError:
                continue
            node_uses[node] = semantics.uses
            for symbol_id in semantics.definitions:
                var_to_defs.setdefault(symbol_id, []).append(node)

        for use_node, uses in node_uses.items():
            for symbol_id in uses:
                def_nodes = var_to_defs.get(symbol_id, [])
                for def_node in def_nodes:
                    if def_node is use_node:
                        continue
                    identity = (
                        catalog.values[symbol_id].id.symbol
                        if isinstance(symbol_id, ValueId)
                        else symbol_id
                    )
                    symbol = catalog.symbols.get(identity)
                    label = (
                        symbol.display_name if symbol is not None else str(symbol_id)
                    )
                    def_node.add_edge_to(use_node, "data", label)

    def _add_data_edges(
        self, pdg: ProgramDependenceGraph, parent_map: Dict[Any, Any]
    ) -> None:
        try:
            self._add_data_edges_from_ddg(pdg, parent_map)
        except Exception as exc:
            # Shared IRSemantics is the authoritative representation for
            # constructs the optional legacy dataflow/DDG lowering does not
            # model. A lowering failure must not discard the CFG, control
            # dependence, or semantic def/use edges already available here.
            pdg.data_dependence_mode = "semantics"
            pdg.data_dependence_reason = f"{type(exc).__name__}: {exc}"
        else:
            pdg.data_dependence_mode = "hybrid"
            pdg.data_dependence_reason = ""
        self._add_semantic_data_edges(pdg)


def construct_pdg(cfg: cfg_graph.Code, **kwargs) -> ProgramDependenceGraph:
    """
    Convenience wrapper to construct a PDG from a CFG.

    Args:
        cfg: CFG Code object (single function)
        kwargs: ``PDGConstructionOptions`` overrides.
    """
    options = PDGConstructionOptions(**kwargs)
    return PDGConstructor(options).construct_from_cfg(cfg)
