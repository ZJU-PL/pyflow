"""
Program Dependence Graph (PDG) construction.

Construction sources:
- Control dependences are derived from the CDG constructed from a CFG.
- Data dependences are derived from the DDG constructed from dataflow IR and
  projected back onto PDG statement/condition nodes. AST-local def/use is used
  only as a fallback for PDG nodes that the current DDG does not represent
  directly (for example, returns and local-copy assignments).

This module focuses on intraprocedural PDGs (single function).
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from pyflow.analysis.cfg import expandphi, ssa
from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.analysis.cdg import construct_cdg
from pyflow.analysis.ddg import construct_ddg
from pyflow.analysis.dataflowIR import convert
from pyflow.analysis.dataflowIR import graph as df_graph
from pyflow.language.python import ast as py_ast
from pyflow.language.python import defuse as py_defuse

from .graph import ProgramDependenceGraph, PDGNode


class _IntraproceduralDFS:
    """
    A DFS that does not traverse into nested `ast.Code` objects.

    The built-in `pyflow.language.python.defuse.DFS` intentionally forces
    traversal into nested code objects (e.g., MakeFunction), which is useful
    for whole-program def-use but undesirable for intraprocedural PDGs.
    """

    __slots__ = ("pre", "_root_code", "_visited_code")

    def __init__(self, pre, *, root_code: Optional[py_ast.Code] = None):
        self.pre = pre
        self._root_code = root_code
        self._visited_code: Set[py_ast.Code] = set()

    def visit(self, node: Any) -> None:
        if isinstance(node, py_ast.Code):
            if self._root_code is not None and node is not self._root_code:
                return
            if node in self._visited_code:
                return
            self._visited_code.add(node)

        self.pre(node)

        if isinstance(node, py_ast.leafTypes):
            return

        node.visitChildren(self.visit)

    def process(self, node: Any) -> None:
        self.visit(node)


@dataclass(frozen=True)
class PDGConstructionOptions:
    include_control: bool = True
    include_data: bool = True
    run_ssa: bool = False
    expand_phi: bool = True
    allow_ast_fallback_on_ddg_failure: bool = True


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


def _collect_local_defs_uses(
    root: Any, *, root_code: Optional[py_ast.Code]
) -> Tuple[Set[py_ast.Local], Set[py_ast.Local]]:
    duv = py_defuse.DefUseVisitor()
    _IntraproceduralDFS(duv, root_code=root_code).process(root)
    return set(duv.lcldef.keys()), set(duv.lcluse.keys())


def _iter_ast_children(node: Any) -> List[Any]:
    children: List[Any] = []
    for child in node.children():
        if isinstance(child, (list, tuple)):
            children.extend(item for item in child if item is not None)
        elif child is not None:
            children.append(child)
    return children


def _build_ast_parent_map(root: Any) -> Dict[int, Any]:
    parents: Dict[int, Any] = {}
    visited_code: Set[py_ast.Code] = set()

    def walk(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, py_ast.Code):
            if node in visited_code:
                return
            visited_code.add(node)

        if isinstance(node, py_ast.leafTypes):
            return

        for child in _iter_ast_children(node):
            parents[id(child)] = node
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
        parent_map: Dict[int, Any],
    ) -> Optional[PDGNode]:
        node = ast_node
        while node is not None:
            pdg_node = pdg.get_node_for_ast(node)
            if pdg_node is not None:
                return pdg_node
            node = parent_map.get(id(node))
        return None

    def _resolve_pdg_node_for_ddg_op(
        self,
        pdg: ProgramDependenceGraph,
        ddg_node: Any,
        parent_map: Dict[int, Any],
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
        parent_map: Dict[int, Any],
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

    def _add_ast_fallback_data_edges(
        self, pdg: ProgramDependenceGraph, backed_nodes: Set[PDGNode]
    ) -> None:
        root_code = getattr(pdg.cfg, "code", None)
        if root_code is None:
            return

        def key_for_local(lcl: py_ast.Local) -> str:
            # PyFlow's frontend does not guarantee `ast.Local` object identity is shared
            # across occurrences of the same variable. Use a stable key based on name.
            return lcl.name if lcl.name is not None else f"<anon:{id(lcl)}>"

        # Seed parameter definitions at entry (keyed by name).
        var_to_defs: Dict[str, List[PDGNode]] = {}
        if pdg.entry is not None and root_code is not None:
            params = getattr(root_code, "codeparameters", None)
            if params is not None:
                for p in [params.selfparam, params.vparam, params.kparam]:
                    if isinstance(p, py_ast.Local):
                        var_to_defs.setdefault(key_for_local(p), []).append(pdg.entry)
                for p in getattr(params, "params", ()):
                    if isinstance(p, py_ast.Local):
                        var_to_defs.setdefault(key_for_local(p), []).append(pdg.entry)

        # Collect per-node def/use summaries.
        node_uses: Dict[PDGNode, Set[py_ast.Local]] = {}
        for node in pdg.nodes:
            if node.ast_node is None:
                continue
            defs, uses = _collect_local_defs_uses(node.ast_node, root_code=root_code)
            node_uses[node] = uses
            for d in defs:
                var_to_defs.setdefault(key_for_local(d), []).append(node)

        # Add edges from defs to uses.
        for use_node, uses in node_uses.items():
            for lcl in uses:
                def_nodes = var_to_defs.get(key_for_local(lcl), [])
                for def_node in def_nodes:
                    if def_node is use_node:
                        continue
                    if def_node in backed_nodes and use_node in backed_nodes:
                        continue
                    label = lcl.name or "local"
                    def_node.add_edge_to(use_node, "data", label)

    def _add_data_edges(
        self, pdg: ProgramDependenceGraph, parent_map: Dict[int, Any]
    ) -> None:
        try:
            backed_nodes = self._add_data_edges_from_ddg(pdg, parent_map)
        except Exception as exc:
            pdg.data_dependence_reason = f"{type(exc).__name__}: {exc}"
            if not self.options.allow_ast_fallback_on_ddg_failure:
                raise
            pdg.data_dependence_mode = "ast-fallback"
            warnings.warn(
                "PDG DDG-backed data dependence is unavailable; "
                f"falling back to AST-local def/use ({pdg.data_dependence_reason})",
                RuntimeWarning,
                stacklevel=2,
            )
            backed_nodes = set()
        else:
            pdg.data_dependence_mode = "hybrid"
            pdg.data_dependence_reason = ""
        self._add_ast_fallback_data_edges(pdg, backed_nodes)


def construct_pdg(cfg: cfg_graph.Code, **kwargs) -> ProgramDependenceGraph:
    """
    Convenience wrapper to construct a PDG from a CFG.

    Args:
        cfg: CFG Code object (single function)
        kwargs: PDGConstructionOptions overrides (include_control/include_data/run_ssa/expand_phi)
    """
    options = PDGConstructionOptions(**kwargs)
    return PDGConstructor(options).construct_from_cfg(cfg)
