"""
Program Dependence Graph (PDG) construction.

Construction sources:
- Control dependences are derived from the CDG constructed from a CFG.
- Data dependences are derived from local def-use sets extracted from the CFG's
  Python AST, with optional SSA + phi expansion to improve precision.

This module focuses on intraprocedural PDGs (single function).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from pyflow.analysis.cfg import expandphi, ssa
from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.analysis.cfg import dom as cfg_dom
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


def _collect_local_defs_uses(root: Any, *, root_code: Optional[py_ast.Code]) -> Tuple[Set[py_ast.Local], Set[py_ast.Local]]:
    duv = py_defuse.DefUseVisitor()
    _IntraproceduralDFS(duv, root_code=root_code).process(root)
    return set(duv.lcldef.keys()), set(duv.lcluse.keys())


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

        # Edges
        if self.options.include_control:
            self._add_control_edges_from_cfg(pdg, reachable)

        if self.options.include_data:
            self._add_data_edges(pdg)

        return pdg

    def _reachable_cfg_nodes(self, entry: cfg_graph.CFGBlock) -> List[cfg_graph.CFGBlock]:
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

    def _add_pdg_nodes(self, pdg: ProgramDependenceGraph, cfg_nodes: Sequence[cfg_graph.CFGBlock]) -> None:
        root_code = getattr(pdg.cfg, "code", None)

        for cnode in cfg_nodes:
            # Always create a block/anchor node so control dependence wiring is stable
            if isinstance(cnode, cfg_graph.Entry):
                anchor = pdg.add_node("entry", cfg_node=cnode, label=_safe_cfg_label(cnode))
                pdg.entry = anchor
            elif isinstance(cnode, cfg_graph.Exit):
                anchor = pdg.add_node("exit", cfg_node=cnode, label=_safe_cfg_label(cnode))
                pdg.exit_nodes.append(anchor)
            else:
                anchor = pdg.add_node("block", cfg_node=cnode, label=_safe_cfg_label(cnode))

            pdg.set_cfg_anchor(cnode, anchor)
            pdg.add_cfg_content(cnode, anchor)

            # Block contents at statement/condition granularity
            if isinstance(cnode, cfg_graph.Suite):
                for op in list(getattr(cnode, "ops", ())):
                    n = pdg.add_node("stmt", cfg_node=cnode, ast_node=op, label=_safe_ast_label(op))
                    pdg.add_cfg_content(cnode, n)
            elif isinstance(cnode, cfg_graph.Switch):
                cond = cnode.condition
                n = pdg.add_node("cond", cfg_node=cnode, ast_node=cond, label=_safe_ast_label(cond))
                pdg.add_cfg_content(cnode, n)
                pdg.set_cfg_anchor(cnode, n)
            elif isinstance(cnode, cfg_graph.TypeSwitch):
                cond = cnode.original.conditional
                n = pdg.add_node("cond", cfg_node=cnode, ast_node=cond, label=_safe_ast_label(cond))
                pdg.add_cfg_content(cnode, n)
                pdg.set_cfg_anchor(cnode, n)
            elif isinstance(cnode, cfg_graph.Merge):
                for phi in list(getattr(cnode, "phi", ())):
                    n = pdg.add_node("stmt", cfg_node=cnode, ast_node=phi, label=_safe_ast_label(phi))
                    pdg.add_cfg_content(cnode, n)

    def _add_control_edges_from_cfg(
        self, pdg: ProgramDependenceGraph, reachable: Sequence[cfg_graph.CFGBlock]
    ) -> None:
        """
        Add control dependence edges using post-dominator information.

        This uses the standard Ferrante/Ottenstein/Warren algorithm:
        - compute post-dominators via dominance in the reverse CFG
        - for each node A with multiple successors, for each successor S:
          walk runner=S up the postdom tree until ipdom(A), adding control deps
        """

        # Compute immediate postdominators by running dominance on the reverse CFG.
        postdom: Dict[cfg_graph.CFGBlock, Any] = {}

        def forward_callback(node: cfg_graph.CFGBlock):
            # Reverse CFG edges: predecessors are successors in the reversed graph.
            return [p for p in node.reverse() if p is not None]

        def bind_callback(node: cfg_graph.CFGBlock, dj_node: Any):
            postdom[node] = dj_node

        roots = [pdg.cfg.normalTerminal, pdg.cfg.failTerminal, pdg.cfg.errorTerminal]
        cfg_dom.evaluate([r for r in roots if r is not None], forward_callback, bind_callback)

        def ipdom(node: cfg_graph.CFGBlock) -> Optional[cfg_graph.CFGBlock]:
            dj = postdom.get(node)
            if dj is None or dj.idom is None:
                return None
            return dj.idom.node

        reachable_set = set(reachable)

        for controller in reachable:
            succs = [s for s in controller.normalForward() if s is not None]
            if len(succs) <= 1:
                continue

            controller_anchor = pdg.get_cfg_anchor(controller)
            if controller_anchor is None:
                continue

            stop = ipdom(controller)
            for succ in succs:
                label = controller.findExit(succ) or ""
                runner = succ
                seen: Set[cfg_graph.CFGBlock] = set()
                while runner is not None and runner != stop and runner not in seen:
                    seen.add(runner)
                    if runner in reachable_set:
                        for dep in set(pdg.get_cfg_contents(runner)):
                            if dep is controller_anchor:
                                continue
                            controller_anchor.add_edge_to(dep, "control", label)
                    runner = ipdom(runner)

    def _add_data_edges(self, pdg: ProgramDependenceGraph) -> None:
        root_code = getattr(pdg.cfg, "code", None)

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
                    label = lcl.name or "local"
                    def_node.add_edge_to(use_node, "data", label)


def construct_pdg(cfg: cfg_graph.Code, **kwargs) -> ProgramDependenceGraph:
    """
    Convenience wrapper to construct a PDG from a CFG.

    Args:
        cfg: CFG Code object (single function)
        kwargs: PDGConstructionOptions overrides (include_control/include_data/run_ssa/expand_phi)
    """
    options = PDGConstructionOptions(**kwargs)
    return PDGConstructor(options).construct_from_cfg(cfg)
