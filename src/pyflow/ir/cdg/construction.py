"""
Control Dependence Graph construction algorithms.

This module constructs CDGs from CFGs using reverse-CFG post-dominance.
For each branching node A and successor S, the constructor walks upward in
the post-dominator tree from S to ipdom(A), adding control dependence edges
``A -> runner`` labeled with the originating branch condition.
"""

from typing import Any, Dict, List, Optional, Set

from pyflow.ir.cfg import dom
from pyflow.ir.cfg import graph as cfg_graph

from .graph import ControlDependenceGraph


class CDGConstructor:
    """
    Construct Control Dependence Graphs from CFGs.

    The public ``dominance_frontiers`` attribute is retained for compatibility,
    but now stores the actual controller -> control-dependent CFG nodes mapping.
    """

    _EXIT_SINK = object()

    def __init__(self, cfg: cfg_graph.Code, *, include_exceptional: bool = False):
        self.cfg = cfg
        self.include_exceptional = include_exceptional
        self.cdg = ControlDependenceGraph(cfg)
        self.dominance_frontiers: Dict[cfg_graph.CFGBlock, Set[cfg_graph.CFGBlock]] = {}
        self.post_dominators: Dict[cfg_graph.CFGBlock, Set[cfg_graph.CFGBlock]] = {}
        self._postdom_nodes: Dict[cfg_graph.CFGBlock, Any] = {}
        self._exception_postdom_nodes: Dict[cfg_graph.CFGBlock, Any] = {}
        self._cfg_nodes: Optional[List[cfg_graph.CFGBlock]] = None

    def construct(self) -> ControlDependenceGraph:
        self._cfg_nodes = self._get_all_cfg_nodes()
        self._compute_post_dominators()
        self._build_control_dependences()
        return self.cdg

    def _build_dominance_info(self):
        """
        Retained for backward compatibility.

        CDG construction no longer relies on forward dominance.
        """
        return None

    def _compute_dominance_frontiers(self):
        """
        Retained for backward compatibility.

        The compatibility mapping is populated during control-dependence
        construction, but callers that invoke this directly still get an
        initialized mapping.
        """
        if self._cfg_nodes is None:
            self._cfg_nodes = self._get_all_cfg_nodes()
        self.dominance_frontiers = {node: set() for node in self._cfg_nodes}

    def _compute_post_dominators(self):
        """
        Compute post-dominators by running dominance on the reverse CFG.

        The primary tree uses only normal flow so ordinary `if`/`loop` cases
        keep their expected joins. A fallback tree rooted at a synthetic sink
        above all exits fills in nodes that cannot reach `normalTerminal`.
        """
        all_nodes = self._cfg_nodes or self._get_all_cfg_nodes()
        self.post_dominators = {node: set() for node in all_nodes}
        self._postdom_nodes = self._compute_reverse_postdom(include_exceptional=False)
        self._exception_postdom_nodes = self._compute_reverse_postdom(
            include_exceptional=True
        )

        for node in all_nodes:
            node_dj = self._get_postdom_dj_node(node)
            if node_dj is None:
                continue

            current = node_dj.idom
            while current is not None:
                if current.node is not self._EXIT_SINK:
                    self.post_dominators[node].add(current.node)
                current = current.idom

    def _compute_reverse_postdom(
        self, *, include_exceptional: bool
    ) -> Dict[cfg_graph.CFGBlock, Any]:
        mapping: Dict[cfg_graph.CFGBlock, Any] = {}

        def reverse_forward(node):
            if include_exceptional and node is self._EXIT_SINK:
                return [
                    terminal
                    for terminal in (
                        self.cfg.normalTerminal,
                        self.cfg.failTerminal,
                        self.cfg.errorTerminal,
                    )
                    if terminal is not None
                ]
            if node is self._EXIT_SINK:
                return []
            return [
                pred
                for pred, name in node.iterprev()
                if pred is not None
                and name != "yield"
                and (include_exceptional or name not in ("error", "fail"))
            ]

        def bind_callback(node, dj_node: Any):
            if node is not self._EXIT_SINK:
                mapping[node] = dj_node

        if include_exceptional:
            dom.evaluate([self._EXIT_SINK], reverse_forward, bind_callback)
        elif self.cfg.normalTerminal is not None:
            dom.evaluate([self.cfg.normalTerminal], reverse_forward, bind_callback)

        return mapping

    def _get_postdom_dj_node(self, node: cfg_graph.CFGBlock) -> Optional[Any]:
        if self.include_exceptional:
            return self._exception_postdom_nodes.get(
                node
            ) or self._postdom_nodes.get(node)
        return self._postdom_nodes.get(node) or self._exception_postdom_nodes.get(node)

    def _post_dominates(
        self, pdom: cfg_graph.CFGBlock, node: cfg_graph.CFGBlock
    ) -> bool:
        return pdom in self.post_dominators.get(node, set())

    def _post_dominates_recursive(
        self,
        pdom: cfg_graph.CFGBlock,
        node: cfg_graph.CFGBlock,
        visited: Set[cfg_graph.CFGBlock],
    ) -> bool:
        # Preserve the helper name for compatibility with existing callers.
        del visited
        return self._post_dominates(pdom, node)

    def _build_control_dependences(self):
        """
        Build control dependence edges using post-dominators.
        """
        all_cfg_nodes = self._cfg_nodes or self._get_all_cfg_nodes()
        self.dominance_frontiers = {node: set() for node in all_cfg_nodes}

        for cfg_node in all_cfg_nodes:
            self.cdg.add_node(cfg_node)

        for controller in all_cfg_nodes:
            successors = []
            for label, successor in controller.next.items():
                if successor is None or label == "yield":
                    continue
                if not self.include_exceptional and label in ("error", "fail"):
                    continue
                successors.append((label, successor))

            if len(successors) <= 1:
                continue

            stop = self._get_immediate_post_dominator(controller)
            for label, successor in successors:
                runner = successor
                seen: Set[cfg_graph.CFGBlock] = set()
                while runner is not None and runner != stop and runner not in seen:
                    seen.add(runner)
                    self.dominance_frontiers[controller].add(runner)
                    self.cdg.add_control_dependence(controller, runner, label)
                    runner = self._get_immediate_post_dominator(runner)

    def _get_control_edge_label(
        self, controller: cfg_graph.CFGBlock, dependent: cfg_graph.CFGBlock
    ) -> str:
        del controller
        del dependent
        return "control"

    def _get_all_cfg_nodes(self) -> List[cfg_graph.CFGBlock]:
        if self._cfg_nodes is not None:
            return list(self._cfg_nodes)

        visited: Set[cfg_graph.CFGBlock] = set()
        order: List[cfg_graph.CFGBlock] = []
        stack: List[cfg_graph.CFGBlock] = [self.cfg.entryTerminal]

        while stack:
            node = stack.pop()
            if node in visited:
                continue

            visited.add(node)
            order.append(node)
            for next_node in node.forward():
                if next_node is not None and next_node not in visited:
                    stack.append(next_node)

        return order

    def _get_predecessors(self, node: cfg_graph.CFGBlock) -> List[cfg_graph.CFGBlock]:
        return [pred for pred in node.reverse() if pred is not None]

    def _get_immediate_post_dominator(
        self, node: cfg_graph.CFGBlock
    ) -> Optional[Any]:
        dj_node = self._get_postdom_dj_node(node)
        if dj_node is None or dj_node.idom is None:
            return None
        return dj_node.idom.node

    def get_dominance_frontier(
        self, node: cfg_graph.CFGBlock
    ) -> Set[cfg_graph.CFGBlock]:
        """
        Get the control-dependent nodes for a controller.
        """
        return self.dominance_frontiers.get(node, set())

    def get_post_dominators(self, node: cfg_graph.CFGBlock) -> Set[cfg_graph.CFGBlock]:
        return self.post_dominators.get(node, set())

    def is_control_dependent(
        self, dependent: cfg_graph.CFGBlock, controller: cfg_graph.CFGBlock
    ) -> bool:
        return dependent in self.dominance_frontiers.get(controller, set())


def construct_cdg(
    cfg: cfg_graph.Code, *, include_exceptional: bool = False
) -> ControlDependenceGraph:
    """Construct a CDG, optionally treating exceptional exits as branches."""
    constructor = CDGConstructor(cfg, include_exceptional=include_exceptional)
    return constructor.construct()


def analyze_control_dependencies(
    cfg: cfg_graph.Code, *, include_exceptional: bool = False
) -> Dict[str, Any]:
    """
    Analyze control dependencies in a CFG and return statistics.

    ``dominance_frontiers`` is retained as a compatibility key, but it now
    reports controller -> control-dependent nodes. Set ``include_exceptional``
    to include ``fail`` and ``error`` successors in post-dominance and control
    dependence; the default preserves the historical normal-flow-only result.
    """
    constructor = CDGConstructor(cfg, include_exceptional=include_exceptional)
    cdg = constructor.construct()

    def node_key(node: cfg_graph.CFGBlock) -> str:
        cdg_node = cdg.get_node(node)
        if cdg_node is not None:
            return f"{cdg_node.node_id}:{type(node).__name__}"
        return f"{id(node)}:{type(node).__name__}"

    stats = cdg.get_statistics()
    stats["dominance_frontiers"] = {
        node_key(node): sorted(node_key(frontier_node) for frontier_node in frontier)
        for node, frontier in constructor.dominance_frontiers.items()
    }
    stats["post_dominators"] = {
        node_key(node): sorted(node_key(pdom) for pdom in pdoms)
        for node, pdoms in constructor.post_dominators.items()
    }
    return stats
