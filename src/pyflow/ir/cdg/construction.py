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
    """Construct a total control-dependence graph from a CFG."""

    _EXIT_SINK = object()

    def __init__(self, cfg: cfg_graph.Code, *, include_exceptional: bool = False):
        self.cfg = cfg
        self.include_exceptional = include_exceptional
        self.cdg = ControlDependenceGraph(cfg)
        self.control_dependences: Dict[cfg_graph.CFGBlock, Set[cfg_graph.CFGBlock]] = {}
        self.post_dominators: Dict[cfg_graph.CFGBlock, Set[cfg_graph.CFGBlock]] = {}
        self._postdom_nodes: Dict[cfg_graph.CFGBlock, Any] = {}
        self._cfg_nodes: Optional[List[cfg_graph.CFGBlock]] = None

    def _successors(self, node):
        successors = [
            (label, child)
            for label, child in node.next.items()
            if child is not None and label != "yield"
        ]
        if self.include_exceptional:
            return successors
        normal = [(label, child) for label, child in successors if label not in ("fail", "error")]
        # Explicit raises and other unconditional exceptional transfers remain
        # real exits. Only implicit exceptions beside normal flow are omitted.
        return normal or successors

    def _predecessors(self, node, node_set):
        return [
            pred
            for pred, label in node.iterprev()
            if pred in node_set and (label, node) in self._successors(pred)
        ]

    def construct(self) -> ControlDependenceGraph:
        # A constructor may be reused after the CFG has changed.
        self.cdg = ControlDependenceGraph(self.cfg)
        self.cdg.include_exceptional = self.include_exceptional
        self.control_dependences = {}
        self.post_dominators = {}
        self._postdom_nodes = {}
        self._cfg_nodes = None
        self._cfg_nodes = self._get_all_cfg_nodes()
        self._compute_post_dominators()
        self._build_control_dependences()
        return self.cdg

    def _compute_post_dominators(self):
        """
        Compute post-dominators by running dominance on the reverse CFG.

        A synthetic sink joins normal, explicit-failure, and error exits. Sink
        SCCs that cannot reach any procedure exit are treated as virtual exits,
        giving non-terminating regions a total post-dominator relation too.
        """
        all_nodes = self._cfg_nodes or self._get_all_cfg_nodes()
        self.post_dominators = {node: set() for node in all_nodes}
        self._postdom_nodes = self._compute_reverse_postdom()

        for node in all_nodes:
            node_dj = self._get_postdom_dj_node(node)
            if node_dj is None:
                continue

            current = node_dj.idom
            while current is not None:
                if current.node is not self._EXIT_SINK:
                    self.post_dominators[node].add(current.node)
                current = current.idom

    def _compute_reverse_postdom(self) -> Dict[cfg_graph.CFGBlock, Any]:
        mapping: Dict[cfg_graph.CFGBlock, Any] = {}
        all_nodes = self._cfg_nodes or self._get_all_cfg_nodes()
        node_set = set(all_nodes)
        real_terminals = [
            terminal
            for terminal in (
                self.cfg.normalTerminal,
                self.cfg.failTerminal,
                self.cfg.errorTerminal,
            )
            if terminal in node_set
        ]
        virtual_terminals = self._nonterminating_sink_representatives(all_nodes, real_terminals)

        def reverse_forward(node):
            if node is self._EXIT_SINK:
                return [*real_terminals, *virtual_terminals]
            return self._predecessors(node, node_set)

        def bind_callback(node, dj_node: Any):
            if node is not self._EXIT_SINK:
                mapping[node] = dj_node

        dom.evaluate([self._EXIT_SINK], reverse_forward, bind_callback)

        return mapping

    def _nonterminating_sink_representatives(self, all_nodes, real_terminals):
        """Return one deterministic virtual exit for each non-exiting sink SCC."""
        can_exit = set(real_terminals)
        pending = list(real_terminals)
        node_set = set(all_nodes)
        while pending:
            node = pending.pop()
            for predecessor in self._predecessors(node, node_set):
                if predecessor not in can_exit:
                    can_exit.add(predecessor)
                    pending.append(predecessor)

        nonterminating = set(all_nodes) - can_exit
        if not nonterminating:
            return []

        successors = {
            node: [child for label, child in self._successors(node) if child in nonterminating]
            for node in nonterminating
        }
        predecessors = {node: [] for node in nonterminating}
        for source, targets in successors.items():
            for target in targets:
                predecessors[target].append(source)

        def finish_order(graph):
            seen = set()
            order = []
            for root in all_nodes:
                if root not in graph or root in seen:
                    continue
                seen.add(root)
                stack = [(root, iter(graph[root]))]
                while stack:
                    current, children = stack[-1]
                    try:
                        child = next(children)
                        if child not in seen:
                            seen.add(child)
                            stack.append((child, iter(graph[child])))
                    except StopIteration:
                        order.append(current)
                        stack.pop()
            return order

        components = []
        assigned = set()
        for root in reversed(finish_order(successors)):
            if root in assigned:
                continue
            component = set()
            stack = [root]
            assigned.add(root)
            while stack:
                current = stack.pop()
                component.add(current)
                for predecessor in predecessors[current]:
                    if predecessor not in assigned:
                        assigned.add(predecessor)
                        stack.append(predecessor)
            components.append(component)

        component_of = {
            node: index for index, component in enumerate(components) for node in component
        }
        order_index = {node: index for index, node in enumerate(all_nodes)}
        result = []
        for index, component in enumerate(components):
            if any(
                component_of[target] != index
                for source in component
                for target in successors[source]
            ):
                continue
            result.append(min(component, key=order_index.__getitem__))
        return result

    def _get_postdom_dj_node(self, node: cfg_graph.CFGBlock) -> Optional[Any]:
        return self._postdom_nodes.get(node)

    def _build_control_dependences(self):
        """
        Build control dependence edges using post-dominators.
        """
        all_cfg_nodes = self._cfg_nodes or self._get_all_cfg_nodes()
        self.control_dependences = {node: set() for node in all_cfg_nodes}

        for cfg_node in all_cfg_nodes:
            self.cdg.add_node(cfg_node)

        for controller in all_cfg_nodes:
            successors = self._successors(controller)

            if len(successors) <= 1:
                continue

            stop = self._get_immediate_post_dominator(controller)
            for label, successor in successors:
                runner = successor
                seen: Set[cfg_graph.CFGBlock] = set()
                while runner is not None and runner != stop and runner not in seen:
                    seen.add(runner)
                    self.control_dependences[controller].add(runner)
                    self.cdg.add_control_dependence(controller, runner, label)
                    runner = self._get_immediate_post_dominator(runner)

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
            for _, next_node in self._successors(node):
                if next_node is not None and next_node not in visited:
                    stack.append(next_node)

        return order

    def _get_immediate_post_dominator(self, node: cfg_graph.CFGBlock) -> Optional[Any]:
        dj_node = self._get_postdom_dj_node(node)
        if dj_node is None or dj_node.idom is None:
            return None
        return dj_node.idom.node

    def get_control_dependences(self, node: cfg_graph.CFGBlock) -> Set[cfg_graph.CFGBlock]:
        """Get the control-dependent nodes for a controller."""
        return self.control_dependences.get(node, set())

    def get_post_dominators(self, node: cfg_graph.CFGBlock) -> Set[cfg_graph.CFGBlock]:
        return self.post_dominators.get(node, set())

    def is_control_dependent(
        self, dependent: cfg_graph.CFGBlock, controller: cfg_graph.CFGBlock
    ) -> bool:
        return dependent in self.control_dependences.get(controller, set())


def construct_cdg(
    cfg: cfg_graph.Code, *, include_exceptional: bool = False
) -> ControlDependenceGraph:
    """Construct structured control dependences, optionally including implicit exceptions."""
    constructor = CDGConstructor(cfg, include_exceptional=include_exceptional)
    return constructor.construct()


def analyze_control_dependencies(
    cfg: cfg_graph.Code, *, include_exceptional: bool = False
) -> Dict[str, Any]:
    """
    Analyze control dependencies in a CFG and return statistics.

    The result follows the selected control projection, with total
    post-dominance for non-terminating sink regions.
    """
    constructor = CDGConstructor(cfg, include_exceptional=include_exceptional)
    cdg = constructor.construct()

    def node_key(node: cfg_graph.CFGBlock) -> str:
        cdg_node = cdg.get_node(node)
        if cdg_node is None:
            raise ValueError(f"CFG node is absent from constructed CDG: {node!r}")
        return f"{cdg_node.block_id}:{type(node).__name__}"

    stats = cdg.get_statistics()
    stats["control_dependences"] = {
        node_key(node): sorted(node_key(frontier_node) for frontier_node in frontier)
        for node, frontier in constructor.control_dependences.items()
    }
    stats["post_dominators"] = {
        node_key(node): sorted(node_key(pdom) for pdom in pdoms)
        for node, pdoms in constructor.post_dominators.items()
    }
    return stats
