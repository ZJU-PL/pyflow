"""CFG-to-supergraph adapter for IFDS/IDE analyses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Sequence

from pyflow.analysis.cfg import dfs as cfg_dfs
from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from .supergraph import Supergraph


CallResolver = Callable[
    ["CFGSupergraphAdapter", "CFGNode", py_ast.PythonASTNode | None],
    Iterable[cfg_graph.Code],
]


@dataclass(frozen=True)
class CFGNode:
    """Statement-level node view over a CFG block."""

    procedure: cfg_graph.Code
    block: cfg_graph.CFGBlock
    kind: str
    index: int | None = None


def extract_call_expression(operation: py_ast.PythonASTNode | None):
    """Return the call expression contained in a statement, if any."""
    if isinstance(operation, py_ast.Assign):
        expr = operation.expr
    elif isinstance(operation, py_ast.Discard):
        expr = operation.expr
    else:
        return None
    if isinstance(expr, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
        return expr
    return None


def assigned_locals(operation: py_ast.PythonASTNode | None) -> tuple[py_ast.Local, ...]:
    """Return locals overwritten by an operation."""
    if isinstance(operation, py_ast.Assign):
        return tuple(lcl for lcl in operation.lcls if isinstance(lcl, py_ast.Local))
    return ()


def direct_call_cfg_resolver(
    adapter: "CFGSupergraphAdapter",
    node: CFGNode,
    operation: py_ast.PythonASTNode | None,
) -> tuple[cfg_graph.Code, ...]:
    """Resolve callees through ``ast.DirectCall.code``."""
    call = extract_call_expression(operation)
    if not isinstance(call, py_ast.DirectCall) or call.code is None:
        return ()
    callee = adapter.cfg_by_ast_code.get(call.code)
    if callee is None:
        return ()
    return (callee,)


def annotation_invokes_cfg_resolver(
    adapter: "CFGSupergraphAdapter",
    node: CFGNode,
    operation: py_ast.PythonASTNode | None,
) -> tuple[cfg_graph.Code, ...]:
    """Resolve callees from operation annotations populated by other analyses."""
    annotation = getattr(operation, "annotation", None)
    invokes = getattr(annotation, "invokes", None)
    if not invokes:
        return ()
    entries = invokes[0] if isinstance(invokes, tuple) and invokes else invokes
    if not entries:
        return ()
    resolved: list[cfg_graph.Code] = []
    seen: set[cfg_graph.Code] = set()
    for entry in entries:
        if not isinstance(entry, tuple) or not entry:
            continue
        code = entry[0]
        callee = adapter.cfg_by_ast_code.get(code)
        if callee is not None and callee not in seen:
            seen.add(callee)
            resolved.append(callee)
    return tuple(resolved)


def named_call_cfg_resolver(
    adapter: "CFGSupergraphAdapter",
    node: CFGNode,
    operation: py_ast.PythonASTNode | None,
) -> tuple[cfg_graph.Code, ...]:
    """Resolve simple source-level ``ast.Call`` sites by symbolic name."""
    call = extract_call_expression(operation)
    if isinstance(call, py_ast.Call):
        target = call.expr
        if isinstance(target, py_ast.Local) and target.name:
            return adapter.cfgs_by_name.get(target.name, ())
    if isinstance(call, py_ast.MethodCall):
        name = call.name
        if isinstance(name, py_ast.Local) and name.name:
            return adapter.cfgs_by_name.get(name.name, ())
        if isinstance(name, py_ast.Existing):
            pyobj = getattr(name.object, "pyobj", None)
            if isinstance(pyobj, str):
                return adapter.cfgs_by_name.get(pyobj, ())
    return ()


def composite_cfg_resolver(*resolvers: CallResolver) -> CallResolver:
    """Chain together multiple call resolvers and union their results."""

    def resolve(
        adapter: "CFGSupergraphAdapter",
        node: CFGNode,
        operation: py_ast.PythonASTNode | None,
    ) -> tuple[cfg_graph.Code, ...]:
        merged: list[cfg_graph.Code] = []
        seen: set[cfg_graph.Code] = set()
        for resolver in resolvers:
            for callee in resolver(adapter, node, operation):
                if callee not in seen:
                    seen.add(callee)
                    merged.append(callee)
        return tuple(merged)

    return resolve


class CFGSupergraphAdapter:
    """
    Build a reusable IFDS supergraph from existing ``analysis.cfg`` graphs.

    Suites are lowered to statement-level nodes so dataflow problems can reason
    about operations in program order and model call sites precisely.
    """

    def __init__(
        self,
        cfgs: Sequence[cfg_graph.Code],
        *,
        call_resolver: CallResolver | None = None,
        include_exceptional_edges: bool = False,
    ) -> None:
        self.cfgs = tuple(cfgs)
        self.call_resolver = call_resolver or composite_cfg_resolver(
            direct_call_cfg_resolver,
            annotation_invokes_cfg_resolver,
            named_call_cfg_resolver,
        )
        self.include_exceptional_edges = include_exceptional_edges
        self.cfg_by_ast_code = {
            cfg.code: cfg for cfg in self.cfgs if getattr(cfg, "code", None) is not None
        }
        self.cfgs_by_name: Dict[str, tuple[cfg_graph.Code, ...]] = {}
        by_name: Dict[str, list[cfg_graph.Code]] = {}
        for cfg in self.cfgs:
            code = getattr(cfg, "code", None)
            if code is None:
                continue
            by_name.setdefault(code.codeName(), []).append(cfg)
        self.cfgs_by_name = {name: tuple(values) for name, values in by_name.items()}

        self.supergraph = Supergraph[cfg_graph.Code, CFGNode]()
        self._nodes_by_block: Dict[cfg_graph.CFGBlock, list[CFGNode]] = {}
        self._operation_by_node: Dict[CFGNode, py_ast.PythonASTNode | None] = {}
        self._call_expr_by_node: Dict[CFGNode, py_ast.PythonASTNode] = {}
        self._callee_cfgs_by_node: Dict[CFGNode, tuple[cfg_graph.Code, ...]] = {}

        for cfg in self.cfgs:
            self._register_procedure(cfg)
        for cfg in self.cfgs:
            self._connect_procedure(cfg)

    def operation_of(self, node: CFGNode):
        return self._operation_by_node.get(node)

    def call_expression_of(self, node: CFGNode):
        return self._call_expr_by_node.get(node)

    def callees_of(self, node: CFGNode) -> tuple[cfg_graph.Code, ...]:
        return self._callee_cfgs_by_node.get(node, ())

    def nodes_for_block(self, block: cfg_graph.CFGBlock) -> tuple[CFGNode, ...]:
        return tuple(self._nodes_by_block[block])

    def first_node_of_block(self, block: cfg_graph.CFGBlock) -> CFGNode:
        return self._nodes_by_block[block][0]

    def last_node_of_block(self, block: cfg_graph.CFGBlock) -> CFGNode:
        return self._nodes_by_block[block][-1]

    def _reachable_blocks(self, cfg: cfg_graph.Code) -> tuple[cfg_graph.CFGBlock, ...]:
        order: list[cfg_graph.CFGBlock] = []
        cfg_dfs.CFGDFS(pre=order.append).process(cfg.entryTerminal)
        return tuple(order)

    def _register_procedure(self, cfg: cfg_graph.Code) -> None:
        blocks = self._reachable_blocks(cfg)
        for block in blocks:
            self._make_block_nodes(cfg, block)
        exits = tuple(
            self._nodes_by_block[block][0]
            for block in blocks
            if isinstance(block, cfg_graph.Exit)
        )
        entry = self.first_node_of_block(cfg.entryTerminal)
        self.supergraph.add_procedure(cfg, entry, exits)

        for block in blocks:
            for node in self._nodes_by_block[block]:
                if node != entry and node not in exits:
                    self.supergraph.add_node(cfg, node)

    def _make_block_nodes(
        self, cfg: cfg_graph.Code, block: cfg_graph.CFGBlock
    ) -> list[CFGNode]:
        existing = self._nodes_by_block.get(block)
        if existing is not None:
            return existing

        nodes: list[CFGNode]
        if isinstance(block, cfg_graph.Entry):
            nodes = [CFGNode(cfg, block, "entry")]
        elif isinstance(block, cfg_graph.Exit):
            nodes = [CFGNode(cfg, block, "exit")]
        elif isinstance(block, cfg_graph.Suite):
            if block.ops:
                nodes = [CFGNode(cfg, block, "op", index) for index, _ in enumerate(block.ops)]
                for node in nodes:
                    self._operation_by_node[node] = block.ops[node.index]
            else:
                nodes = [CFGNode(cfg, block, "suite")]
        elif isinstance(block, cfg_graph.Switch):
            node = CFGNode(cfg, block, "condition")
            nodes = [node]
            self._operation_by_node[node] = block.condition
        elif isinstance(block, cfg_graph.TypeSwitch):
            node = CFGNode(cfg, block, "typeswitch")
            nodes = [node]
            self._operation_by_node[node] = block.original
        elif isinstance(block, cfg_graph.Merge):
            if block.phi:
                nodes = [CFGNode(cfg, block, "phi", index) for index, _ in enumerate(block.phi)]
                for node in nodes:
                    self._operation_by_node[node] = block.phi[node.index]
            else:
                nodes = [CFGNode(cfg, block, "merge")]
        elif isinstance(block, cfg_graph.Yield):
            nodes = [CFGNode(cfg, block, "yield")]
        elif isinstance(block, cfg_graph.State):
            nodes = [CFGNode(cfg, block, "state")]
        else:
            nodes = [CFGNode(cfg, block, "block")]

        self._nodes_by_block[block] = nodes
        return nodes

    def _connect_procedure(self, cfg: cfg_graph.Code) -> None:
        blocks = self._reachable_blocks(cfg)
        for block in blocks:
            nodes = self._nodes_by_block[block]
            for index in range(len(nodes) - 1):
                self._connect_local_successor(nodes[index], nodes[index + 1])

            tail = nodes[-1]
            successors = (
                tuple(block.forward())
                if self.include_exceptional_edges
                else tuple(block.normalForward())
            )
            for successor in successors:
                self._connect_local_successor(tail, self.first_node_of_block(successor))

    def _connect_local_successor(self, source: CFGNode, target: CFGNode) -> None:
        operation = self.operation_of(source)
        callees = tuple(self.call_resolver(self, source, operation))
        if callees:
            self.supergraph.add_return_site(source, target)
            self._callee_cfgs_by_node[source] = callees
            call_expr = extract_call_expression(operation)
            if call_expr is not None:
                self._call_expr_by_node[source] = call_expr
            for callee in callees:
                self.supergraph.add_call_edge(source, callee)
        else:
            self.supergraph.add_normal_edge(source, target)


def build_supergraph_from_cfgs(
    cfgs: Sequence[cfg_graph.Code],
    *,
    call_resolver: CallResolver | None = None,
    include_exceptional_edges: bool = False,
) -> CFGSupergraphAdapter:
    """Convenience wrapper for building a CFG-backed supergraph."""
    return CFGSupergraphAdapter(
        cfgs,
        call_resolver=call_resolver,
        include_exceptional_edges=include_exceptional_edges,
    )
