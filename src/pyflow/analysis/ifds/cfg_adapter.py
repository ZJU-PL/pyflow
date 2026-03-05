"""CFG-to-supergraph adapter for IFDS/IDE analyses."""

from __future__ import annotations

from dataclasses import dataclass, field
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
    call_index: int | None = None
    scope: tuple[str, ...] = ()


@dataclass
class _OperationFragment:
    nodes: list[CFGNode] = field(default_factory=list)
    entry: CFGNode | None = None
    normal_exits: set[CFGNode] = field(default_factory=set)


def extract_call_expression(operation: py_ast.PythonASTNode | None):
    """Return the outermost call expression reachable from an operation, if any."""
    calls = iter_call_expressions(operation)
    if not calls:
        return None
    return calls[0]


def iter_call_expressions(
    node: py_ast.PythonASTNode | None,
) -> tuple[py_ast.PythonASTNode, ...]:
    """Yield call expressions reachable from a node in preorder."""
    found: list[py_ast.PythonASTNode] = []

    def visit(current) -> None:
        if current is None or isinstance(current, py_ast.leafTypes):
            return
        if isinstance(current, py_ast.Code):
            return
        if isinstance(current, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            found.append(current)
        if isinstance(current, (list, tuple)):
            for child in current:
                visit(child)
            return
        if hasattr(current, "visitChildren"):
            current.visitChildren(visit)

    visit(node)
    return tuple(found)


def iter_call_expressions_in_eval_order(
    node: py_ast.PythonASTNode | None,
) -> tuple[py_ast.PythonASTNode, ...]:
    """Yield call expressions in Python evaluation order, innermost result first."""
    found: list[py_ast.PythonASTNode] = []

    def visit(current) -> None:
        if current is None or isinstance(current, py_ast.leafTypes):
            return
        if isinstance(current, py_ast.Code):
            return
        if isinstance(current, (list, tuple)):
            for child in current:
                visit(child)
            return
        if hasattr(current, "visitChildren"):
            current.visitChildren(visit)
        if isinstance(current, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            found.append(current)

    visit(node)
    return tuple(found)


def assigned_locals(operation: py_ast.PythonASTNode | None) -> tuple[py_ast.Local, ...]:
    """Return locals overwritten by an operation.

    This is used by IFDS clients to implement strong updates (kills) and
    to route multi-result calls to specific assignment targets. Keep it a
    best-effort overapproximation of Python "stores to locals".
    """
    direct: list[py_ast.Local] = []

    if isinstance(operation, py_ast.Assign):
        direct.extend(lcl for lcl in operation.lcls if isinstance(lcl, py_ast.Local))
    elif isinstance(operation, py_ast.UnpackSequence):
        direct.extend(lcl for lcl in operation.targets if isinstance(lcl, py_ast.Local))
    elif isinstance(operation, py_ast.AnnAssign):
        # Only an annotated assignment with a value overwrites the target.
        if operation.value is None:
            direct = []
        elif isinstance(operation.target, py_ast.Local):
            direct.append(operation.target)
    elif isinstance(operation, py_ast.InputBlock):
        for input_ in getattr(operation, "inputs", ()):
            lcl = getattr(input_, "lcl", None)
            if isinstance(lcl, py_ast.Local):
                direct.append(lcl)
    else:
        direct = []

    # Nested assignment expressions (walrus) also overwrite their targets.
    # This is an intentional overapproximation: it ignores short-circuiting
    # conditions and other path sensitivity.
    walrus_targets: list[py_ast.Local] = []

    def visit(current) -> None:
        if current is None or isinstance(current, py_ast.leafTypes):
            return
        if isinstance(current, py_ast.Code):
            return
        if isinstance(current, py_ast.NamedExpr):
            if isinstance(current.target, py_ast.Local):
                walrus_targets.append(current.target)
            visit(current.value)
            return
        if isinstance(current, (list, tuple)):
            for child in current:
                visit(child)
            return
        if hasattr(current, "visitChildren"):
            current.visitChildren(visit)

    visit(operation)

    if not walrus_targets:
        return tuple(direct)
    merged: list[py_ast.Local] = []
    seen: set[py_ast.Local] = set()
    for lcl in (*direct, *walrus_targets):
        if lcl not in seen:
            seen.add(lcl)
            merged.append(lcl)
    return tuple(merged)


def direct_call_cfg_resolver(
    adapter: "CFGSupergraphAdapter",
    node: CFGNode,
    call_expression: py_ast.PythonASTNode | None,
) -> tuple[cfg_graph.Code, ...]:
    """Resolve callees through ``ast.DirectCall.code``."""
    if not isinstance(call_expression, py_ast.DirectCall) or call_expression.code is None:
        return ()
    callee = adapter.cfg_by_ast_code.get(call_expression.code)
    if callee is None:
        return ()
    return (callee,)


def annotation_invokes_cfg_resolver(
    adapter: "CFGSupergraphAdapter",
    node: CFGNode,
    call_expression: py_ast.PythonASTNode | None,
) -> tuple[cfg_graph.Code, ...]:
    """Resolve callees from call-expression annotations populated by other analyses."""
    del node
    annotation = getattr(call_expression, "annotation", None)
    invokes = getattr(annotation, "invokes", None)
    if not invokes:
        return ()

    # Prefer merged contextual data when available; otherwise treat invokes as
    # a flat iterable of entries. Do not special-case plain tuples as
    # (merged, context) without an attribute check: invoke entries can
    # themselves be tuples.
    entries = getattr(invokes, "merged", None)
    if entries is None:
        entries = invokes
    if not entries:
        return ()

    resolved: list[cfg_graph.Code] = []
    seen: set[cfg_graph.Code] = set()

    def iter_codes(obj) -> Iterable[object]:
        """Yield potential callee code objects from nested invoke structures."""
        if obj is None:
            return
        # Common case: invoke entry is a tuple whose first element is a code object.
        if isinstance(obj, tuple) and obj:
            head = obj[0]
            if head in adapter.cfg_by_ast_code:
                yield head
                return
            # Otherwise, treat it as a nested container and recurse.
            for item in obj:
                yield from iter_codes(item)
            return
        if isinstance(obj, list):
            for item in obj:
                yield from iter_codes(item)
            return
        if obj in adapter.cfg_by_ast_code:
            yield obj

    for code in iter_codes(entries):
        callee = adapter.cfg_by_ast_code.get(code)
        if callee is not None and callee not in seen:
            seen.add(callee)
            resolved.append(callee)
    return tuple(resolved)


def named_call_cfg_resolver(
    adapter: "CFGSupergraphAdapter",
    node: CFGNode,
    call_expression: py_ast.PythonASTNode | None,
) -> tuple[cfg_graph.Code, ...]:
    """Resolve simple source-level ``ast.Call`` sites by symbolic name."""
    del node
    if isinstance(call_expression, py_ast.Call):
        target = call_expression.expr
        if isinstance(target, py_ast.Local) and target.name:
            callee = adapter.unique_cfg_by_name.get(target.name)
            if callee is not None:
                return (callee,)
            return ()
    if isinstance(call_expression, py_ast.MethodCall):
        name = call_expression.name
        if isinstance(name, py_ast.Local) and name.name:
            callee = adapter.unique_cfg_by_name.get(name.name)
            if callee is not None:
                return (callee,)
            return ()
        if isinstance(name, py_ast.Existing):
            pyobj = getattr(name.object, "pyobj", None)
            if isinstance(pyobj, str):
                callee = adapter.unique_cfg_by_name.get(pyobj)
                if callee is not None:
                    return (callee,)
    return ()


def composite_cfg_resolver(*resolvers: CallResolver) -> CallResolver:
    """Chain together multiple call resolvers and union their results."""

    def resolve(
        adapter: "CFGSupergraphAdapter",
        node: CFGNode,
        call_expression: py_ast.PythonASTNode | None,
    ) -> tuple[cfg_graph.Code, ...]:
        merged: list[cfg_graph.Code] = []
        seen: set[cfg_graph.Code] = set()
        for resolver in resolvers:
            for callee in resolver(adapter, node, call_expression):
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
        include_exceptional_edges: bool = True,
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
        self.unique_cfg_by_name: Dict[str, cfg_graph.Code] = {}
        by_name: Dict[str, list[cfg_graph.Code]] = {}
        for cfg in self.cfgs:
            code = getattr(cfg, "code", None)
            if code is None:
                continue
            by_name.setdefault(code.codeName(), []).append(cfg)
        self.cfgs_by_name = {name: tuple(values) for name, values in by_name.items()}
        self.unique_cfg_by_name = {
            name: values[0] for name, values in by_name.items() if len(values) == 1
        }

        self.supergraph = Supergraph[cfg_graph.Code, CFGNode]()
        self._nodes_by_block: Dict[cfg_graph.CFGBlock, list[CFGNode]] = {}
        self._operation_by_node: Dict[CFGNode, py_ast.PythonASTNode | None] = {}
        self._call_expr_by_node: Dict[CFGNode, py_ast.PythonASTNode] = {}
        self._callee_cfgs_by_node: Dict[CFGNode, tuple[cfg_graph.Code, ...]] = {}
        self._local_successors: Dict[CFGNode, set[CFGNode]] = {}
        self._suite_exit_nodes: Dict[cfg_graph.CFGBlock, tuple[set[CFGNode], set[CFGNode]]] = {}

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
                fragment = self._lower_suite_fragment(
                    cfg,
                    block,
                    tuple(block.ops),
                    kind="op",
                    parent_scope=(),
                )
                nodes = fragment.nodes
                self._suite_exit_nodes[block] = (
                    set(fragment.normal_exits),
                )
            else:
                nodes = [CFGNode(cfg, block, "suite")]
        elif isinstance(block, cfg_graph.Switch):
            fragment = self._lower_operation_fragment(
                cfg, block, "condition", block.condition, None, ()
            )
            nodes = fragment.nodes
        elif isinstance(block, cfg_graph.TypeSwitch):
            fragment = self._lower_operation_fragment(
                cfg, block, "typeswitch", block.original, None, ()
            )
            nodes = fragment.nodes
        elif isinstance(block, cfg_graph.Merge):
            if block.phi:
                fragment = self._lower_suite_fragment(
                    cfg,
                    block,
                    tuple(block.phi),
                    kind="phi",
                    parent_scope=(),
                )
                nodes = fragment.nodes
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

    def _record_local_edge(self, source: CFGNode, target: CFGNode) -> None:
        self._local_successors.setdefault(source, set()).add(target)

    def _new_node(
        self,
        cfg: cfg_graph.Code,
        block: cfg_graph.CFGBlock,
        kind: str,
        index: int | None,
        *,
        call_index: int | None = None,
        scope: tuple[str, ...] = (),
        operation: py_ast.PythonASTNode | None = None,
        call_expression: py_ast.PythonASTNode | None = None,
    ) -> CFGNode:
        node = CFGNode(cfg, block, kind, index, call_index, scope)
        self._operation_by_node[node] = operation
        if call_expression is not None:
            self._call_expr_by_node[node] = call_expression
        return node

    def _lower_suite_fragment(
        self,
        cfg: cfg_graph.Code,
        block: cfg_graph.CFGBlock,
        operations: tuple[py_ast.PythonASTNode, ...],
        *,
        kind: str,
        parent_scope: tuple[str, ...],
        index: int | None = None,
    ) -> _OperationFragment:
        if not operations:
            marker = self._new_node(
                cfg,
                block,
                f"{kind}_empty",
                index,
                scope=parent_scope + ("empty",),
            )
            return _OperationFragment(
                nodes=[marker],
                entry=marker,
                normal_exits={marker},
            )

        fragments = [
            self._lower_operation_fragment(
                cfg,
                block,
                kind,
                operation,
                index,
                parent_scope + (str(position),),
            )
            for position, operation in enumerate(operations)
        ]

        composed = fragments[0]
        for fragment in fragments[1:]:
            for exit_node in composed.normal_exits:
                self._record_local_edge(exit_node, fragment.entry)
            composed = _OperationFragment(
                nodes=[*composed.nodes, *fragment.nodes],
                entry=composed.entry,
                normal_exits=set(fragment.normal_exits),
            )
        return composed

    def _lower_operation_fragment(
        self,
        cfg: cfg_graph.Code,
        block: cfg_graph.CFGBlock,
        kind: str,
        operation: py_ast.PythonASTNode | None,
        index: int | None,
        scope: tuple[str, ...],
    ) -> _OperationFragment:
        if isinstance(operation, py_ast.TryExceptFinally):
            return self._lower_try_fragment(cfg, block, kind, operation, index, scope)

        nodes: list[CFGNode] = []
        previous: CFGNode | None = None
        call_expressions = iter_call_expressions_in_eval_order(operation)
        for call_index, call_expression in enumerate(call_expressions):
            node = self._new_node(
                cfg,
                block,
                "call",
                index,
                call_index=call_index,
                scope=scope + ("call", str(call_index)),
                operation=operation,
                call_expression=call_expression,
            )
            if previous is not None:
                self._record_local_edge(previous, node)
            previous = node
            nodes.append(node)

        terminal = self._new_node(
            cfg,
            block,
            kind,
            index,
            scope=scope,
            operation=operation,
        )
        if previous is not None:
            self._record_local_edge(previous, terminal)
        nodes.append(terminal)

        normal_exits = set()
        if not isinstance(operation, py_ast.Raise):
            normal_exits.add(terminal)

        return _OperationFragment(
            nodes=nodes,
            entry=nodes[0],
            normal_exits=normal_exits,
        )

    def _lower_try_fragment(
        self,
        cfg: cfg_graph.Code,
        block: cfg_graph.CFGBlock,
        kind: str,
        operation: py_ast.TryExceptFinally,
        index: int | None,
        scope: tuple[str, ...],
    ) -> _OperationFragment:
        body = self._lower_suite_fragment(
            cfg,
            block,
            tuple(operation.body.blocks),
            kind=kind,
            parent_scope=scope + ("try", "body"),
            index=index,
        )

        else_fragment = None
        if operation.else_ is not None:
            else_fragment = self._lower_suite_fragment(
                cfg,
                block,
                tuple(operation.else_.blocks),
                kind=kind,
                parent_scope=scope + ("try", "else"),
                index=index,
            )

        finally_normal = None
        if operation.finally_ is not None:
            finally_normal = self._lower_suite_fragment(
                cfg,
                block,
                tuple(operation.finally_.blocks),
                kind=kind,
                parent_scope=scope + ("try", "finally", "normal"),
                index=index,
            )

        normal_out = self._new_node(
            cfg,
            block,
            "try_normal_out",
            index,
            scope=scope + ("try", "normal_out"),
            operation=operation,
        )

        nodes = [*body.nodes]
        if else_fragment is not None:
            nodes.extend(else_fragment.nodes)
        if finally_normal is not None:
            nodes.extend(finally_normal.nodes)
        nodes.append(normal_out)

        normal_target = finally_normal.entry if finally_normal is not None else normal_out

        for exit_node in body.normal_exits:
            self._record_local_edge(exit_node, else_fragment.entry if else_fragment is not None else normal_target)

        if else_fragment is not None:
            for exit_node in else_fragment.normal_exits:
                self._record_local_edge(exit_node, normal_target)

        if finally_normal is not None:
            for exit_node in finally_normal.normal_exits:
                self._record_local_edge(exit_node, normal_out)

        return _OperationFragment(
            nodes=nodes,
            entry=body.entry,
            normal_exits={normal_out},
        )

    def _connect_procedure(self, cfg: cfg_graph.Code) -> None:
        blocks = self._reachable_blocks(cfg)
        for block in blocks:
            nodes = self._nodes_by_block[block]
            for source in nodes:
                for target in self._local_successors.get(source, ()):
                    self._connect_local_successor(source, target)

            exit_sources = self._exit_sources_for_block(block, nodes)
            next_map = getattr(block, "next", None) or {}
            if self.include_exceptional_edges:
                successor_items = tuple(next_map.items())
            else:
                successor_items = tuple(
                    (name, successor)
                    for name, successor in next_map.items()
                    if name not in ("error", "fail")
                )
            for exit_name, successor in successor_items:
                for source in exit_sources(exit_name):
                    self._connect_local_successor(source, self.first_node_of_block(successor))

    def _exit_sources_for_block(
        self,
        block: cfg_graph.CFGBlock,
        nodes: list[CFGNode],
    ):
        if isinstance(block, cfg_graph.Suite) and block in self._suite_exit_nodes:
            (normal_exits,) = self._suite_exit_nodes[block]

            def resolve(exit_name: object) -> set[CFGNode]:
                if exit_name == "normal":
                    return set(normal_exits)
                return set()

            return resolve

        tail = nodes[-1]

        def resolve(_exit_name: object) -> set[CFGNode]:
            return {tail}

        return resolve

    def _connect_local_successor(self, source: CFGNode, target: CFGNode) -> None:
        call_expr = self.call_expression_of(source)
        callees = tuple(self.call_resolver(self, source, call_expr))
        if callees:
            self.supergraph.add_return_site(source, target)
            self._callee_cfgs_by_node[source] = callees
            for callee in callees:
                self.supergraph.add_call_edge(source, callee)
        else:
            self.supergraph.add_normal_edge(source, target)


def build_supergraph_from_cfgs(
    cfgs: Sequence[cfg_graph.Code],
    *,
    call_resolver: CallResolver | None = None,
    include_exceptional_edges: bool = True,
) -> CFGSupergraphAdapter:
    """Convenience wrapper for building a CFG-backed supergraph."""
    return CFGSupergraphAdapter(
        cfgs,
        call_resolver=call_resolver,
        include_exceptional_edges=include_exceptional_edges,
    )
