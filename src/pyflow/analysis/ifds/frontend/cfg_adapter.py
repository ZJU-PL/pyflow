"""CFG-to-supergraph adapter for IFDS/IDE analyses."""

from __future__ import annotations

import builtins
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Mapping, Sequence

from pyflow.ir.cfg import dfs as cfg_dfs
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.ir.core import (
    AnalysisFacts,
    Capabilities,
    LocalStorage,
    MissingAnalysisFact,
    Precision,
    ensure_codes_indexed,
    index_cfg,
)
from pyflow.language.python.ir_metadata import (
    actual_argument_expressions,
    assigned_locals,
)
from pyflow.language.python import ast as py_ast

from ..core.supergraph import Supergraph
from ..core.transfers import bind_call_arguments

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


@dataclass(frozen=True)
class CallResultRoute:
    """Adapter-level metadata for where a call result ultimately lands."""

    kind: str
    assigned_locals: tuple[py_ast.Local, ...] = ()
    modified_slots: tuple[object, ...] = ()
    return_expression_index: int | None = None


@dataclass(frozen=True)
class CallEffect:
    """Effect summary for a lowered call-expression node."""

    node: CFGNode
    operation: py_ast.PythonASTNode | None
    call_expression: py_ast.PythonASTNode
    evaluation_index: int | None
    call_name: str | None
    callees: tuple[cfg_graph.Code, ...]
    actual_arguments: tuple[object, ...]
    argument_bindings: tuple[
        tuple[cfg_graph.Code, tuple[tuple[object, py_ast.Local], ...]], ...
    ]
    return_sites: tuple[CFGNode, ...]
    kill_slots: tuple[object, ...]
    result_route: CallResultRoute
    semantic_role: str | None = None


@dataclass(frozen=True)
class SuspensionEffect:
    """Await/yield boundary retained for async and generator-aware clients."""

    node: CFGNode
    operation: py_ast.PythonASTNode
    kind: str
    value: object | None


@dataclass(frozen=True)
class ProcedureSemantics:
    """Execution model inferred for an analyzed procedure."""

    is_async: bool = False
    is_generator: bool = False
    is_async_generator: bool = False


@dataclass(frozen=True)
class StoreEffect:
    """Effect summary for nodes that overwrite storage."""

    node: CFGNode
    operation: py_ast.PythonASTNode | None
    assigned_locals: tuple[py_ast.Local, ...]
    written_slots: tuple[object, ...]
    strong_update_slots: tuple[object, ...]


@dataclass(frozen=True)
class ReturnEffect:
    """Effect summary for return statements."""

    node: CFGNode
    operation: py_ast.Return
    expressions: tuple[object, ...]
    return_slots_by_index: tuple[tuple[object, ...], ...]


@dataclass(frozen=True)
class GuardEffect:
    """Effect summary for branch-refining conditional nodes."""

    node: CFGNode
    operation: py_ast.PythonASTNode | None
    condition: object
    true_successors: tuple[CFGNode, ...]
    false_successors: tuple[CFGNode, ...]
    nullable_target: object | None = None
    true_branch_means_null: bool | None = None


@dataclass(frozen=True)
class ExceptionalEffect:
    """Effect summary for nodes on exceptional control-flow paths."""

    node: CFGNode
    operation: py_ast.PythonASTNode | None
    exceptional_successors: tuple[CFGNode, ...]
    normal_successors: tuple[CFGNode, ...]
    raises: bool
    exception_types: tuple[str, ...] = ()


@dataclass
class _OperationFragment:
    nodes: list[CFGNode] = field(default_factory=list)
    entry: CFGNode | None = None
    normal_exits: set[CFGNode] = field(default_factory=set)
    exceptional_exits: set[CFGNode] = field(default_factory=set)
    abrupt_exits: dict[str, set[CFGNode]] = field(default_factory=dict)


def _merge_abrupt_exits(
    *mappings: Mapping[str, set[CFGNode]],
) -> dict[str, set[CFGNode]]:
    merged: dict[str, set[CFGNode]] = defaultdict(set)
    for mapping in mappings:
        for kind, nodes in mapping.items():
            merged[kind].update(nodes)
    return dict(merged)


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


def iter_suspension_expressions(
    node: py_ast.PythonASTNode | None,
) -> tuple[py_ast.PythonASTNode, ...]:
    """Return await/yield expressions nested in one lowered operation."""
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
        if isinstance(
            current,
            (py_ast.Await, py_ast.Yield, py_ast.YieldFrom, py_ast.AsyncYield),
        ):
            found.append(current)
        if hasattr(current, "visitChildren"):
            current.visitChildren(visit)

    visit(node)
    return tuple(found)


def direct_call_cfg_resolver(
    adapter: "CFGSupergraphAdapter",
    node: CFGNode,
    call_expression: py_ast.PythonASTNode | None,
) -> tuple[cfg_graph.Code, ...]:
    """Resolve callees through ``ast.DirectCall.code``."""
    if (
        not isinstance(call_expression, py_ast.DirectCall)
        or call_expression.code is None
    ):
        return ()
    callee = adapter.cfg_by_ast_code.get(call_expression.code)
    if callee is None:
        return ()
    return (callee,)


def fact_call_targets_cfg_resolver(
    adapter: "CFGSupergraphAdapter",
    node: CFGNode,
    call_expression: py_ast.PythonASTNode | None,
) -> tuple[cfg_graph.Code, ...]:
    """Resolve context-insensitive callees from published IPA/CPA facts."""
    if call_expression is None:
        return ()
    code = getattr(node.procedure, "code", None)
    catalog = adapter.catalog_by_procedure.get(node.procedure)
    if not isinstance(code, py_ast.Code) or catalog is None:
        return ()
    node_id = catalog.node_id(call_expression, code)
    code_result = catalog.facts.query(Capabilities.CALL_TARGET_CODES, node_id)
    if code_result.precision is not Precision.UNKNOWN:
        target_codes = {
            catalog.code(code_id)
            for code_id in code_result.values
            if catalog.has_procedure(code_id)
        }
    else:
        try:
            target_codes = {
                target_code
                for target_code, _context in AnalysisFacts(
                    catalog
                ).merged_call_targets(code, call_expression)
            }
        except (KeyError, MissingAnalysisFact):
            return ()
    resolved = {
        adapter.cfg_by_ast_code[target_code]
        for target_code in target_codes
        if target_code in adapter.cfg_by_ast_code
    }
    return tuple(
        sorted(
            resolved,
            key=lambda cfg: str(catalog.procedure(cfg.code).code_id),
        )
    )


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
    Build a reusable IFDS supergraph from existing ``ir.cfg`` graphs.

    Suites are lowered to statement-level nodes so dataflow problems can reason
    about operations in program order and model call sites precisely.
    """

    def __init__(
        self,
        cfgs: Sequence[cfg_graph.Code],
        *,
        call_resolver: CallResolver | None = None,
        include_exceptional_edges: bool = True,
        procedure_heap_summaries: dict[object, object] | None = None,
        catalog=None,
        cfgs_indexed: bool = False,
    ) -> None:
        self.cfgs = tuple(cfgs)
        self.call_resolver = call_resolver or composite_cfg_resolver(
            direct_call_cfg_resolver,
            fact_call_targets_cfg_resolver,
        )
        self.include_exceptional_edges = include_exceptional_edges
        self.procedure_heap_summaries = dict(procedure_heap_summaries or {})
        self.catalog_by_procedure = {}
        if catalog is None:
            catalog = ensure_codes_indexed(
                (
                    cfg.code
                    for cfg in self.cfgs
                    if isinstance(getattr(cfg, "code", None), py_ast.Code)
                ),
                rebuild_semantics=False,
            )
        for cfg in self.cfgs:
            code = getattr(cfg, "code", None)
            if not isinstance(code, py_ast.Code):
                continue
            if not cfgs_indexed:
                index_cfg(catalog, cfg, rebuild_semantics=False)
            self.catalog_by_procedure[cfg] = catalog

        if self.catalog_by_procedure and not cfgs_indexed:
            from pyflow.ir.core.build_semantics import build_semantics

            build_semantics(catalog)

        self.cfg_by_ast_code = {
            cfg.code: cfg for cfg in self.cfgs if getattr(cfg, "code", None) is not None
        }
        self.supergraph = Supergraph[cfg_graph.Code, CFGNode]()
        self._nodes_by_block: Dict[cfg_graph.CFGBlock, list[CFGNode]] = {}
        self._operation_by_node: Dict[CFGNode, py_ast.PythonASTNode | None] = {}
        self._call_expr_by_node: Dict[CFGNode, py_ast.PythonASTNode] = {}
        self._callee_cfgs_by_node: Dict[CFGNode, tuple[cfg_graph.Code, ...]] = {}
        self._local_successors: Dict[CFGNode, set[CFGNode]] = {}
        self._exceptional_local_edges: set[tuple[CFGNode, CFGNode]] = set()
        self._effect_by_node: Dict[CFGNode, object] = {}
        self._suspension_effects_by_node: Dict[
            CFGNode, tuple[SuspensionEffect, ...]
        ] = {}
        self._procedure_semantics: Dict[cfg_graph.Code, ProcedureSemantics] = {
            cfg: self._infer_procedure_semantics(cfg) for cfg in self.cfgs
        }
        self._suite_exit_nodes: Dict[cfg_graph.CFGBlock, _OperationFragment] = {}

        for cfg in self.cfgs:
            self._register_procedure(cfg)
        for cfg in self.cfgs:
            self._connect_procedure(cfg)

    def call_name(
        self,
        call_expression: object,
        procedure: cfg_graph.Code | None = None,
    ) -> str | None:
        """Read a symbolic call name from the shared structural semantics."""
        if call_expression is None:
            return None
        if procedure is not None:
            candidates = ((procedure, self.catalog_by_procedure[procedure]),)
        else:
            candidates = tuple(
                (candidate, catalog)
                for candidate, catalog in self.catalog_by_procedure.items()
                if catalog.has_node(call_expression, candidate.code)
            )
        if len(candidates) != 1:
            return None
        owner, catalog = candidates[0]
        sites = catalog.semantics.calls_for(
            catalog.node_id(call_expression, owner.code)
        )
        if len(sites) != 1:
            return None
        symbolic_name = sites[0].symbolic_name
        if symbolic_name is not None:
            return symbolic_name
        return self._syntactic_call_leaf(call_expression)

    @staticmethod
    def _syntactic_call_leaf(call_expression: object) -> str | None:
        """Recover a stable method leaf when receiver qualification is unknown.

        Structural call indexing deliberately leaves names such as
        ``factory(...).method(...)`` unresolved because the receiver has no
        static qualified name.  IFDS call models can still safely use the
        explicit attribute leaf; the model registry accepts it only when that
        leaf identifies compatible active models.
        """
        name = None
        if isinstance(call_expression, py_ast.Call) and isinstance(
            call_expression.expr, py_ast.GetAttr
        ):
            name = call_expression.expr.name
        elif isinstance(call_expression, py_ast.MethodCall):
            name = call_expression.name
        if isinstance(name, py_ast.Local):
            return name.name
        if isinstance(name, py_ast.Existing):
            pyobj = getattr(name.object, "pyobj", None)
            if isinstance(pyobj, str):
                return pyobj
        return None

    def operation_of(self, node: CFGNode):
        return self._operation_by_node.get(node)

    def call_expression_of(self, node: CFGNode):
        return self._call_expr_by_node.get(node)

    def callees_of(self, node: CFGNode) -> tuple[cfg_graph.Code, ...]:
        return self._callee_cfgs_by_node.get(node, ())

    def effect_of(self, node: CFGNode):
        """Return cached adapter-level effect metadata for a lowered CFG node."""
        effect = self._effect_by_node.get(node)
        if effect is not None:
            return effect
        effect = self._build_effect(node)
        self._effect_by_node[node] = effect
        return effect

    def procedure_semantics(self, procedure: cfg_graph.Code) -> ProcedureSemantics:
        return self._procedure_semantics.get(procedure, ProcedureSemantics())

    def procedure_heap_summary(self, procedure: cfg_graph.Code):
        """Return a flow-sensitive heap summary supplied by the alias pass."""
        try:
            summary = self.procedure_heap_summaries.get(procedure)
        except TypeError:
            summary = None
        if summary is not None:
            return summary
        code = getattr(procedure, "code", None)
        if code is not None:
            return self.procedure_heap_summaries.get(code)
        return None

    def suspension_effects_of(self, node: CFGNode) -> tuple[SuspensionEffect, ...]:
        """Return every suspension boundary evaluated by ``node``."""
        cached = self._suspension_effects_by_node.get(node)
        if cached is not None:
            return cached
        effects = tuple(
            SuspensionEffect(
                node=node,
                operation=suspension,
                kind={
                    py_ast.Await: "await",
                    py_ast.Yield: "yield",
                    py_ast.YieldFrom: "yield_from",
                    py_ast.AsyncYield: "async_yield",
                }[type(suspension)],
                value=getattr(suspension, "expr", None),
            )
            for suspension in iter_suspension_expressions(self.operation_of(node))
        )
        self._suspension_effects_by_node[node] = effects
        return effects

    def is_exceptional_successor(self, source: CFGNode, target: CFGNode) -> bool:
        return (source, target) in self._exceptional_local_edges or (
            source.block is not target.block
            and source.block.findExit(target.block) in ("error", "fail")
        )

    def nodes_for_block(self, block: cfg_graph.CFGBlock) -> tuple[CFGNode, ...]:
        return tuple(self._nodes_by_block[block])

    def first_node_of_block(self, block: cfg_graph.CFGBlock) -> CFGNode:
        return self._nodes_by_block[block][0]

    def last_node_of_block(self, block: cfg_graph.CFGBlock) -> CFGNode:
        return self._nodes_by_block[block][-1]

    def _canonical_slot(self, slot: object) -> object:
        get_forward = getattr(slot, "getForward", None)
        if callable(get_forward):
            return get_forward()
        return slot

    def _slots_for_local(
        self, procedure: cfg_graph.Code, local: object
    ) -> tuple[object, ...]:
        catalog = self.catalog_by_procedure.get(procedure)
        code = getattr(procedure, "code", None)
        if catalog is None or code is None or not catalog.has_symbol(local, code):
            return ()
        return (LocalStorage(catalog.symbol_id(local, code)),)

    def _modified_slots_for_operation(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[object, ...]:
        catalog = self.catalog_by_procedure.get(procedure)
        if catalog is None:
            return ()
        try:
            return catalog.semantics.operation(
                catalog.node_id(operation, procedure.code)
            ).writes
        except KeyError:
            return ()

    def _written_slots_for_operation(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[object, ...]:
        if operation is None:
            return ()
        if isinstance(
            operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)
        ):
            return tuple(
                slot
                for local in assigned_locals(operation)
                for slot in self._slots_for_local(procedure, local)
            )
        if isinstance(operation, py_ast.Delete):
            return tuple(self._slots_for_local(procedure, operation.lcl))
        if isinstance(operation, py_ast.InputBlock):
            locals_: list[py_ast.Local] = []
            for input_ in getattr(operation, "inputs", ()):
                lcl = getattr(input_, "lcl", None)
                if isinstance(lcl, py_ast.Local):
                    locals_.append(lcl)
            return tuple(
                slot
                for local in locals_
                for slot in self._slots_for_local(procedure, local)
            )
        if isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetGlobal,
                py_ast.DeleteGlobal,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            return self._modified_slots_for_operation(procedure, operation)
        return ()

    def _strong_update_slots_for_operation(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[object, ...]:
        if operation is None:
            return ()
        if isinstance(
            operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)
        ):
            return self._written_slots_for_operation(procedure, operation)
        if isinstance(operation, (py_ast.Delete, py_ast.InputBlock)):
            return self._written_slots_for_operation(procedure, operation)
        if isinstance(
            operation,
            (py_ast.SetGlobal, py_ast.DeleteGlobal, py_ast.SetCellDeref),
        ):
            return self._written_slots_for_operation(procedure, operation)
        return ()

    def _call_kill_slots(self, node: CFGNode) -> tuple[object, ...]:
        operation = self.operation_of(node)
        call_expression = self.call_expression_of(node)
        if operation is None or call_expression is None:
            return ()
        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
            return tuple(
                slot
                for local in assigned_locals(operation)
                for slot in self._slots_for_local(node.procedure, local)
            )
        if (
            isinstance(operation, py_ast.AnnAssign)
            and operation.value is call_expression
        ):
            return tuple(
                slot
                for local in assigned_locals(operation)
                for slot in self._slots_for_local(node.procedure, local)
            )
        if (
            isinstance(operation, (py_ast.SetGlobal, py_ast.SetCellDeref))
            and operation.value is call_expression
        ):
            return self._modified_slots_for_operation(node.procedure, operation)
        return ()

    def _call_result_route(self, node: CFGNode) -> CallResultRoute:
        operation = self.operation_of(node)
        call_expression = self.call_expression_of(node)
        if operation is None or call_expression is None:
            return CallResultRoute("expression")
        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
            return CallResultRoute(
                "assigned_locals",
                assigned_locals=assigned_locals(operation),
            )
        if (
            isinstance(operation, py_ast.AnnAssign)
            and operation.value is call_expression
        ):
            return CallResultRoute(
                "assigned_locals",
                assigned_locals=assigned_locals(operation),
            )
        if isinstance(operation, py_ast.Return):
            for index, expr in enumerate(operation.exprs):
                if expr is call_expression:
                    return CallResultRoute("return_slot", return_expression_index=index)
        if (
            isinstance(
                operation,
                (
                    py_ast.SetAttr,
                    py_ast.SetSubscript,
                    py_ast.SetSlice,
                    py_ast.SetGlobal,
                    py_ast.SetCellDeref,
                    py_ast.Store,
                ),
            )
            and getattr(operation, "value", None) is call_expression
        ):
            return CallResultRoute(
                "modified_slots",
                modified_slots=self._modified_slots_for_operation(
                    node.procedure, operation
                ),
            )
        return CallResultRoute("expression")

    def _guard_nullable_target(self, expr: object):
        if isinstance(expr, py_ast.ConvertToBool):
            return self._guard_nullable_target(expr.expr)
        if isinstance(expr, py_ast.Is):
            if self._is_explicit_null_expression(expr.right):
                return expr.left, True
            if self._is_explicit_null_expression(expr.left):
                return expr.right, True
        if isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            call_name = self.call_name(expr)
            if call_name in {"interpreter__is__", "interpreter__is_not__"}:
                actuals = actual_argument_expressions(expr)
                if len(actuals) == 2:
                    left, right = actuals
                    if self._is_explicit_null_expression(right):
                        return left, call_name == "interpreter__is__"
                    if self._is_explicit_null_expression(left):
                        return right, call_name == "interpreter__is__"
        if isinstance(expr, py_ast.Not):
            target, true_means_null = self._guard_nullable_target(expr.expr)
            if target is not None:
                return target, not true_means_null
        return None, None

    def _is_explicit_null_expression(self, expr: object) -> bool:
        return (
            isinstance(expr, py_ast.Existing)
            and getattr(expr.object, "pyobj", object()) is None
        )

    def _build_effect(self, node: CFGNode):
        operation = self.operation_of(node)
        if node.kind == "call":
            call_expression = self.call_expression_of(node)
            if call_expression is None:
                return None
            callees = self.callees_of(node)
            bindings: list[
                tuple[cfg_graph.Code, tuple[tuple[object, py_ast.Local], ...]]
            ] = []
            for callee in callees:
                params = getattr(getattr(callee, "code", None), "codeparameters", None)
                if params is None:
                    continue
                bindings.append((callee, bind_call_arguments(call_expression, params)))
            call_name = self.call_name(call_expression, node.procedure)
            return CallEffect(
                node=node,
                operation=operation,
                call_expression=call_expression,
                evaluation_index=node.call_index,
                call_name=call_name,
                callees=callees,
                actual_arguments=actual_argument_expressions(call_expression),
                argument_bindings=tuple(bindings),
                return_sites=self.supergraph.return_sites_of_call_at(node),
                kill_slots=self._call_kill_slots(node),
                result_route=self._call_result_route(node),
                semantic_role=self._call_semantic_role(call_name),
            )

        suspension_effects = self.suspension_effects_of(node)
        if suspension_effects:
            return suspension_effects[0]

        if isinstance(operation, py_ast.Return):
            return ReturnEffect(
                node=node,
                operation=operation,
                expressions=tuple(operation.exprs),
                return_slots_by_index=(
                    tuple(
                        self._slots_for_local(node.procedure, local)
                        for local in node.procedure.code.codeparameters.returnparams
                    )
                    if getattr(node.procedure, "code", None) is not None
                    else ()
                ),
            )

        if operation is not None and isinstance(
            operation,
            (
                py_ast.Assign,
                py_ast.UnpackSequence,
                py_ast.AnnAssign,
                py_ast.Delete,
                py_ast.InputBlock,
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetGlobal,
                py_ast.DeleteGlobal,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            return StoreEffect(
                node=node,
                operation=operation,
                assigned_locals=assigned_locals(operation),
                written_slots=self._written_slots_for_operation(
                    node.procedure, operation
                ),
                strong_update_slots=self._strong_update_slots_for_operation(
                    node.procedure, operation
                ),
            )

        if node.kind in {"condition", "typeswitch"} and operation is not None:
            true_successors: list[CFGNode] = []
            false_successors: list[CFGNode] = []
            for successor in self.supergraph.normal_successors(node):
                exit_name = node.block.findExit(successor.block)
                if exit_name == "true":
                    true_successors.append(successor)
                elif exit_name == "false":
                    false_successors.append(successor)
            condition = (
                operation.conditional
                if isinstance(operation, py_ast.Condition)
                else operation
            )
            nullable_target, true_branch_means_null = self._guard_nullable_target(
                condition
            )
            return GuardEffect(
                node=node,
                operation=operation,
                condition=condition,
                true_successors=tuple(true_successors),
                false_successors=tuple(false_successors),
                nullable_target=nullable_target,
                true_branch_means_null=true_branch_means_null,
            )

        normal_successors: list[CFGNode] = []
        exceptional_successors: list[CFGNode] = []
        for successor in self.supergraph.normal_successors(node):
            exit_name = node.block.findExit(successor.block)
            if exit_name in ("error", "fail"):
                exceptional_successors.append(successor)
            else:
                normal_successors.append(successor)
        if exceptional_successors or isinstance(operation, py_ast.Raise):
            return ExceptionalEffect(
                node=node,
                operation=operation,
                exceptional_successors=tuple(exceptional_successors),
                normal_successors=tuple(normal_successors),
                raises=isinstance(operation, py_ast.Raise),
                exception_types=self._raised_exception_type_names(operation),
            )
        return None

    @staticmethod
    def _call_semantic_role(call_name: str | None) -> str | None:
        if not call_name:
            return None
        leaf = call_name.rsplit(".", 1)[-1]
        return {
            "__enter__": "context_enter",
            "__exit__": "context_exit",
            "__aenter__": "async_context_enter",
            "__aexit__": "async_context_exit",
            "interpreter_enter": "context_enter",
            "interpreter_exit": "context_exit",
            "interpreter_aenter": "async_context_enter",
            "interpreter_aexit": "async_context_exit",
            "interpreter_aiter": "async_iter",
            "interpreter_anext": "async_next",
        }.get(leaf)

    def _infer_procedure_semantics(self, cfg: cfg_graph.Code) -> ProcedureSemantics:
        code = getattr(cfg, "code", None)
        catalog = self.catalog_by_procedure.get(cfg)
        if code is None or catalog is None:
            return ProcedureSemantics()
        procedure = catalog.procedure(code)
        return ProcedureSemantics(
            is_async=procedure.is_async,
            is_generator=procedure.is_generator,
            is_async_generator=procedure.is_async and procedure.is_generator,
        )

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
                self._suite_exit_nodes[block] = fragment
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
        elif isinstance(block, cfg_graph.ForIter):
            fragment = self._lower_operation_fragment(
                cfg, block, "foriter", block.iterator, None, ()
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

    def _record_exceptional_local_edge(self, source: CFGNode, target: CFGNode) -> None:
        self._record_local_edge(source, target)
        self._exceptional_local_edges.add((source, target))

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
                exceptional_exits=set(),
                abrupt_exits={},
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
                exceptional_exits={
                    *composed.exceptional_exits,
                    *fragment.exceptional_exits,
                },
                abrupt_exits=_merge_abrupt_exits(
                    composed.abrupt_exits, fragment.abrupt_exits
                ),
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
        # Every call may raise unless a future call model proves otherwise.
        exceptional_exits = set(nodes[:-1]) if "try" in scope else set()
        abrupt_exits: dict[str, set[CFGNode]] = {}
        if isinstance(operation, py_ast.Raise):
            exceptional_exits.add(terminal)
        elif isinstance(operation, py_ast.Return) and "try" in scope:
            abrupt_exits["return"] = {terminal}
        elif isinstance(operation, py_ast.Break) and "try" in scope:
            abrupt_exits["break"] = {terminal}
        elif isinstance(operation, py_ast.Continue) and "try" in scope:
            abrupt_exits["continue"] = {terminal}
        else:
            normal_exits.add(terminal)

        return _OperationFragment(
            nodes=nodes,
            entry=nodes[0],
            normal_exits=normal_exits,
            exceptional_exits=exceptional_exits,
            abrupt_exits=abrupt_exits,
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

        handler_fragments: list[_OperationFragment] = []
        handler_types: list[tuple[str, ...]] = []
        for handler_index, handler in enumerate(operation.handlers):
            handler_parts: list[_OperationFragment] = []
            preamble = self._lower_suite_fragment(
                cfg,
                block,
                tuple(handler.preamble.blocks),
                kind=kind,
                parent_scope=scope + ("try", "handler", str(handler_index), "preamble"),
                index=index,
            )
            handler_parts.append(preamble)
            if handler.value is not None:
                handler_parts.append(
                    self._lower_operation_fragment(
                        cfg,
                        block,
                        kind,
                        handler.value,
                        index,
                        scope + ("try", "handler", str(handler_index), "value"),
                    )
                )
            handler_body = self._lower_suite_fragment(
                cfg,
                block,
                tuple(handler.body.blocks),
                kind=kind,
                parent_scope=scope + ("try", "handler", str(handler_index), "body"),
                index=index,
            )
            handler_parts.append(handler_body)

            fragment = handler_parts[0]
            for next_part in handler_parts[1:]:
                for exit_node in fragment.normal_exits:
                    self._record_local_edge(exit_node, next_part.entry)
                fragment = _OperationFragment(
                    nodes=[*fragment.nodes, *next_part.nodes],
                    entry=fragment.entry,
                    normal_exits=set(next_part.normal_exits),
                    exceptional_exits={
                        *fragment.exceptional_exits,
                        *next_part.exceptional_exits,
                    },
                    abrupt_exits=_merge_abrupt_exits(
                        fragment.abrupt_exits, next_part.abrupt_exits
                    ),
                )
            handler_fragments.append(fragment)
            handler_types.append(self._exception_type_names(handler.type))

        default_fragment = None
        if operation.defaultHandler is not None:
            default_fragment = self._lower_suite_fragment(
                cfg,
                block,
                tuple(operation.defaultHandler.blocks),
                kind=kind,
                parent_scope=scope + ("try", "default"),
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
        finally_exceptional = None
        if operation.finally_ is not None:
            finally_normal = self._lower_suite_fragment(
                cfg,
                block,
                tuple(operation.finally_.blocks),
                kind=kind,
                parent_scope=scope + ("try", "finally", "normal"),
                index=index,
            )
            finally_exceptional = self._lower_suite_fragment(
                cfg,
                block,
                tuple(operation.finally_.blocks),
                kind=kind,
                parent_scope=scope + ("try", "finally", "exceptional"),
                index=index,
            )

        abrupt_inputs = _merge_abrupt_exits(
            body.abrupt_exits,
            *(fragment.abrupt_exits for fragment in handler_fragments),
            default_fragment.abrupt_exits if default_fragment is not None else {},
            else_fragment.abrupt_exits if else_fragment is not None else {},
        )
        finally_abrupt: dict[str, _OperationFragment] = {}
        if operation.finally_ is not None:
            for abrupt_kind in sorted(abrupt_inputs):
                finally_abrupt[abrupt_kind] = self._lower_suite_fragment(
                    cfg,
                    block,
                    tuple(operation.finally_.blocks),
                    kind=kind,
                    parent_scope=scope + ("try", "finally", "abrupt", abrupt_kind),
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
        for fragment in handler_fragments:
            nodes.extend(fragment.nodes)
        if default_fragment is not None:
            nodes.extend(default_fragment.nodes)
        if else_fragment is not None:
            nodes.extend(else_fragment.nodes)
        if finally_normal is not None:
            nodes.extend(finally_normal.nodes)
        if finally_exceptional is not None:
            nodes.extend(finally_exceptional.nodes)
        for abrupt_kind in sorted(finally_abrupt):
            nodes.extend(finally_abrupt[abrupt_kind].nodes)
        nodes.append(normal_out)

        normal_target = (
            finally_normal.entry if finally_normal is not None else normal_out
        )

        for exit_node in body.normal_exits:
            self._record_local_edge(
                exit_node,
                else_fragment.entry if else_fragment is not None else normal_target,
            )

        unhandled_body_exits: set[CFGNode] = set()
        for exit_node in body.exceptional_exits:
            raised_types = self._raised_exception_type_names(
                self._operation_by_node.get(exit_node)
            )
            matching_handlers = self._matching_handler_entries(
                tuple(zip(handler_fragments, handler_types)), raised_types
            )
            if matching_handlers:
                for target in matching_handlers:
                    self._record_exceptional_local_edge(exit_node, target)
                continue
            if default_fragment is not None:
                self._record_exceptional_local_edge(exit_node, default_fragment.entry)
            elif finally_exceptional is not None:
                self._record_exceptional_local_edge(
                    exit_node, finally_exceptional.entry
                )
            else:
                unhandled_body_exits.add(exit_node)

        abrupt_outputs: dict[str, set[CFGNode]] = defaultdict(set)
        abrupt_finally_exceptions: set[CFGNode] = set()
        for abrupt_kind, exit_nodes in abrupt_inputs.items():
            finally_fragment = finally_abrupt.get(abrupt_kind)
            if finally_fragment is None:
                abrupt_outputs[abrupt_kind].update(exit_nodes)
                continue
            for exit_node in exit_nodes:
                self._record_local_edge(exit_node, finally_fragment.entry)
            abrupt_outputs[abrupt_kind].update(finally_fragment.normal_exits)
            for override_kind, override_nodes in finally_fragment.abrupt_exits.items():
                abrupt_outputs[override_kind].update(override_nodes)
            abrupt_finally_exceptions.update(finally_fragment.exceptional_exits)

        if else_fragment is not None:
            for exit_node in else_fragment.normal_exits:
                self._record_local_edge(exit_node, normal_target)

        for fragment in handler_fragments:
            for exit_node in fragment.normal_exits:
                self._record_local_edge(exit_node, normal_target)
            if finally_exceptional is not None:
                for exit_node in fragment.exceptional_exits:
                    self._record_exceptional_local_edge(
                        exit_node, finally_exceptional.entry
                    )

        if default_fragment is not None:
            for exit_node in default_fragment.normal_exits:
                self._record_local_edge(exit_node, normal_target)
            if finally_exceptional is not None:
                for exit_node in default_fragment.exceptional_exits:
                    self._record_exceptional_local_edge(
                        exit_node, finally_exceptional.entry
                    )

        if finally_normal is not None:
            for exit_node in finally_normal.normal_exits:
                self._record_local_edge(exit_node, normal_out)
            for abrupt_kind, exit_nodes in finally_normal.abrupt_exits.items():
                abrupt_outputs[abrupt_kind].update(exit_nodes)
        exceptional_exits: set[CFGNode] = set()
        if finally_exceptional is not None:
            exceptional_exits.update(finally_exceptional.normal_exits)
            exceptional_exits.update(finally_exceptional.exceptional_exits)
            for abrupt_kind, exit_nodes in finally_exceptional.abrupt_exits.items():
                abrupt_outputs[abrupt_kind].update(exit_nodes)
        else:
            for fragment in handler_fragments:
                exceptional_exits.update(fragment.exceptional_exits)
            if default_fragment is not None:
                exceptional_exits.update(default_fragment.exceptional_exits)
            if not handler_fragments and default_fragment is None:
                exceptional_exits.update(body.exceptional_exits)
            exceptional_exits.update(unhandled_body_exits)
        exceptional_exits.update(abrupt_finally_exceptions)

        return _OperationFragment(
            nodes=nodes,
            entry=body.entry,
            normal_exits={normal_out},
            exceptional_exits=exceptional_exits,
            abrupt_exits=dict(abrupt_outputs),
        )

    @staticmethod
    def _exception_type_names(expr: object) -> tuple[str, ...]:
        if expr is None:
            return ()
        if isinstance(expr, py_ast.Local) and expr.name:
            return (expr.name,)
        if isinstance(expr, py_ast.Existing):
            value = getattr(expr.object, "pyobj", None)
            if isinstance(value, tuple):
                names: list[str] = []
                for item in value:
                    name = getattr(item, "__qualname__", None) or getattr(
                        item, "__name__", None
                    )
                    if name:
                        names.append(str(name))
                return tuple(names)
            name = getattr(value, "__qualname__", None) or getattr(
                value, "__name__", None
            )
            return (str(name),) if name else ()
        if isinstance(expr, (list, tuple)):
            names: list[str] = []
            for item in expr:
                names.extend(CFGSupergraphAdapter._exception_type_names(item))
            return tuple(dict.fromkeys(names))
        return ()

    def _raised_exception_type_names(self, operation: object) -> tuple[str, ...]:
        if not isinstance(operation, py_ast.Raise):
            return ()
        exception = operation.exception
        if isinstance(exception, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            name = self.call_name(exception)
            return (name,) if name else ()
        return self._exception_type_names(exception)

    @staticmethod
    def _exception_name_matches(raised: str, handled: str) -> bool:
        raised_leaf = raised.rsplit(".", 1)[-1]
        handled_leaf = handled.rsplit(".", 1)[-1]
        if raised == handled or raised_leaf == handled_leaf:
            return True
        raised_type = getattr(builtins, raised_leaf, None)
        handled_type = getattr(builtins, handled_leaf, None)
        return (
            isinstance(raised_type, type)
            and isinstance(handled_type, type)
            and issubclass(raised_type, BaseException)
            and issubclass(handled_type, BaseException)
            and issubclass(raised_type, handled_type)
        )

    @classmethod
    def _matching_handler_entries(
        cls,
        handlers: tuple[tuple[_OperationFragment, tuple[str, ...]], ...],
        raised_types: tuple[str, ...],
    ) -> tuple[CFGNode, ...]:
        if not handlers:
            return ()
        if not raised_types:
            # Unknown exceptions conservatively reach typed handlers up to and
            # including the first bare handler.
            entries: list[CFGNode] = []
            for fragment, handled_types in handlers:
                entries.append(fragment.entry)
                if not handled_types:
                    break
            return tuple(entries)
        for fragment, handled_types in handlers:
            if not handled_types:
                return (fragment.entry,)
            if any(
                cls._exception_name_matches(raised, handled)
                for raised in raised_types
                for handled in handled_types
            ):
                return (fragment.entry,)
        return ()

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
                # Unhandled exceptional termination is represented by the
                # operation's ExceptionalEffect, not as ordinary intraprocedural
                # flow to a procedure exit.
                if exit_name in ("fail", "error") and isinstance(
                    successor, cfg_graph.Exit
                ):
                    continue
                for source in exit_sources(exit_name):
                    self._connect_local_successor(
                        source, self.first_node_of_block(successor)
                    )

    def _exit_sources_for_block(
        self,
        block: cfg_graph.CFGBlock,
        nodes: list[CFGNode],
    ):
        if isinstance(block, cfg_graph.Suite) and block in self._suite_exit_nodes:
            fragment = self._suite_exit_nodes[block]

            def resolve(exit_name: object) -> set[CFGNode]:
                if exit_name == "normal":
                    return set(fragment.normal_exits)
                if exit_name in ("error", "fail"):
                    return set(fragment.exceptional_exits)
                if isinstance(exit_name, str) and exit_name in fragment.abrupt_exits:
                    return set(fragment.abrupt_exits[exit_name])
                return set(fragment.normal_exits)

            return resolve

        tail = nodes[-1]

        def resolve(_exit_name: object) -> set[CFGNode]:
            return {tail}

        return resolve

    def _connect_local_successor(self, source: CFGNode, target: CFGNode) -> None:
        if (source, target) in self._exceptional_local_edges:
            self.supergraph.add_normal_edge(source, target)
            return
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
    catalog=None,
    cfgs_indexed: bool = False,
) -> CFGSupergraphAdapter:
    """Convenience wrapper for building a CFG-backed supergraph."""
    return CFGSupergraphAdapter(
        cfgs,
        call_resolver=call_resolver,
        include_exceptional_edges=include_exceptional_edges,
        catalog=catalog,
        cfgs_indexed=cfgs_indexed,
    )
