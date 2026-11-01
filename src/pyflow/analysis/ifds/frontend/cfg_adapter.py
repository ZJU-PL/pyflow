"""CFG-to-supergraph adapter for IFDS/IDE analyses."""

from __future__ import annotations

import ast as source_ast
from functools import cached_property
from pyflow.frontend.source import read_python_source
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
from pyflow.language.python.exception_types import exception_type_names, handler_match

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
    argument_bindings: tuple[tuple[cfg_graph.Code, tuple[tuple[object, py_ast.Local], ...]], ...]
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
    if not isinstance(call_expression, py_ast.DirectCall) or call_expression.code is None:
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
                for target_code, _context in AnalysisFacts(catalog).merged_call_targets(
                    code, call_expression
                )
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
        self._suspension_effects_by_node: Dict[CFGNode, tuple[SuspensionEffect, ...]] = {}
        self._procedure_semantics: Dict[cfg_graph.Code, ProcedureSemantics] = {
            cfg: self._infer_procedure_semantics(cfg) for cfg in self.cfgs
        }
        self._suite_exit_nodes: Dict[cfg_graph.CFGBlock, _OperationFragment] = {}
        self._generated_catalogs = {}

        for cfg in self.cfgs:
            self._register_procedure(cfg)
        for cfg in self.cfgs:
            self._connect_procedure(cfg)
        if self._generated_catalogs:
            from pyflow.ir.core.build_semantics import build_semantics

            for catalog in self._generated_catalogs.values():
                build_semantics(catalog)

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
        if not catalog.has_node(call_expression, owner.code):
            # CFG normalization can clone a nested call expression after the
            # source catalog was indexed.  Preserve model lookup through the
            # syntactic leaf instead of failing the entire IFDS solve.
            return self._syntactic_call_leaf(call_expression)
        sites = catalog.semantics.calls_for(catalog.node_id(call_expression, owner.code))
        if len(sites) != 1:
            return None
        symbolic_name = sites[0].symbolic_name
        if symbolic_name is not None:
            return self._qualify_call_name(owner, symbolic_name)
        structured = self._structured_call_name(owner, call_expression)
        return structured or self._qualify_call_name(
            owner, self._syntactic_call_leaf(call_expression)
        )

    def _structured_call_name(self, procedure, call):
        from pyflow.analysis.taint_policy.call_types import CALL_RETURN_TYPES

        def expression_name(expression):
            if isinstance(expression, py_ast.Local):
                return self._qualify_call_name(procedure, expression.name)
            if isinstance(expression, py_ast.GetGlobal):
                name = getattr(getattr(expression, "name", None), "object", None)
                name = getattr(name, "pyobj", None)
                return self._qualify_call_name(procedure, name) if isinstance(name, str) else None
            if isinstance(expression, py_ast.GetAttr):
                base = expression_name(expression.expr)
                name = getattr(getattr(expression.name, "object", None), "pyobj", None)
                return f"{base}.{name}" if base and isinstance(name, str) else None
            if isinstance(expression, py_ast.Call):
                return CALL_RETURN_TYPES.get(expression_name(expression.expr) or "")
            return None

        if isinstance(call, py_ast.Call):
            return expression_name(call.expr)
        return None

    def _procedure_filename(self, procedure):
        catalog = self.catalog_by_procedure[procedure]
        return catalog.procedure(procedure.code).code_id.anchor.filename

    @cached_property
    def _source_call_bindings(self):
        from pyflow.analysis.taint_policy.call_types import ast_receiver_bindings

        trees = {}
        bindings = {}

        def imports(scope):
            result = {}

            def visit(node):
                if node is not scope and isinstance(
                    node,
                    (
                        source_ast.FunctionDef,
                        source_ast.AsyncFunctionDef,
                        source_ast.ClassDef,
                        source_ast.Lambda,
                    ),
                ):
                    return
                if isinstance(node, source_ast.Import):
                    for alias in node.names:
                        result[alias.asname or alias.name.split(".")[0]] = (
                            alias.name if alias.asname else alias.name.split(".")[0]
                        )
                elif isinstance(node, source_ast.ImportFrom) and node.module:
                    for alias in node.names:
                        result[alias.asname or alias.name] = f"{node.module}.{alias.name}"
                for child in source_ast.iter_child_nodes(node):
                    visit(child)

            visit(scope)
            return result

        for procedure in self.cfgs:
            filename = self._procedure_filename(procedure)
            if filename not in trees:
                try:
                    trees[filename] = (
                        source_ast.parse(read_python_source(filename)) if filename else None
                    )
                except (OSError, UnicodeError, SyntaxError):
                    trees[filename] = None
            tree = trees[filename]
            if tree is None:
                bindings[procedure] = {}
                continue
            catalog = self.catalog_by_procedure[procedure]
            identity = catalog.procedure(procedure.code).code_id
            scope = next(
                (
                    node
                    for node in source_ast.walk(tree)
                    if isinstance(node, (source_ast.FunctionDef, source_ast.AsyncFunctionDef))
                    and node.lineno == identity.anchor.line
                ),
                tree,
            )
            aliases = imports(tree)
            aliases.update(imports(scope))
            bindings[procedure] = ast_receiver_bindings(scope, aliases)
        # ImportFrom lowering introduces a temporary module receiver. Its
        # spelling is an IR implementation detail, never a library identity.
        temporary_modules = {}
        for node, operation in self._operation_by_node.items():
            if isinstance(operation, py_ast.Assign) and isinstance(operation.expr, py_ast.Import):
                aliases = temporary_modules.setdefault(self._procedure_filename(node.procedure), {})
                for local in assigned_locals(operation):
                    aliases[local.name] = operation.expr.name
        for procedure, aliases in bindings.items():
            aliases.update(temporary_modules.get(self._procedure_filename(procedure), {}))
        return bindings

    def _qualify_call_name(self, procedure, name):
        if not name:
            return name
        aliases = self._source_call_bindings.get(procedure, {})
        head, separator, rest = name.partition(".")
        return aliases.get(head, head) + (separator + rest if separator else "")

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
        elif isinstance(call_expression, py_ast.Call) and isinstance(
            call_expression.expr, py_ast.GetGlobal
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

    def _slots_for_local(self, procedure: cfg_graph.Code, local: object) -> tuple[object, ...]:
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
            return catalog.semantics.operation(catalog.node_id(operation, procedure.code)).writes
        except KeyError:
            return ()

    def _written_slots_for_operation(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[object, ...]:
        if operation is None:
            return ()
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)):
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
                slot for local in locals_ for slot in self._slots_for_local(procedure, local)
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
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)):
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
        if isinstance(operation, py_ast.AnnAssign) and operation.value is call_expression:
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
        if isinstance(operation, py_ast.AnnAssign) and operation.value is call_expression:
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
                modified_slots=self._modified_slots_for_operation(node.procedure, operation),
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
        return isinstance(expr, py_ast.Existing) and getattr(expr.object, "pyobj", object()) is None

    def _build_effect(self, node: CFGNode):
        operation = self.operation_of(node)
        if node.kind == "call":
            call_expression = self.call_expression_of(node)
            if call_expression is None:
                return None
            callees = self.callees_of(node)
            bindings: list[tuple[cfg_graph.Code, tuple[tuple[object, py_ast.Local], ...]]] = []
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
                written_slots=self._written_slots_for_operation(node.procedure, operation),
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
                operation.conditional if isinstance(operation, py_ast.Condition) else operation
            )
            nullable_target, true_branch_means_null = self._guard_nullable_target(condition)
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
            if exit_name in ("error", "fail") or (node, successor) in self._exceptional_local_edges:
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
            self._nodes_by_block[block][0] for block in blocks if isinstance(block, cfg_graph.Exit)
        )
        entry = self.first_node_of_block(cfg.entryTerminal)
        self.supergraph.add_procedure(cfg, entry, exits)

        for block in blocks:
            for node in self._nodes_by_block[block]:
                if node != entry and node not in exits:
                    self.supergraph.add_node(cfg, node)

    def _make_block_nodes(self, cfg: cfg_graph.Code, block: cfg_graph.CFGBlock) -> list[CFGNode]:
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
            raise ValueError("IFDS requires try statements lowered by cfg.transform")

        nodes: list[CFGNode] = []
        previous: CFGNode | None = None
        call_expressions = iter_call_expressions_in_eval_order(operation)
        if isinstance(block, cfg_graph.ExceptionMatch) and operation is block.condition:
            call_expressions = iter_call_expressions_in_eval_order(block.handler_type)
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
        exceptional_exits = set(nodes[:-1])
        if operation is not None:
            from pyflow.ir.cfg.killflow import OpFlow

            flow = OpFlow()
            flow.process(operation)
            if flow.fails or flow.errors:
                exceptional_exits.add(terminal)
        if isinstance(operation, py_ast.Raise):
            exceptional_exits.add(terminal)
        else:
            normal_exits.add(terminal)

        return _OperationFragment(
            nodes=nodes,
            entry=nodes[0],
            normal_exits=normal_exits,
            exceptional_exits=exceptional_exits,
        )

    def _raised_exception_type_names(self, operation: object) -> tuple[str, ...]:
        if not isinstance(operation, py_ast.Raise):
            return ()
        exception = operation.exception
        if isinstance(exception, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            name = self.call_name(exception)
            return (name,) if name else ()
        return exception_type_names(exception)

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
                if exit_name in ("fail", "error") and isinstance(successor, cfg_graph.Exit):
                    continue
                for source in sorted(
                    exit_sources(exit_name), key=lambda node: (node.scope, node.kind)
                ):
                    target = self.first_node_of_block(successor)
                    if exit_name in ("fail", "error"):
                        target = self._lower_exception_edge(cfg, source, successor, exit_name)
                        self._record_exceptional_local_edge(source, target)
                    self._connect_local_successor(source, target)

    def _lower_exception_edge(self, cfg, source, successor, exit_name):
        """Bind a captured value and specialize ordered handler dispatch.

        A capture is shared by exceptional CFG predecessors. The supergraph
        binds each incoming value on its own edge, retaining explicit raise
        values and known types without re-lowering the source statement.
        """
        block = successor
        seen = set()
        while isinstance(block, cfg_graph.Merge) and block not in seen:
            seen.add(block)
            block = block.getExit("normal")
        if not isinstance(block, cfg_graph.Suite) or not block.ops:
            return self.first_node_of_block(successor)
        capture = block.ops[0]
        if not isinstance(capture, py_ast.InputBlock) or not all(
            item.src.name == "exception" for item in capture.inputs
        ):
            return self.first_node_of_block(successor)
        capture_node = next(
            node for node in self._nodes_by_block[block] if self.operation_of(node) is capture
        )
        following = tuple(self._local_successors.get(capture_node, ()))
        target = following[0] if following else self.first_node_of_block(block.getExit("normal"))
        operation = self.operation_of(source)
        raised_types = (
            self._raised_exception_type_names(operation)
            if exit_name == "fail" and source.kind != "call"
            else ()
        )
        while isinstance(target.block, cfg_graph.ExceptionMatch) and raised_types:
            matched = handler_match(raised_types, target.block.handler_type)
            if matched is None:
                break
            target = self.first_node_of_block(target.block.getExit("true" if matched else "false"))
        expression = self.call_expression_of(source)
        if expression is None:
            expression = (
                operation.exception
                if isinstance(operation, py_ast.Raise)
                else getattr(operation, "expr", None)
            )
        binding = py_ast.Assign(
            expression or py_ast.DoNotCare(), [item.lcl for item in capture.inputs]
        )
        if operation is not None:
            binding.annotation = operation.annotation
        catalog = self.catalog_by_procedure[cfg]
        catalog.register_node(catalog.procedure(cfg.code).code_id, binding)
        self._generated_catalogs[id(catalog)] = catalog
        node = self._new_node(
            cfg,
            source.block,
            "exception_bind",
            source.index,
            scope=source.scope + ("exception", str(len(self._operation_by_node))),
            operation=binding,
        )
        self.supergraph.add_node(cfg, node)
        self._record_local_edge(node, target)
        self._connect_local_successor(node, target)
        return node

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
                    result = set()
                    from pyflow.ir.cfg.killflow import OpFlow

                    for source in fragment.exceptional_exits:
                        if source.kind == "call":
                            if exit_name == "error":
                                result.add(source)
                            continue
                        operation = self.operation_of(source)
                        flow = OpFlow()
                        flow.process(operation)
                        if exit_name == "fail" and flow.fails:
                            result.add(source)
                        elif (
                            exit_name == "error"
                            and flow.errors
                            and not isinstance(operation, py_ast.Raise)
                        ):
                            result.add(source)
                    return result
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
