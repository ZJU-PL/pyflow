"""Build mandatory context-independent semantics from normalized Python IR."""

from __future__ import annotations

from collections.abc import Hashable, Iterable
from typing import TypeVar

from pyflow.language.python import ast

from .catalog import IRCatalog
from .ids import AllocationSiteId, CallSiteId
from .semantics import CallSite, ControlEffects, OperationSemantics
from .storage import (
    AttributeStorage,
    CellStorage,
    GlobalStorage,
    LocalStorage,
    StorageLocation,
    SubscriptStorage,
    UnknownStorage,
)
from .symbols import SymbolKind


_ALLOCATION_TYPES = (
    ast.Allocate,
    ast.BuildList,
    ast.BuildMap,
    ast.BuildSet,
    ast.BuildTuple,
    ast.MakeFunction,
)
_CALL_TYPES = (ast.Call, ast.MethodCall, ast.DirectCall)
H = TypeVar("H", bound=Hashable)


def _flatten(value):
    if isinstance(value, (tuple, list)):
        for item in value:
            yield from _flatten(item)
    elif value is not None:
        yield value


def _children(node):
    if isinstance(node, (tuple, list)):
        return tuple(_flatten(node))
    children = getattr(node, "children", None)
    return tuple(_flatten(children())) if children is not None else ()


def _dedupe(values: Iterable[H]) -> tuple[H, ...]:
    result: list[H] = []
    seen: set[H] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def _definition_references(node) -> tuple[object, ...]:
    if isinstance(node, ast.Assign):
        return tuple(node.lcls)
    if isinstance(node, ast.UnpackSequence):
        return tuple(node.targets)
    if isinstance(node, ast.NamedExpr):
        return (node.target,)
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return (node.target,)
    if isinstance(node, ast.Delete):
        return (node.lcl,)
    if isinstance(node, ast.InputBlock):
        return tuple(input_.lcl for input_ in node.inputs)
    if isinstance(node, ast.For):
        return (node.index,)
    if isinstance(node, ast.TypeSwitch):
        return tuple(
            case.expr for case in node.cases if getattr(case, "expr", None) is not None
        )
    return ()


def _local_occurrences(node, *, skipped: frozenset[object] = frozenset()):
    if node is None or isinstance(node, ast.leafTypes):
        return
    if isinstance(node, (tuple, list)):
        for child in node:
            yield from _local_occurrences(child, skipped=skipped)
        return
    if node in skipped:
        return
    if isinstance(node, ast.Local):
        yield node
        return
    if isinstance(node, ast.Code):
        return
    for child in _children(node):
        yield from _local_occurrences(child, skipped=skipped)


def _literal_name(node) -> object:
    if isinstance(node, ast.Existing):
        return getattr(node.object, "pyobj", repr(node.object))
    if isinstance(node, ast.Local):
        return node.name or "*"
    return "*"


def _storage_for_expr(
    catalog: IRCatalog, code_id, node
) -> tuple[StorageLocation, ...]:
    if isinstance(node, ast.Local) and catalog.has_symbol(node, code_id):
        return (LocalStorage(catalog.symbol_id(node, code_id)),)
    if isinstance(node, (ast.Cell, ast.GetCell, ast.GetCellDeref)):
        cell = node if isinstance(node, ast.Cell) else node.cell
        if catalog.has_symbol(cell, code_id):
            return (CellStorage(catalog.symbol_id(cell, code_id)),)
        return (UnknownStorage("cell"),)
    if isinstance(node, ast.GetGlobal):
        return (GlobalStorage("", str(_literal_name(node.name))),)
    if isinstance(node, (ast.GetAttr, ast.Load, ast.Check)):
        bases = _storage_for_expr(catalog, code_id, node.expr)
        return tuple(AttributeStorage(base, _literal_name(node.name)) for base in bases)
    if isinstance(node, ast.GetSubscript):
        bases = _storage_for_expr(catalog, code_id, node.expr)
        return tuple(
            SubscriptStorage(base, _literal_name(node.subscript)) for base in bases
        )
    return ()


def _explicit_storage(catalog: IRCatalog, code_id, node):
    reads: list[StorageLocation] = []
    writes: list[StorageLocation] = []
    if isinstance(node, ast.GetGlobal):
        reads.extend(_storage_for_expr(catalog, code_id, node))
    elif isinstance(node, (ast.SetGlobal, ast.DeleteGlobal)):
        writes.append(GlobalStorage("", str(_literal_name(node.name))))
    elif isinstance(node, (ast.GetCell, ast.GetCellDeref)):
        reads.extend(_storage_for_expr(catalog, code_id, node))
    elif isinstance(node, ast.SetCellDeref):
        writes.extend(_storage_for_expr(catalog, code_id, node.cell))
    elif isinstance(node, (ast.GetAttr, ast.Load, ast.Check, ast.GetSubscript)):
        reads.extend(_storage_for_expr(catalog, code_id, node))
    elif isinstance(node, (ast.SetAttr, ast.DeleteAttr, ast.Store)):
        for base in _storage_for_expr(catalog, code_id, node.expr):
            writes.append(AttributeStorage(base, _literal_name(node.name)))
    elif isinstance(node, (ast.SetSubscript, ast.DeleteSubscript)):
        for base in _storage_for_expr(catalog, code_id, node.expr):
            writes.append(
                SubscriptStorage(base, _literal_name(node.subscript))
            )
    return reads, writes


def _control_effects(node) -> ControlEffects:
    if isinstance(node, ast.Return):
        return ControlEffects(normal=False, returns=True)
    if isinstance(node, ast.Raise):
        return ControlEffects(normal=False, raises=True)
    if isinstance(node, ast.Break):
        return ControlEffects(normal=False, breaks=True)
    if isinstance(node, ast.Continue):
        return ControlEffects(normal=False, continues=True)
    if isinstance(node, (ast.Yield, ast.YieldFrom, ast.AsyncYield)):
        return ControlEffects(yields=True)
    if isinstance(node, ast.Assert):
        return ControlEffects(raises=True)
    if isinstance(node, _CALL_TYPES):
        return ControlEffects(raises=True, errors=True)
    if isinstance(
        node,
        (
            ast.GetAttr,
            ast.SetAttr,
            ast.DeleteAttr,
            ast.GetSubscript,
            ast.SetSubscript,
            ast.DeleteSubscript,
            ast.Load,
            ast.Store,
            ast.Check,
        ),
    ):
        return ControlEffects(errors=True)
    return ControlEffects()


def _call_arguments(call) -> tuple[object, ...]:
    result = []
    selfarg = getattr(call, "selfarg", None)
    if selfarg is not None:
        result.append(selfarg)
    receiver = getattr(call, "expr", None)
    if isinstance(call, ast.MethodCall) and receiver is not None:
        result.append(receiver)
    result.extend(getattr(call, "args", ()))
    for keyword in getattr(call, "kwds", ()):
        if isinstance(keyword, tuple) and len(keyword) == 2:
            result.append(keyword[1])
        else:
            result.append(keyword)
    vargs = getattr(call, "vargs", None)
    if vargs is not None:
        result.append(vargs)
    kargs = getattr(call, "kargs", None)
    if kargs is not None:
        result.append(kargs)
    return tuple(result)


def _symbolic_call_name(call) -> str | None:
    if isinstance(call, ast.DirectCall) and call.code is not None:
        return str(call.code.codeName())
    if isinstance(call, ast.Call):
        expr = call.expr
        if isinstance(expr, ast.Local):
            return str(expr.name) if expr.name is not None else None
        if isinstance(expr, ast.Existing):
            name = getattr(expr.object, "pythonName", lambda: None)()
            if isinstance(name, str):
                return name
            pyobj = getattr(expr.object, "pyobj", None)
            return pyobj if isinstance(pyobj, str) else None
    if isinstance(call, ast.MethodCall):
        name = call.name
        if isinstance(name, ast.Local):
            return str(name.name) if name.name is not None else None
        if isinstance(name, ast.Existing):
            pyobj = getattr(name.object, "pyobj", None)
            return pyobj if isinstance(pyobj, str) else None
    return None


def _register_call(catalog: IRCatalog, node, node_id):
    if not isinstance(node, _CALL_TYPES):
        return ()
    callee = getattr(node, "expr", None)
    callee_id = catalog.node_id(callee, node_id.code) if callee is not None else None
    argument_ids = tuple(
        catalog.node_id(arg, node_id.code) for arg in _call_arguments(node)
    )
    keyword_arguments = tuple(
        (str(keyword[0]), catalog.node_id(keyword[1], node_id.code))
        for keyword in getattr(node, "kwds", ())
        if isinstance(keyword, tuple) and len(keyword) == 2
    )
    direct_target = None
    if isinstance(node, ast.DirectCall) and node.code is not None:
        try:
            direct_target = catalog.procedure(node.code).code_id
        except KeyError:
            direct_target = None
    call_id = CallSiteId(node_id, 0)
    catalog.semantics.register_call(
        CallSite(
            call_id,
            node_id,
            callee_id,
            argument_ids,
            keyword_arguments,
            direct_target=direct_target,
            symbolic_name=_symbolic_call_name(node),
        )
    )
    return (call_id,)


def build_semantics(catalog: IRCatalog) -> None:
    """Populate structural semantics for every indexed Python IR node."""
    # Transformations may replace a parent container in place while creating
    # fresh child objects.  Close the catalog over the current child relation
    # before building records so semantics never contain dangling NodeIds.
    pending = list(catalog.nodes())
    cursor = 0
    while cursor < len(pending):
        parent_id, parent = pending[cursor]
        cursor += 1
        for child in _children(parent):
            if not isinstance(child, ast.PythonASTNode) or isinstance(child, ast.Code):
                continue
            if catalog.has_node(child, parent_id.code):
                continue
            child_id = catalog.register_node(
                parent_id.code,
                child,
                origin=catalog.source_map.origin(parent_id),
            )
            if isinstance(child, (ast.Local, ast.Cell)) and not catalog.has_symbol(
                child, parent_id.code
            ):
                procedure = catalog.procedure(parent_id.code)
                name = child.name or f"tmp{child_id.ordinal}"
                symbol = catalog.symbols.find(procedure.root_scope, name)
                if symbol is None:
                    kind = (
                        SymbolKind.CELL
                        if isinstance(child, ast.Cell)
                        else SymbolKind.TEMPORARY
                        if child.name is None
                        else SymbolKind.LOCAL
                    )
                    symbol = catalog.symbols.intern(
                        procedure.root_scope,
                        name,
                        kind,
                        declaration_origin=catalog.source_map.origin(parent_id),
                    )
                catalog.bind_symbol(child, symbol.id)
            pending.append((child_id, child))

    catalog.semantics.clear()
    for node_id, node in catalog.nodes():
        definition_symbols = tuple(
            catalog.symbol_id(reference, node_id.code)
            for reference in _definition_references(node)
            if catalog.has_symbol(reference, node_id.code)
        )
        definitions = tuple(
            catalog.value_id(reference, node_id.code)
            if catalog.has_value(reference, node_id.code)
            else catalog.symbol_id(reference, node_id.code)
            for reference in _definition_references(node)
            if catalog.has_symbol(reference, node_id.code)
        )
        skipped = frozenset(_definition_references(node))
        use_locals = tuple(
            local
            for local in _local_occurrences(node, skipped=skipped)
            if catalog.has_symbol(local, node_id.code)
        )
        use_symbols = _dedupe(
            catalog.symbol_id(local, node_id.code) for local in use_locals
        )
        uses = _dedupe(
            catalog.value_id(local, node_id.code)
            if catalog.has_value(local, node_id.code)
            else catalog.symbol_id(local, node_id.code)
            for local in use_locals
        )
        reads: list[StorageLocation] = [
            LocalStorage(symbol) for symbol in use_symbols
        ]
        writes: list[StorageLocation] = [
            LocalStorage(symbol) for symbol in definition_symbols
        ]
        explicit_reads, explicit_writes = _explicit_storage(
            catalog, node_id.code, node
        )
        reads.extend(explicit_reads)
        writes.extend(explicit_writes)
        allocations = (
            (AllocationSiteId(node_id, 0),) if isinstance(node, _ALLOCATION_TYPES) else ()
        )
        calls = _register_call(catalog, node, node_id)
        complete = not isinstance(node, _CALL_TYPES)
        diagnostics = (
            ("call heap effects require points-to refinement",)
            if not complete
            else ()
        )
        if not complete:
            reads.append(UnknownStorage("call-read"))
            writes.append(UnknownStorage("call-write"))
        catalog.semantics.set_operation(
            node_id,
            OperationSemantics(
                definitions=_dedupe(definitions),
                uses=uses,
                reads=_dedupe(reads),
                writes=_dedupe(writes),
                allocations=allocations,
                calls=calls,
                evaluation_order=tuple(
                    catalog.node_id(child, node_id.code)
                    for child in _children(node)
                    if isinstance(child, ast.PythonASTNode)
                    and not isinstance(child, ast.Code)
                ),
                control=_control_effects(node),
                complete=complete,
                diagnostics=diagnostics,
            ),
        )


def build_program_semantics(program) -> None:
    build_semantics(program.ir)
