"""Shared Python IR utility functions used across analysis modules.

These functions operate on :mod:`pyflow.language.python.ast` nodes and
have no dependencies on any specific analysis engine (IFDS, CPA, shape, etc.).
"""

from __future__ import annotations

import weakref

from pyflow.language.python import ast as py_ast

# Identity-keyed weakref fallback tables.  AST nodes store call/code/class
# metadata directly on slots so no global references are held.  These dicts
# only back weak-referenced GIR source nodes (when retain_source_syntax=True)
# and non-AST mock objects in tests; entries are removed automatically on GC.
_CALL_ARGUMENT_ORDERS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CALL_POSITIONAL_SPREADS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CALL_KEYWORD_SPREADS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CALL_POSITIONAL_ITEMS: dict[int, tuple[object, tuple[tuple[bool, object], ...]]] = {}
_CODE_DEFINITION_ANNOTATIONS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CODE_CLOSURE_CELLS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CODE_CHILD_CODES: dict[int, tuple[object, tuple[object, ...] | None]] = {}
_CLASS_CELLS: dict[int, tuple[object, object | None]] = {}
_GIR_SOURCE_NODES: dict[int, tuple[object, object]] = {}


def _weak_store(table: dict[int, tuple[object, object]], obj: object, value: object) -> None:
    key = id(obj)
    try:
        ref: object = weakref.ref(obj, lambda _r, _k=key, _t=table: _t.pop(_k, None))
    except TypeError:
        table[key] = (obj, value)
        return
    table[key] = (ref, value)


def _weak_load(table: dict[int, tuple[object, object]], obj: object):
    entry = table.get(id(obj))
    if entry is None:
        return None
    owner, value = entry
    if isinstance(owner, weakref.ReferenceType):
        return value if owner() is obj else None
    return value if owner is obj else None


def register_call_argument_metadata(
    call: object,
    *,
    evaluation_order: tuple[object, ...],
    positional_spreads: tuple[object, ...] = (),
    keyword_spreads: tuple[object, ...] = (),
    positional_items: tuple[tuple[bool, object], ...] = (),
) -> None:
    """Record source-order call metadata without retaining global strong refs."""
    if isinstance(call, (py_ast.Call, py_ast.MethodCall, py_ast.DirectCall)):
        call._call_meta = (
            evaluation_order,
            positional_spreads,
            keyword_spreads,
            positional_items,
        )
        return
    _weak_store(_CALL_ARGUMENT_ORDERS, call, evaluation_order)
    _weak_store(_CALL_POSITIONAL_SPREADS, call, positional_spreads)
    _weak_store(_CALL_KEYWORD_SPREADS, call, keyword_spreads)
    _weak_store(_CALL_POSITIONAL_ITEMS, call, positional_items)


def call_argument_evaluation_order(call: object) -> tuple[object, ...] | None:
    meta = getattr(call, "_call_meta", None)
    if meta is not None:
        return meta[0]
    return _weak_load(_CALL_ARGUMENT_ORDERS, call)


def call_positional_spreads(call: object) -> tuple[object, ...]:
    meta = getattr(call, "_call_meta", None)
    if meta is not None:
        return meta[1]
    val = _weak_load(_CALL_POSITIONAL_SPREADS, call)
    return val if val is not None else ()


def call_keyword_spreads(call: object) -> tuple[object, ...]:
    meta = getattr(call, "_call_meta", None)
    if meta is not None:
        return meta[2]
    val = _weak_load(_CALL_KEYWORD_SPREADS, call)
    return val if val is not None else ()


def call_positional_items(call: object) -> tuple[tuple[bool, object], ...]:
    meta = getattr(call, "_call_meta", None)
    if meta is not None:
        return meta[3]
    val = _weak_load(_CALL_POSITIONAL_ITEMS, call)
    return val if val is not None else ()


def copy_call_argument_metadata(source: object, target: object) -> None:
    meta = getattr(source, "_call_meta", None)
    if meta is not None:
        if isinstance(target, (py_ast.Call, py_ast.MethodCall, py_ast.DirectCall)):
            target._call_meta = meta
            return
        register_call_argument_metadata(
            target,
            evaluation_order=meta[0],
            positional_spreads=meta[1],
            keyword_spreads=meta[2],
            positional_items=meta[3],
        )
        return
    order = call_argument_evaluation_order(source)
    if order is None:
        return
    register_call_argument_metadata(
        target,
        evaluation_order=order,
        positional_spreads=call_positional_spreads(source),
        keyword_spreads=call_keyword_spreads(source),
        positional_items=call_positional_items(source),
    )


def register_code_definition_metadata(
    code: object,
    *,
    annotations: tuple[object, ...] = (),
    closure_cells: tuple[object, ...] = (),
) -> None:
    if isinstance(code, py_ast.Code):
        existing = code._code_meta
        child_codes = existing[2] if existing is not None else None
        if annotations or closure_cells or child_codes is not None:
            code._code_meta = (annotations, closure_cells, child_codes)
        return
    _weak_store(_CODE_DEFINITION_ANNOTATIONS, code, annotations)
    _weak_store(_CODE_CLOSURE_CELLS, code, closure_cells)


def register_code_child_codes(
    code: object,
    child_codes: tuple[object, ...],
) -> None:
    """Record direct nested Code nodes created inside *code*."""
    if isinstance(code, py_ast.Code):
        existing = code._code_meta
        annotations = existing[0] if existing is not None else ()
        closure_cells = existing[1] if existing is not None else ()
        code._code_meta = (annotations, closure_cells, child_codes)
        return
    _weak_store(_CODE_CHILD_CODES, code, child_codes)


def code_child_codes(code: object) -> tuple[object, ...] | None:
    meta = getattr(code, "_code_meta", None)
    if meta is not None:
        return meta[2]
    return _weak_load(_CODE_CHILD_CODES, code)


def code_definition_annotations(code: object) -> tuple[object, ...]:
    meta = getattr(code, "_code_meta", None)
    if meta is not None:
        return meta[0]
    val = _weak_load(_CODE_DEFINITION_ANNOTATIONS, code)
    return val if val is not None else ()


def code_closure_cells(code: object) -> tuple[object, ...]:
    meta = getattr(code, "_code_meta", None)
    if meta is not None:
        return meta[1]
    val = _weak_load(_CODE_CLOSURE_CELLS, code)
    return val if val is not None else ()


def register_class_cell(class_node: object, cell: object | None) -> None:
    if isinstance(class_node, py_ast.ClassDef):
        class_node._class_cell = cell
        return
    _weak_store(_CLASS_CELLS, class_node, cell)


def class_cell(class_node: object) -> object | None:
    if isinstance(class_node, py_ast.ClassDef):
        return class_node._class_cell
    return _weak_load(_CLASS_CELLS, class_node)


def register_gir_source_node(ir_node: object, source_node: object) -> None:
    """Retain the source-syntax node needed for faithful GIR reconstruction."""
    _weak_store(_GIR_SOURCE_NODES, ir_node, source_node)


def gir_source_node(ir_node: object) -> object | None:
    return _weak_load(_GIR_SOURCE_NODES, ir_node)


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

    if isinstance(operation, py_ast.PythonASTNode):
        visit(operation)

    if walrus_targets:
        return tuple(dict.fromkeys((*direct, *walrus_targets)))
    return tuple(dict.fromkeys(direct))


def actual_argument_expressions(call) -> tuple[object, ...]:
    """Return positional, keyword, and unpacked argument expressions for a call."""
    source_order = call_argument_evaluation_order(call)
    if source_order is not None:
        selfarg = getattr(call, "selfarg", None)
        return (selfarg, *tuple(source_order)) if selfarg is not None else tuple(source_order)
    actuals: list[object] = []
    selfarg = getattr(call, "selfarg", None)
    if selfarg is not None:
        actuals.append(selfarg)
    actuals.extend(getattr(call, "args", ()))
    for keyword in getattr(call, "kwds", ()):
        if isinstance(keyword, tuple) and len(keyword) == 2:
            actuals.append(keyword[1])
        else:
            actuals.append(keyword)
    vargs = getattr(call, "vargs", None)
    if vargs is not None:
        actuals.append(vargs)
    kargs = getattr(call, "kargs", None)
    if kargs is not None:
        actuals.append(kargs)
    return tuple(actuals)


def resolve_call_name(call, *, code=None) -> str | None:
    """Return the indexed structural call name, or inspect standalone syntax.

    Analysis clients must pass ``code`` so missing semantics is visible rather
    than reconstructed privately.  The syntax-only form remains for frontend
    construction utilities and isolated AST tests.
    """
    if code is not None:
        owner = getattr(code, "code", code)
        catalog = owner.ir_catalog
        node_id = catalog.node_id(call, owner)
        sites = catalog.semantics.calls_for(node_id)
        if len(sites) != 1:
            return None
        return sites[0].symbolic_name
    if isinstance(call, py_ast.DirectCall) and call.code is not None:
        return call.code.codeName()
    if isinstance(call, py_ast.Call):
        expr = call.expr
        if isinstance(expr, py_ast.Local):
            return expr.name
        if isinstance(expr, py_ast.Existing):
            name = getattr(expr.object, "pythonName", lambda: None)()
            if isinstance(name, str):
                return name
            pyobj = getattr(expr.object, "pyobj", None)
            if isinstance(pyobj, str):
                return pyobj
            return None
    if isinstance(call, py_ast.MethodCall):
        name = call.name
        if isinstance(name, py_ast.Local):
            return name.name
        if isinstance(name, py_ast.Existing):
            pyobj = getattr(name.object, "pyobj", None)
            if isinstance(pyobj, str):
                return pyobj
    return None
