"""Shared Python IR utility functions used across analysis modules.

These functions operate on :mod:`pyflow.language.python.ast` nodes and
have no dependencies on any specific analysis engine (IFDS, CPA, shape, etc.).
"""

from __future__ import annotations

from pyflow.language.python import ast as py_ast


_CALL_ARGUMENT_ORDERS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CALL_POSITIONAL_SPREADS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CALL_KEYWORD_SPREADS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CALL_POSITIONAL_ITEMS: dict[
    int, tuple[object, tuple[tuple[bool, object], ...]]
] = {}
_CODE_DEFINITION_ANNOTATIONS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CODE_CLOSURE_CELLS: dict[int, tuple[object, tuple[object, ...]]] = {}
_CLASS_CELLS: dict[int, tuple[object, object | None]] = {}
_GIR_SOURCE_NODES: dict[int, tuple[object, object]] = {}


def register_call_argument_metadata(
    call: object,
    *,
    evaluation_order: tuple[object, ...],
    positional_spreads: tuple[object, ...] = (),
    keyword_spreads: tuple[object, ...] = (),
    positional_items: tuple[tuple[bool, object], ...] = (),
) -> None:
    """Record source-order call metadata without mutating slot-based IR nodes."""
    key = id(call)
    _CALL_ARGUMENT_ORDERS[key] = (call, evaluation_order)
    _CALL_POSITIONAL_SPREADS[key] = (call, positional_spreads)
    _CALL_KEYWORD_SPREADS[key] = (call, keyword_spreads)
    _CALL_POSITIONAL_ITEMS[key] = (call, positional_items)


def call_argument_evaluation_order(call: object) -> tuple[object, ...] | None:
    entry = _CALL_ARGUMENT_ORDERS.get(id(call))
    return entry[1] if entry is not None and entry[0] is call else None


def call_positional_spreads(call: object) -> tuple[object, ...]:
    entry = _CALL_POSITIONAL_SPREADS.get(id(call))
    return entry[1] if entry is not None and entry[0] is call else ()


def call_keyword_spreads(call: object) -> tuple[object, ...]:
    entry = _CALL_KEYWORD_SPREADS.get(id(call))
    return entry[1] if entry is not None and entry[0] is call else ()


def call_positional_items(call: object) -> tuple[tuple[bool, object], ...]:
    entry = _CALL_POSITIONAL_ITEMS.get(id(call))
    return entry[1] if entry is not None and entry[0] is call else ()


def copy_call_argument_metadata(source: object, target: object) -> None:
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
    key = id(code)
    _CODE_DEFINITION_ANNOTATIONS[key] = (code, annotations)
    _CODE_CLOSURE_CELLS[key] = (code, closure_cells)


def code_definition_annotations(code: object) -> tuple[object, ...]:
    entry = _CODE_DEFINITION_ANNOTATIONS.get(id(code))
    return entry[1] if entry is not None and entry[0] is code else ()


def code_closure_cells(code: object) -> tuple[object, ...]:
    entry = _CODE_CLOSURE_CELLS.get(id(code))
    return entry[1] if entry is not None and entry[0] is code else ()


def register_class_cell(class_node: object, cell: object | None) -> None:
    _CLASS_CELLS[id(class_node)] = (class_node, cell)


def class_cell(class_node: object) -> object | None:
    entry = _CLASS_CELLS.get(id(class_node))
    return entry[1] if entry is not None and entry[0] is class_node else None


def register_gir_source_node(ir_node: object, source_node: object) -> None:
    """Retain the source-syntax node needed for faithful GIR reconstruction."""
    _GIR_SOURCE_NODES[id(ir_node)] = (ir_node, source_node)


def gir_source_node(ir_node: object) -> object | None:
    entry = _GIR_SOURCE_NODES.get(id(ir_node))
    return entry[1] if entry is not None and entry[0] is ir_node else None


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
        return (
            (selfarg, *tuple(source_order))
            if selfarg is not None
            else tuple(source_order)
        )
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
