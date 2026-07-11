"""Shared Python IR utility functions used across analysis modules.

These functions operate on :mod:`pyflow.language.python.ast` nodes and
have no dependencies on any specific analysis engine (IFDS, CPA, shape, etc.).
"""

from __future__ import annotations

from pyflow.language.python import ast as py_ast


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


def resolve_call_name(call, fallback_callee_names=()) -> str | None:
    """Resolve a best-effort symbolic name for a call expression."""
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
    fallback = tuple(fallback_callee_names)
    if len(fallback) == 1:
        return fallback[0]
    return None
