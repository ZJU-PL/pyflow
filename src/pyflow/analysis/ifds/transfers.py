"""Reusable transfer-function helpers for IFDS analyses."""

from __future__ import annotations

from typing import FrozenSet, Iterable

from pyflow.language.python import ast as py_ast


def collect_locals(node) -> FrozenSet[py_ast.Local]:
    """Collect all local references reachable from a PyFlow AST node."""
    found: set[py_ast.Local] = set()

    def visit(current) -> None:
        if current is None or isinstance(current, py_ast.leafTypes):
            return
        if isinstance(current, py_ast.Code):
            return
        if isinstance(current, py_ast.Local):
            found.add(current)
            return
        if isinstance(current, (list, tuple)):
            for child in current:
                visit(child)
            return
        current.visitChildren(visit)

    visit(node)
    return frozenset(found)


def identity_unless_killed(fact, killed: Iterable[object]):
    """Pass a fact through unless it is in the killed set."""
    killed_set = frozenset(killed)
    if fact in killed_set:
        return ()
    return (fact,)


def actual_parameters(call) -> tuple[py_ast.Local, ...]:
    """Return local actual arguments for a call expression."""
    actuals: list[py_ast.Local] = []
    if isinstance(getattr(call, "selfarg", None), py_ast.Local):
        actuals.append(call.selfarg)
    actuals.extend(arg for arg in getattr(call, "args", ()) if isinstance(arg, py_ast.Local))
    return tuple(actuals)


def formal_parameters(params) -> tuple[py_ast.Local, ...]:
    """Return local formal parameters from ``CodeParameters``."""
    formals: list[py_ast.Local] = []
    if isinstance(params.selfparam, py_ast.Local):
        formals.append(params.selfparam)
    formals.extend(param for param in params.posonlyparams if isinstance(param, py_ast.Local))
    formals.extend(param for param in params.params if isinstance(param, py_ast.Local))
    return tuple(formals)


def resolve_call_name(call, fallback_callee_names=()) -> str | None:
    """Resolve a best-effort symbolic name for a call expression."""
    if isinstance(call, py_ast.DirectCall) and call.code is not None:
        return call.code.codeName()
    if isinstance(call, py_ast.Call):
        expr = call.expr
        if isinstance(expr, py_ast.Local):
            return expr.name
        if isinstance(expr, py_ast.Existing):
            return getattr(expr.object, "pythonName", lambda: None)() or getattr(
                expr.object, "pyobj", None
            )
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
