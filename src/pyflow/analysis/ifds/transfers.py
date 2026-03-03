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


def formal_parameters(params) -> tuple[py_ast.Local, ...]:
    """Return local formal parameters from ``CodeParameters``."""
    formals: list[py_ast.Local] = []
    if isinstance(params.selfparam, py_ast.Local):
        formals.append(params.selfparam)
    formals.extend(param for param in params.posonlyparams if isinstance(param, py_ast.Local))
    formals.extend(param for param in params.params if isinstance(param, py_ast.Local))
    return tuple(formals)


def bind_call_arguments(call, params) -> tuple[tuple[object, py_ast.Local], ...]:
    """Bind call-site expressions to callee formals using Python-style argument rules."""
    bindings: list[tuple[object, py_ast.Local]] = []

    positional_formals: list[tuple[str | None, py_ast.Local]] = []
    keyword_formals: dict[str, py_ast.Local] = {}

    if isinstance(params.selfparam, py_ast.Local):
        positional_formals.append((params.selfparam.name, params.selfparam))
        if params.selfparam.name is not None:
            keyword_formals[params.selfparam.name] = params.selfparam

    for name, param in zip(params.posonlynames, params.posonlyparams):
        if isinstance(param, py_ast.Local):
            positional_formals.append((name, param))

    for name, param in zip(params.paramnames, params.params):
        if not isinstance(param, py_ast.Local):
            continue
        positional_formals.append((name, param))
        if name is not None:
            keyword_formals[name] = param

    next_formal_index = 0
    bound_formals: set[py_ast.Local] = set()

    def bind_next_positional(actual) -> bool:
        nonlocal next_formal_index
        while next_formal_index < len(positional_formals):
            _, formal = positional_formals[next_formal_index]
            next_formal_index += 1
            if formal in bound_formals:
                continue
            bindings.append((actual, formal))
            bound_formals.add(formal)
            return True
        return False

    receiver = getattr(call, "selfarg", None)
    if receiver is not None:
        if not bind_next_positional(receiver) and isinstance(params.vparam, py_ast.Local):
            bindings.append((receiver, params.vparam))

    for actual in getattr(call, "args", ()):
        if bind_next_positional(actual):
            continue
        if isinstance(params.vparam, py_ast.Local):
            bindings.append((actual, params.vparam))

    for keyword in getattr(call, "kwds", ()):
        if not isinstance(keyword, tuple) or len(keyword) != 2:
            continue
        name, actual = keyword
        formal = keyword_formals.get(name)
        if formal is not None and formal not in bound_formals:
            bindings.append((actual, formal))
            bound_formals.add(formal)
            continue
        if isinstance(params.kparam, py_ast.Local):
            bindings.append((actual, params.kparam))

    if isinstance(params.vparam, py_ast.Local):
        vargs = getattr(call, "vargs", None)
        if vargs is not None:
            bindings.append((vargs, params.vparam))

    if isinstance(params.kparam, py_ast.Local):
        kargs = getattr(call, "kargs", None)
        if kargs is not None:
            bindings.append((kargs, params.kparam))

    return tuple(bindings)


def actual_parameters(call, params=None) -> tuple[py_ast.Local, ...]:
    """Return local actual arguments for a call expression."""
    actuals: list[py_ast.Local] = []
    if params is None:
        actuals.extend(
            arg
            for arg in actual_argument_expressions(call)
            if isinstance(arg, py_ast.Local)
        )
        return tuple(actuals)

    for actual, _formal in bind_call_arguments(call, params):
        if isinstance(actual, py_ast.Local):
            actuals.append(actual)
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
