"""Must-constant local bindings at CFG program points.

Heap identities describe objects, so rebinding a name must not erase facts
about an object still reachable through another alias. Track constant local
bindings separately so reads cannot revive an old object's taint after a
scalar overwrite. Joins retain only bindings proven constant on every path.
"""

from collections import deque

from pyflow.language.python import ast as py_ast
from pyflow.language.python.ir_metadata import assigned_locals, actual_argument_expressions


def local_key(adapter, procedure, local):
    return adapter.catalog_by_procedure[procedure].symbol_id(local, procedure.code)


def constant_locals_before(adapter):
    incoming = {}
    pending = deque()
    for procedure in adapter.supergraph.procedures():
        entry = adapter.supergraph.entry_of(procedure)
        incoming[entry] = frozenset()
        pending.append(entry)
    while pending:
        node = pending.popleft()
        before = incoming[node]
        after = set(before)
        operation = adapter.operation_of(node)
        if node.kind == "call":
            call = adapter.call_expression_of(node)
            # Calls may mutate modeled receiver/argument ports. Do not let a
            # previous scalar binding mask those effects, including havoc.
            values = list(actual_argument_expressions(call))
            if isinstance(call, py_ast.Call) and isinstance(call.expr, py_ast.GetAttr):
                values.append(call.expr.expr)
            elif isinstance(call, py_ast.MethodCall):
                values.append(call.expr)
            for value in values:
                if isinstance(value, py_ast.Local):
                    after.discard(local_key(adapter, node.procedure, value))
        if node.kind == "op":
            if isinstance(operation, (py_ast.Assign, py_ast.AnnAssign, py_ast.UnpackSequence)):
                targets = {
                    local_key(adapter, node.procedure, local)
                    for local in assigned_locals(operation)
                }
                value = (
                    operation.value if isinstance(operation, py_ast.AnnAssign) else operation.expr
                )
                after.difference_update(targets)
                if not isinstance(operation, py_ast.UnpackSequence) and _constant(
                    value, before, adapter, node.procedure
                ):
                    after.update(targets)
            elif isinstance(operation, py_ast.Delete):
                after.discard(local_key(adapter, node.procedure, operation.lcl))
        successors = adapter.supergraph.normal_successors(
            node
        ) | adapter.supergraph.call_to_return_successors(node)
        for successor in successors:
            candidate = (
                before if adapter.is_exceptional_successor(node, successor) else frozenset(after)
            )
            previous = incoming.get(successor)
            joined = candidate if previous is None else previous & candidate
            if previous != joined:
                incoming[successor] = joined
                pending.append(successor)
    return incoming


def _constant(value, names, adapter, procedure):
    if isinstance(value, py_ast.Existing):
        return _scalar(getattr(value.object, "pyobj", object()))
    if isinstance(value, py_ast.Local):
        return local_key(adapter, procedure, value) in names
    if isinstance(value, (py_ast.BinaryOp, py_ast.UnaryPrefixOp)):
        operands = (
            (value.left, value.right) if isinstance(value, py_ast.BinaryOp) else (value.expr,)
        )
        return all(_constant(item, names, adapter, procedure) for item in operands)
    if isinstance(value, (py_ast.Call, py_ast.DirectCall)):
        name = adapter.call_name(value, procedure) or ""
        if name in {
            "interpreter__add__",
            "interpreter__iadd__",
            "interpreter__sub__",
            "interpreter__mul__",
            "interpreter__div__",
            "interpreter__truediv__",
            "interpreter__floordiv__",
            "interpreter__mod__",
            "interpreter__pow__",
            "interpreter__and__",
            "interpreter__or__",
            "interpreter__xor__",
            "interpreter__lshift__",
            "interpreter__rshift__",
            "interpreter__neg__",
            "interpreter__pos__",
            "interpreter__invert__",
        }:
            arguments = actual_argument_expressions(value)
            return bool(arguments) and all(
                _constant(item, names, adapter, procedure) for item in arguments
            )
    return False


def _scalar(value):
    if type(value) in {str, bytes, int, float, complex, bool, type(None)}:
        return True
    if type(value) in {tuple, frozenset}:
        return all(_scalar(item) for item in value)
    return False
