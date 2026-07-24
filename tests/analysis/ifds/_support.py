from __future__ import annotations

from dataclasses import dataclass

from pyflow.ir.cfg import transform
from pyflow.language.asttools.annotation import annotationSet, makeContextualAnnotation
from pyflow.language.python import ast


def make_code(name: str, params, body_blocks, *, return_name: str = "ret0"):
    return_param = ast.Local(return_name)
    code = ast.Code(
        name,
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=list(params),
            paramnames=[param.name for param in params],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[return_param],
            type_params=None,
        ),
        ast.Suite(list(body_blocks)),
    )
    return code, return_param


def build_cfg(compiler, code):
    annotate_code_for_ifds(code)
    return transform.evaluate(compiler, code)


@dataclass(frozen=True, eq=False)
class FakeSlot:
    label: str

    def getForward(self):
        return self


def _ctx_annotation(*slots):
    return makeContextualAnnotation([annotationSet(slots)])


def annotate_code_for_ifds(code):
    local_slots: dict[str, FakeSlot] = {}
    global_slots: dict[str, FakeSlot] = {}
    cell_slots: dict[str, FakeSlot] = {}
    attr_slots: dict[tuple[FakeSlot, str], FakeSlot] = {}
    subscript_slots: dict[tuple[FakeSlot, str], FakeSlot] = {}

    def global_name(existing) -> str:
        pyobj = getattr(existing.object, "pyobj", None)
        if isinstance(pyobj, str):
            return pyobj
        return repr(pyobj)

    def attr_name(node) -> str:
        if isinstance(node, ast.Existing):
            return global_name(node)
        if isinstance(node, ast.Local) and node.name is not None:
            return node.name
        return "*"

    def subscript_name(node) -> str:
        if isinstance(node, ast.Existing):
            pyobj = getattr(node.object, "pyobj", None)
            return f"[{pyobj!r}]"
        return "[*]"

    def slot_for_local(local):
        return local_slots.setdefault(local.name, FakeSlot(local.name))

    def slot_for_global(existing):
        name = global_name(existing)
        return global_slots.setdefault(name, FakeSlot(name))

    def slot_for_cell(cell):
        return cell_slots.setdefault(cell.name, FakeSlot(cell.name))

    def slots_for_expr(expr):
        if expr is None or isinstance(expr, ast.leafTypes):
            return ()
        if isinstance(expr, ast.Local) and expr.name is not None:
            return (slot_for_local(expr),)
        if isinstance(expr, ast.GetGlobal):
            return (slot_for_global(expr.name),)
        if isinstance(expr, ast.GetCellDeref):
            return (slot_for_cell(expr.cell),)
        if isinstance(expr, (ast.GetAttr, ast.Load)):
            base_slots = slots_for_expr(expr.expr)
            name = attr_name(expr.name)
            return tuple(
                attr_slots.setdefault((base, name), FakeSlot(f"{base.label}.{name}"))
                for base in base_slots
            )
        if isinstance(expr, ast.GetSubscript):
            base_slots = slots_for_expr(expr.expr)
            key = subscript_name(expr.subscript)
            return tuple(
                subscript_slots.setdefault((base, key), FakeSlot(f"{base.label}{key}"))
                for base in base_slots
            )
        return ()

    def reads_for_node(node):
        if node is None or isinstance(node, ast.leafTypes):
            return ()
        if isinstance(
            node,
            (
                ast.Local,
                ast.GetGlobal,
                ast.GetCellDeref,
                ast.GetAttr,
                ast.Load,
                ast.GetSubscript,
            ),
        ):
            return slots_for_expr(node)
        if isinstance(node, ast.Assign):
            return reads_for_node(node.expr)
        if isinstance(node, ast.Return):
            slots = []
            for expr in node.exprs:
                slots.extend(reads_for_node(expr))
            return tuple(slots)
        if isinstance(
            node,
            (
                ast.SetAttr,
                ast.SetSubscript,
                ast.SetSlice,
                ast.SetGlobal,
                ast.SetCellDeref,
                ast.Store,
            ),
        ):
            return reads_for_node(node.value)
        if isinstance(node, ast.Delete):
            return reads_for_node(node.lcl)
        if isinstance(node, ast.DeleteGlobal):
            return (slot_for_global(node.name),)
        if isinstance(node, ast.DeleteAttr):
            return reads_for_node(node.expr)
        if isinstance(node, (ast.DeleteSubscript, ast.DeleteSlice)):
            return reads_for_node(node.expr)
        if isinstance(node, ast.Discard):
            return reads_for_node(node.expr)
        if isinstance(node, (ast.Call, ast.DirectCall, ast.MethodCall)):
            slots = []
            for arg in node.args:
                slots.extend(reads_for_node(arg))
            for _, value in node.kwds:
                slots.extend(reads_for_node(value))
            if isinstance(node, ast.MethodCall):
                slots.extend(reads_for_node(node.expr))
            return tuple(slots)
        if isinstance(node, ast.Suite):
            slots = []
            for block in node.blocks:
                slots.extend(reads_for_node(block))
            return tuple(slots)
        if isinstance(node, ast.TryExceptFinally):
            slots = list(reads_for_node(node.body))
            for handler in node.handlers:
                slots.extend(reads_for_node(handler))
            if node.defaultHandler is not None:
                slots.extend(reads_for_node(node.defaultHandler))
            if node.else_ is not None:
                slots.extend(reads_for_node(node.else_))
            if node.finally_ is not None:
                slots.extend(reads_for_node(node.finally_))
            return tuple(slots)
        if isinstance(node, ast.ExceptionHandler):
            slots = list(reads_for_node(node.preamble))
            slots.extend(reads_for_node(node.type))
            if node.value is not None:
                slots.extend(reads_for_node(node.value))
            slots.extend(reads_for_node(node.body))
            return tuple(slots)
        return ()

    def modifies_for_node(node):
        if isinstance(node, ast.Assign):
            return tuple(
                slot_for_local(local) for local in node.lcls if isinstance(local, ast.Local)
            )
        if isinstance(node, (ast.SetAttr, ast.Store)):
            base_slots = slots_for_expr(node.expr)
            name = attr_name(node.name)
            return tuple(
                attr_slots.setdefault((base, name), FakeSlot(f"{base.label}.{name}"))
                for base in base_slots
            )
        if isinstance(node, (ast.SetSubscript, ast.SetSlice)):
            base_slots = slots_for_expr(node.expr)
            key = (
                subscript_name(node.subscript)
                if isinstance(node, ast.SetSubscript)
                else "[slice]"
            )
            return tuple(
                subscript_slots.setdefault((base, key), FakeSlot(f"{base.label}{key}"))
                for base in base_slots
            )
        if isinstance(node, ast.SetGlobal):
            return (slot_for_global(node.name),)
        if isinstance(node, ast.DeleteGlobal):
            return (slot_for_global(node.name),)
        if isinstance(node, ast.SetCellDeref):
            return (slot_for_cell(node.cell),)
        if isinstance(node, ast.Delete):
            if isinstance(node.lcl, ast.Local) and node.lcl.name is not None:
                return (slot_for_local(node.lcl),)
            return ()
        if isinstance(node, ast.DeleteAttr):
            base_slots = slots_for_expr(node.expr)
            name = attr_name(node.name)
            return tuple(
                attr_slots.setdefault((base, name), FakeSlot(f"{base.label}.{name}"))
                for base in base_slots
            )
        if isinstance(node, ast.DeleteSubscript):
            base_slots = slots_for_expr(node.expr)
            key = subscript_name(node.subscript)
            return tuple(
                subscript_slots.setdefault((base, key), FakeSlot(f"{base.label}{key}"))
                for base in base_slots
            )
        if isinstance(node, ast.DeleteSlice):
            base_slots = slots_for_expr(node.expr)
            return tuple(
                subscript_slots.setdefault((base, "[slice]"), FakeSlot(f"{base.label}[slice]"))
                for base in base_slots
            )
        return ()

    def visit(node):
        if node is None or isinstance(node, ast.leafTypes):
            return
        annotation = getattr(node, "annotation", None)
        if annotation is not None and hasattr(annotation, "rewrite"):
            rewrite = {}
            if hasattr(annotation, "opReads"):
                rewrite["opReads"] = _ctx_annotation(*reads_for_node(node))
                rewrite["opModifies"] = _ctx_annotation(*modifies_for_node(node))
            if hasattr(annotation, "references"):
                refs = ()
                if isinstance(node, ast.Local) and node.name is not None:
                    refs = (slot_for_local(node),)
                elif isinstance(node, ast.Cell):
                    refs = (slot_for_cell(node),)
                elif isinstance(node, ast.Existing):
                    refs = (FakeSlot(global_name(node)),)
                rewrite["references"] = _ctx_annotation(*refs)
            node.rewriteAnnotation(**rewrite)
        if isinstance(node, (list, tuple)):
            for child in node:
                visit(child)
            return
        if isinstance(node, ast.Code):
            node.rewriteAnnotation(contexts=(object(),))
            params = getattr(node, "codeparameters", None)
            if params is not None:
                visit(getattr(params, "selfparam", None))
                visit(getattr(params, "posonlyparams", ()))
                visit(getattr(params, "params", ()))
                visit(getattr(params, "defaults", ()))
                visit(getattr(params, "vparam", None))
                visit(getattr(params, "kparam", None))
                visit(getattr(params, "returnparams", ()))
            visit(node.ast)
            return
        node.visitChildren(visit)

    def iter_nodes(node):
        if node is None or isinstance(node, ast.leafTypes):
            return
        yield node
        if isinstance(node, (list, tuple)):
            for child in node:
                yield from iter_nodes(child)
            return
        if isinstance(node, ast.Code):
            params = getattr(node, "codeparameters", None)
            if params is not None:
                yield from iter_nodes(getattr(params, "selfparam", None))
                yield from iter_nodes(getattr(params, "posonlyparams", ()))
                yield from iter_nodes(getattr(params, "params", ()))
                yield from iter_nodes(getattr(params, "defaults", ()))
                yield from iter_nodes(getattr(params, "vparam", None))
                yield from iter_nodes(getattr(params, "kparam", None))
                yield from iter_nodes(getattr(params, "returnparams", ()))
            yield from iter_nodes(node.ast)
            return
        children = []
        node.visitChildren(children.append)
        for child in children:
            yield from iter_nodes(child)

    visit(code)
    assert code.annotation.contexts is not None
    for node in iter_nodes(code):
        annotation = getattr(node, "annotation", None)
        if annotation is None:
            continue
        if hasattr(annotation, "opReads"):
            assert getattr(annotation, "opReads", None) is not None
            assert getattr(annotation, "opModifies", None) is not None
        if hasattr(annotation, "references"):
            assert getattr(annotation, "references", None) is not None


def call_stmt(callee_code, args, targets=()):
    direct = ast.DirectCall(callee_code, None, list(args), [], None, None)
    if targets:
        return ast.Assign(direct, list(targets))
    return ast.Discard(direct)
