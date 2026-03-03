"""Fallback annotation completion for source-loaded IFDS analyses."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.language.asttools.annotation import annotationSet, makeContextualAnnotation
from pyflow.language.python import ast


@dataclass(frozen=True)
class _SyntheticSlot:
    label: str

    def getForward(self):
        return self


def ensure_ifds_annotations_complete(codes) -> None:
    """Populate minimal IFDS annotations when the full pipeline leaves gaps."""
    local_slots: dict[tuple[object, str], _SyntheticSlot] = {}
    global_slots: dict[str, _SyntheticSlot] = {}
    cell_slots: dict[str, _SyntheticSlot] = {}
    attr_slots: dict[tuple[str, str], _SyntheticSlot] = {}
    subscript_slots: dict[tuple[str, str], _SyntheticSlot] = {}

    def context_count(node) -> int:
        annotation = getattr(node, "annotation", None)
        contexts = getattr(annotation, "contexts", None)
        return max(len(contexts), 1) if contexts is not None else 1

    def contextual(*slots, count: int):
        return makeContextualAnnotation([annotationSet(slots) for _ in range(count)])

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

    def slot_for_local(code, local):
        return local_slots.setdefault((code, local.name), _SyntheticSlot(local.name))

    def slot_for_global(existing):
        name = global_name(existing)
        return global_slots.setdefault(name, _SyntheticSlot(name))

    def slot_for_cell(cell):
        return cell_slots.setdefault(cell.name, _SyntheticSlot(cell.name))

    def slots_for_expr(code, expr):
        if expr is None or isinstance(expr, ast.leafTypes):
            return ()
        if isinstance(expr, ast.Local) and expr.name is not None:
            return (slot_for_local(code, expr),)
        if isinstance(expr, ast.GetGlobal):
            return (slot_for_global(expr.name),)
        if isinstance(expr, ast.GetCellDeref):
            return (slot_for_cell(expr.cell),)
        if isinstance(expr, (ast.GetAttr, ast.Load)):
            base_slots = slots_for_expr(code, expr.expr)
            name = attr_name(expr.name)
            return tuple(
                attr_slots.setdefault((base.label, name), _SyntheticSlot(f"{base.label}.{name}"))
                for base in base_slots
            )
        if isinstance(expr, ast.GetSubscript):
            base_slots = slots_for_expr(code, expr.expr)
            key = subscript_name(expr.subscript)
            return tuple(
                subscript_slots.setdefault((base.label, key), _SyntheticSlot(f"{base.label}{key}"))
                for base in base_slots
            )
        return ()

    def reads_for_node(code, node):
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
            return slots_for_expr(code, node)
        if isinstance(node, ast.Assign):
            return reads_for_node(code, node.expr)
        if isinstance(node, ast.Return):
            slots = []
            for expr in node.exprs:
                slots.extend(reads_for_node(code, expr))
            return tuple(slots)
        if isinstance(node, (ast.SetAttr, ast.SetSubscript, ast.SetGlobal, ast.SetCellDeref, ast.Store)):
            return reads_for_node(code, node.value)
        if isinstance(node, ast.Discard):
            return reads_for_node(code, node.expr)
        if isinstance(node, (ast.Call, ast.DirectCall, ast.MethodCall)):
            slots = []
            for arg in node.args:
                slots.extend(reads_for_node(code, arg))
            for _, value in node.kwds:
                slots.extend(reads_for_node(code, value))
            if isinstance(node, ast.MethodCall):
                slots.extend(reads_for_node(code, node.expr))
            return tuple(slots)
        if isinstance(node, ast.Suite):
            slots = []
            for block in node.blocks:
                slots.extend(reads_for_node(code, block))
            return tuple(slots)
        if isinstance(node, ast.TryExceptFinally):
            slots = list(reads_for_node(code, node.body))
            for handler in node.handlers:
                slots.extend(reads_for_node(code, handler))
            if node.defaultHandler is not None:
                slots.extend(reads_for_node(code, node.defaultHandler))
            if node.else_ is not None:
                slots.extend(reads_for_node(code, node.else_))
            if node.finally_ is not None:
                slots.extend(reads_for_node(code, node.finally_))
            return tuple(slots)
        if isinstance(node, ast.ExceptionHandler):
            slots = list(reads_for_node(code, node.preamble))
            slots.extend(reads_for_node(code, node.type))
            if node.value is not None:
                slots.extend(reads_for_node(code, node.value))
            slots.extend(reads_for_node(code, node.body))
            return tuple(slots)
        return ()

    def modifies_for_node(code, node):
        if isinstance(node, ast.Assign):
            return tuple(
                slot_for_local(code, local)
                for local in node.lcls
                if isinstance(local, ast.Local) and local.name is not None
            )
        if isinstance(node, (ast.SetAttr, ast.Store)):
            base_slots = slots_for_expr(code, node.expr)
            name = attr_name(node.name)
            return tuple(
                attr_slots.setdefault((base.label, name), _SyntheticSlot(f"{base.label}.{name}"))
                for base in base_slots
            )
        if isinstance(node, ast.SetSubscript):
            base_slots = slots_for_expr(code, node.expr)
            key = subscript_name(node.subscript)
            return tuple(
                subscript_slots.setdefault((base.label, key), _SyntheticSlot(f"{base.label}{key}"))
                for base in base_slots
            )
        if isinstance(node, ast.SetGlobal):
            return (slot_for_global(node.name),)
        if isinstance(node, ast.SetCellDeref):
            return (slot_for_cell(node.cell),)
        return ()

    def visit(code, node) -> None:
        if node is None or isinstance(node, ast.leafTypes):
            return

        annotation = getattr(node, "annotation", None)
        if annotation is not None and hasattr(annotation, "rewrite"):
            rewrite = {}
            count = context_count(code if isinstance(node, ast.Code) else node)
            reads = reads_for_node(code, node)
            modifies = modifies_for_node(code, node)
            refs = ()
            if isinstance(node, ast.Local) and node.name is not None:
                refs = (slot_for_local(code, node),)
            elif isinstance(node, ast.Cell):
                refs = (slot_for_cell(node),)
            elif isinstance(node, ast.Existing):
                refs = (slot_for_global(node),)

            existing_reads = getattr(annotation, "opReads", None)
            if hasattr(annotation, "opReads") and (
                existing_reads is None
                or (reads and not getattr(existing_reads, "merged", ()))
            ):
                rewrite["opReads"] = contextual(*reads, count=count)

            existing_modifies = getattr(annotation, "opModifies", None)
            if hasattr(annotation, "opModifies") and (
                existing_modifies is None
                or (modifies and not getattr(existing_modifies, "merged", ()))
            ):
                rewrite["opModifies"] = contextual(*modifies, count=count)

            existing_refs = getattr(annotation, "references", None)
            if hasattr(annotation, "references") and (
                existing_refs is None
                or (refs and not getattr(existing_refs, "merged", ()))
            ):
                rewrite["references"] = contextual(*refs, count=count)
            if rewrite:
                node.rewriteAnnotation(**rewrite)

        if isinstance(node, (list, tuple)):
            for child in node:
                visit(code, child)
            return

        if isinstance(node, ast.Code):
            if getattr(node.annotation, "contexts", None) is None:
                node.rewriteAnnotation(contexts=(object(),))
            params = getattr(node, "codeparameters", None)
            if params is not None:
                visit(node, getattr(params, "selfparam", None))
                visit(node, getattr(params, "posonlyparams", ()))
                visit(node, getattr(params, "params", ()))
                visit(node, getattr(params, "defaults", ()))
                visit(node, getattr(params, "vparam", None))
                visit(node, getattr(params, "kparam", None))
                visit(node, getattr(params, "returnparams", ()))
            visit(node, node.ast)
            return

        node.visitChildren(lambda child: visit(code, child))

    for code in codes:
        visit(code, code)
