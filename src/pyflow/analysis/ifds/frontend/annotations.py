"""Syntactic annotation synthesis for best-effort IFDS preparation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from pyflow.language.asttools.annotation import annotationSet, makeContextualAnnotation
from pyflow.language.python import ast


@dataclass(frozen=True, eq=False)
class SyntheticSlot:
    """Stable synthetic storage identity used when precise annotations are absent."""

    label: str
    fallback_generated: bool = True

    def getForward(self):
        return self


@dataclass(frozen=True, eq=False)
class SyntheticAllocation:
    """Fallback allocation identity for syntactically fresh objects."""

    label: str
    site: int
    fallback_generated: bool = True

    def getForward(self):
        return self


class IFDSAnnotationSynthesizer:
    """Populate conservative read/write/reference annotations for PyFlow ASTs.

    This is intentionally syntactic.  It completes the IFDS annotation contract
    when earlier semantic analyses leave holes, but it does not try to replace
    IPA/CPA precision.
    """

    def __init__(self) -> None:
        self.local_slots: dict[tuple[object, str], SyntheticSlot] = {}
        self.global_slots: dict[str, SyntheticSlot] = {}
        self.cell_slots: dict[int, SyntheticSlot] = {}
        self.attr_slots: dict[tuple[SyntheticSlot, str], SyntheticSlot] = {}
        self.subscript_slots: dict[tuple[SyntheticSlot, str], SyntheticSlot] = {}
        self.allocations: dict[tuple[str, int], SyntheticAllocation] = {}

    def complete(self, codes: Iterable[object]) -> None:
        for code in codes:
            self._visit(code, code)

    def _context_count(self, node: object) -> int:
        annotation = getattr(node, "annotation", None)
        contexts = getattr(annotation, "contexts", None)
        return max(len(contexts), 1) if contexts is not None else 1

    def _contextual(self, *slots: object, count: int):
        return makeContextualAnnotation([annotationSet(slots) for _ in range(count)])

    @staticmethod
    def _dedupe(slots: Iterable[object]) -> tuple[object, ...]:
        result: list[object] = []
        seen: set[int] = set()
        for slot in slots:
            key = id(slot)
            if key in seen:
                continue
            seen.add(key)
            result.append(slot)
        return tuple(result)

    def _global_name(self, existing: object) -> str:
        pyobj = getattr(getattr(existing, "object", None), "pyobj", None)
        if isinstance(pyobj, str):
            return pyobj
        return repr(pyobj)

    def _attr_name(self, node: object) -> str:
        if isinstance(node, ast.Existing):
            return self._global_name(node)
        if isinstance(node, ast.Local) and node.name is not None:
            return node.name
        return "*"

    def _subscript_name(self, node: object) -> str:
        if isinstance(node, ast.Existing):
            pyobj = getattr(node.object, "pyobj", None)
            return f"[{pyobj!r}]"
        return "[*]"

    def _slot_for_local_name(self, code: object, name: str) -> SyntheticSlot:
        return self.local_slots.setdefault((code, name), SyntheticSlot(name))

    def _slot_for_local(self, code: object, local: object) -> SyntheticSlot:
        return self._slot_for_local_name(code, local.name)

    def _slot_for_global(self, existing: object) -> SyntheticSlot:
        name = self._global_name(existing)
        return self.global_slots.setdefault(name, SyntheticSlot(name))

    def _slot_for_cell(self, cell: object) -> SyntheticSlot:
        key = id(cell)
        label = getattr(cell, "name", None)
        if not isinstance(label, str) or not label:
            label = "<cell>"
        return self.cell_slots.setdefault(key, SyntheticSlot(f"{label}@{key:x}"))

    def _slot_for_attr(self, base: SyntheticSlot, name: str) -> SyntheticSlot:
        return self.attr_slots.setdefault(
            (base, name), SyntheticSlot(f"{base.label}.{name}")
        )

    def _slot_for_subscript(self, base: SyntheticSlot, key: str) -> SyntheticSlot:
        return self.subscript_slots.setdefault(
            (base, key), SyntheticSlot(f"{base.label}{key}")
        )

    def _allocation_for_expr(self, expr: object) -> SyntheticAllocation:
        label = self._allocation_label(expr)
        return self.allocations.setdefault(
            (label, id(expr)), SyntheticAllocation(label, id(expr))
        )

    def slots_for_expr(self, code: object, expr: object) -> tuple[object, ...]:
        """Return storage slots represented by an expression, not all operands read."""
        if expr is None or isinstance(expr, ast.leafTypes):
            return ()
        if isinstance(expr, ast.Local) and expr.name is not None:
            return (self._slot_for_local(code, expr),)
        if isinstance(expr, ast.GetGlobal):
            return (self._slot_for_global(expr.name),)
        if isinstance(expr, (ast.Cell, ast.GetCell, ast.GetCellDeref)):
            cell = expr if isinstance(expr, ast.Cell) else expr.cell
            return (self._slot_for_cell(cell),)
        if isinstance(expr, (ast.GetAttr, ast.Load, ast.Check)):
            base_slots = self.slots_for_expr(code, expr.expr)
            name = self._attr_name(expr.name)
            return tuple(
                self._slot_for_attr(base, name)
                for base in base_slots
                if isinstance(base, SyntheticSlot)
            )
        if isinstance(expr, ast.GetSubscript):
            base_slots = self.slots_for_expr(code, expr.expr)
            key = self._subscript_name(expr.subscript)
            return tuple(
                self._slot_for_subscript(base, key)
                for base in base_slots
                if isinstance(base, SyntheticSlot)
            )
        if isinstance(expr, ast.GetSlice):
            base_slots = self.slots_for_expr(code, expr.expr)
            return tuple(
                self._slot_for_subscript(base, "[slice]")
                for base in base_slots
                if isinstance(base, SyntheticSlot)
            )
        return ()

    def reads_for_node(self, code: object, node: object) -> tuple[object, ...]:
        if node is None or isinstance(node, ast.leafTypes):
            return ()
        if isinstance(node, (list, tuple)):
            return self._dedupe(
                slot
                for child in node
                for slot in self.reads_for_node(code, child)
            )
        if not hasattr(node, "visitChildren"):
            return ()

        if isinstance(
            node,
            (
                ast.Local,
                ast.Cell,
                ast.GetGlobal,
                ast.GetCell,
                ast.GetCellDeref,
                ast.GetAttr,
                ast.Load,
                ast.Check,
                ast.GetSubscript,
                ast.GetSlice,
            ),
        ):
            return self.slots_for_expr(code, node)

        if isinstance(node, ast.NamedExpr):
            return self.reads_for_node(code, node.value)
        if isinstance(node, ast.AnnAssign):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.annotation),
                    *self.reads_for_node(code, node.value),
                )
            )
        if isinstance(node, ast.TypeAlias):
            return self._dedupe(
                (
                    *self.reads_for_node(code, getattr(node, "params", ())),
                    *self.reads_for_node(code, node.value),
                )
            )
        if isinstance(node, ast.TypeParam):
            return self.reads_for_node(code, node.bound)
        if isinstance(node, ast.TypeParams):
            return self.reads_for_node(code, node.params)
        if isinstance(node, ast.UnpackSequence):
            return self.reads_for_node(code, node.expr)
        if isinstance(node, ast.Assign):
            return self._dedupe(
                (
                    *self._target_reads(code, node.lcls),
                    *self.reads_for_node(code, node.expr),
                )
            )
        if isinstance(node, ast.Phi):
            return self.reads_for_node(code, node.arguments)
        if isinstance(node, ast.Return):
            return self.reads_for_node(code, node.exprs)
        if isinstance(node, ast.Raise):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.exception),
                    *self.reads_for_node(code, node.parameter),
                    *self.reads_for_node(code, node.traceback),
                )
            )
        if isinstance(node, ast.Assert):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.test),
                    *self.reads_for_node(code, node.message),
                )
            )
        if isinstance(node, ast.Print):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.target),
                    *self.reads_for_node(code, node.expr),
                )
            )
        if isinstance(node, (ast.Delete, ast.DeleteGlobal)):
            return ()
        if isinstance(node, ast.DeleteAttr):
            return self.reads_for_node(code, node.expr)
        if isinstance(node, ast.DeleteSubscript):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.expr),
                    *self.reads_for_node(code, node.subscript),
                )
            )
        if isinstance(node, ast.DeleteSlice):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.expr),
                    *self.reads_for_node(code, node.start),
                    *self.reads_for_node(code, node.stop),
                    *self.reads_for_node(code, node.step),
                )
            )
        if isinstance(node, (ast.SetAttr, ast.Store)):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.expr),
                    *self.reads_for_node(code, node.name),
                    *self.reads_for_node(code, node.value),
                )
            )
        if isinstance(node, ast.SetSubscript):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.expr),
                    *self.reads_for_node(code, node.subscript),
                    *self.reads_for_node(code, node.value),
                )
            )
        if isinstance(node, ast.SetSlice):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.expr),
                    *self.reads_for_node(code, node.start),
                    *self.reads_for_node(code, node.stop),
                    *self.reads_for_node(code, node.step),
                    *self.reads_for_node(code, node.value),
                )
            )
        if isinstance(node, (ast.SetGlobal, ast.SetCellDeref)):
            return self.reads_for_node(code, node.value)
        if isinstance(node, ast.Discard):
            return self.reads_for_node(code, node.expr)
        if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await, ast.AsyncYield)):
            return self.reads_for_node(code, node.expr)
        if isinstance(
            node, (ast.GetIter, ast.AsyncGetIter, ast.ConvertToBool, ast.Not)
        ):
            return self.reads_for_node(code, node.expr)
        if isinstance(node, ast.UnaryPrefixOp):
            return self.reads_for_node(code, node.expr)
        if isinstance(node, (ast.BinaryOp, ast.Is)):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.left),
                    *self.reads_for_node(code, node.right),
                )
            )
        if isinstance(node, (ast.BuildTuple, ast.BuildList, ast.BuildSet)):
            return self.reads_for_node(code, node.args)
        if isinstance(node, ast.BuildMap):
            return self.reads_for_node(code, node.args)
        if isinstance(node, ast.BuildSlice):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.start),
                    *self.reads_for_node(code, node.stop),
                    *self.reads_for_node(code, node.step),
                )
            )
        if isinstance(node, (ast.ShortCircutAnd, ast.ShortCircutOr)):
            return self.reads_for_node(code, node.terms)
        if isinstance(node, ast.MakeFunction):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.defaults),
                    *self.reads_for_node(code, node.cells),
                )
            )
        if isinstance(node, (ast.Call, ast.DirectCall, ast.MethodCall)):
            return self._call_reads(code, node)
        if isinstance(node, ast.Suite):
            return self.reads_for_node(code, node.blocks)
        if isinstance(node, ast.TryExceptFinally):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.body),
                    *self.reads_for_node(code, node.handlers),
                    *self.reads_for_node(code, node.defaultHandler),
                    *self.reads_for_node(code, node.else_),
                    *self.reads_for_node(code, node.finally_),
                )
            )
        if isinstance(node, ast.ExceptionHandler):
            value_reads = (
                ()
                if isinstance(node.value, ast.Local)
                else self.reads_for_node(code, node.value)
            )
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.preamble),
                    *self.reads_for_node(code, node.type),
                    *value_reads,
                    *self.reads_for_node(code, node.body),
                )
            )
        if isinstance(node, ast.Condition):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.preamble),
                    *self.reads_for_node(code, node.conditional),
                )
            )
        if isinstance(node, ast.Switch):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.condition),
                    *self.reads_for_node(code, node.t),
                    *self.reads_for_node(code, node.f),
                )
            )
        if isinstance(node, ast.While):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.condition),
                    *self.reads_for_node(code, node.body),
                    *self.reads_for_node(code, node.else_),
                )
            )
        if isinstance(node, ast.For):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.iterator),
                    *self.reads_for_node(code, node.loopPreamble),
                    *self.reads_for_node(code, node.bodyPreamble),
                    *self.reads_for_node(code, node.body),
                    *self.reads_for_node(code, node.else_),
                )
            )
        if isinstance(node, ast.TypeSwitch):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.conditional),
                    *self.reads_for_node(code, node.cases),
                )
            )
        if isinstance(node, ast.TypeSwitchCase):
            return self.reads_for_node(code, node.body)
        if isinstance(node, ast.FunctionDef):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.decorators),
                    *self.reads_for_node(code, node.type_params),
                )
            )
        if isinstance(node, ast.ClassDef):
            return self._dedupe(
                (
                    *self.reads_for_node(code, node.bases),
                    *self.reads_for_node(code, getattr(node, "keywords", ())),
                    *self.reads_for_node(code, node.decorators),
                    *self.reads_for_node(code, node.type_params),
                    *self.reads_for_node(code, node.body),
                )
            )
        if isinstance(node, ast.OutputBlock):
            return self.reads_for_node(
                code, tuple(getattr(output, "expr", None) for output in node.outputs)
            )
        if isinstance(node, ast.Output):
            return self.reads_for_node(code, node.expr)
        if isinstance(node, (ast.InputBlock, ast.Input, ast.Import)):
            return ()
        if isinstance(node, ast.Allocate):
            return self.reads_for_node(code, node.expr)

        slots: list[object] = []
        node.visitChildren(lambda child: slots.extend(self.reads_for_node(code, child)))
        return self._dedupe(slots)

    def _call_reads(self, code: object, node: object) -> tuple[object, ...]:
        slots: list[object] = []
        if isinstance(node, ast.Call):
            slots.extend(self.reads_for_node(code, node.expr))
        if isinstance(node, ast.MethodCall):
            slots.extend(self.reads_for_node(code, node.expr))
            slots.extend(self.reads_for_node(code, node.name))
        selfarg = getattr(node, "selfarg", None)
        if selfarg is not None:
            slots.extend(self.reads_for_node(code, selfarg))
        slots.extend(self.reads_for_node(code, getattr(node, "args", ())))
        for keyword in getattr(node, "kwds", ()):
            if isinstance(keyword, tuple) and len(keyword) == 2:
                slots.extend(self.reads_for_node(code, keyword[1]))
        slots.extend(self.reads_for_node(code, getattr(node, "vargs", None)))
        slots.extend(self.reads_for_node(code, getattr(node, "kargs", None)))
        return self._dedupe(slots)

    def modifies_for_node(self, code: object, node: object) -> tuple[object, ...]:
        if node is None or isinstance(node, ast.leafTypes):
            return ()
        if isinstance(node, (list, tuple)):
            return self._dedupe(
                slot
                for child in node
                for slot in self.modifies_for_node(code, child)
            )
        if not hasattr(node, "visitChildren"):
            return ()

        if isinstance(node, ast.Assign):
            return self._dedupe(
                (
                    *self._slots_for_targets(code, node.lcls),
                    *self._collection_literal_write_slots_for_targets(
                        code, node.lcls, node.expr
                    ),
                    *self.modifies_for_node(code, node.expr),
                )
            )
        if isinstance(node, ast.UnpackSequence):
            return self._dedupe(
                (
                    *self._slots_for_targets(code, node.targets),
                    *self.modifies_for_node(code, node.expr),
                )
            )
        if isinstance(node, ast.AnnAssign):
            return self._dedupe(
                (
                    *self._slots_for_targets(code, (node.target,)),
                    *self.modifies_for_node(code, node.value),
                )
            )
        if isinstance(node, ast.NamedExpr):
            return self._dedupe(
                (
                    *self._slots_for_targets(code, (node.target,)),
                    *self.modifies_for_node(code, node.value),
                )
            )
        if isinstance(node, ast.Phi):
            return self._slots_for_targets(code, (node.target,))
        if isinstance(node, ast.For):
            return self._dedupe(
                (
                    *self._slots_for_targets(code, (node.index,)),
                    *self.modifies_for_node(code, node.loopPreamble),
                    *self.modifies_for_node(code, node.bodyPreamble),
                    *self.modifies_for_node(code, node.body),
                    *self.modifies_for_node(code, node.else_),
                )
            )
        if isinstance(node, ast.Delete):
            return self._slots_for_targets(code, (node.lcl,))
        if isinstance(node, (ast.SetAttr, ast.Store)):
            return self._field_write_slots(code, node.expr, node.name)
        if isinstance(node, ast.SetSubscript):
            return self._subscript_write_slots(code, node.expr, node.subscript)
        if isinstance(node, ast.SetSlice):
            return self._slice_write_slots(code, node.expr)
        if isinstance(node, ast.SetGlobal):
            return (self._slot_for_global(node.name),)
        if isinstance(node, ast.DeleteGlobal):
            return (self._slot_for_global(node.name),)
        if isinstance(node, ast.SetCellDeref):
            return (self._slot_for_cell(node.cell),)
        if isinstance(node, ast.DeleteAttr):
            return self._field_write_slots(code, node.expr, node.name)
        if isinstance(node, ast.DeleteSubscript):
            return self._subscript_write_slots(code, node.expr, node.subscript)
        if isinstance(node, ast.DeleteSlice):
            return self._slice_write_slots(code, node.expr)
        if isinstance(node, ast.InputBlock):
            return self._dedupe(
                self._slot_for_local(code, input_.lcl)
                for input_ in getattr(node, "inputs", ())
                if isinstance(getattr(input_, "lcl", None), ast.Local)
                and input_.lcl.name is not None
            )
        if isinstance(node, ast.ExceptionHandler):
            value_slots = (
                self._slots_for_targets(code, (node.value,))
                if isinstance(node.value, ast.Local)
                else ()
            )
            return self._dedupe(
                (
                    *self.modifies_for_node(code, node.preamble),
                    *value_slots,
                    *self.modifies_for_node(code, node.body),
                )
            )
        if isinstance(node, ast.TypeAlias):
            return (self._slot_for_local_name(code, node.name),)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            return (self._slot_for_local_name(code, node.name),)

        slots: list[object] = []
        node.visitChildren(
            lambda child: slots.extend(self.modifies_for_node(code, child))
        )
        return self._dedupe(slots)

    def _slots_for_targets(
        self, code: object, targets: Iterable[object]
    ) -> tuple[object, ...]:
        slots: list[object] = []
        for target in targets:
            if isinstance(target, ast.Local) and target.name is not None:
                slots.append(self._slot_for_local(code, target))
            elif isinstance(target, ast.GetGlobal):
                slots.append(self._slot_for_global(target.name))
            elif isinstance(target, ast.GetCellDeref):
                slots.append(self._slot_for_cell(target.cell))
            elif isinstance(target, (ast.GetAttr, ast.Load, ast.Check)):
                slots.extend(self._field_write_slots(code, target.expr, target.name))
            elif isinstance(target, ast.GetSubscript):
                slots.extend(
                    self._subscript_write_slots(code, target.expr, target.subscript)
                )
            elif isinstance(target, ast.GetSlice):
                slots.extend(self._slice_write_slots(code, target.expr))
            elif isinstance(target, (list, tuple)):
                slots.extend(self._slots_for_targets(code, target))
        return self._dedupe(slots)

    def _target_reads(
        self, code: object, targets: Iterable[object]
    ) -> tuple[object, ...]:
        slots: list[object] = []
        for target in targets:
            if isinstance(target, (ast.GetAttr, ast.Load, ast.Check)):
                slots.extend(self.reads_for_node(code, target.expr))
                slots.extend(self.reads_for_node(code, target.name))
            elif isinstance(target, ast.GetSubscript):
                slots.extend(self.reads_for_node(code, target.expr))
                slots.extend(self.reads_for_node(code, target.subscript))
            elif isinstance(target, ast.GetSlice):
                slots.extend(self.reads_for_node(code, target.expr))
                slots.extend(self.reads_for_node(code, target.start))
                slots.extend(self.reads_for_node(code, target.stop))
                slots.extend(self.reads_for_node(code, target.step))
            elif isinstance(target, (list, tuple)):
                slots.extend(self._target_reads(code, target))
        return self._dedupe(slots)

    def _collection_literal_write_slots_for_targets(
        self,
        code: object,
        targets: Iterable[object],
        expr: object,
    ) -> tuple[object, ...]:
        if not isinstance(
            expr, (ast.BuildTuple, ast.BuildList, ast.BuildSet, ast.BuildMap)
        ):
            return ()
        slots: list[object] = []
        for target_slot in self._slots_for_targets(code, targets):
            if not isinstance(target_slot, SyntheticSlot):
                continue
            for key in self._collection_literal_keys(expr):
                slots.append(self._slot_for_subscript(target_slot, key))
        return self._dedupe(slots)

    def _collection_literal_keys(self, expr: object) -> tuple[str, ...]:
        if isinstance(expr, (ast.BuildTuple, ast.BuildList)):
            return tuple(f"[{index}]" for index, _value in enumerate(expr.args))
        if isinstance(expr, ast.BuildSet):
            return ("[*]",) if expr.args else ()
        if isinstance(expr, ast.BuildMap):
            keys: list[str] = []
            args = tuple(expr.args)
            for index in range(0, len(args), 2):
                if index + 1 >= len(args):
                    keys.append("[*]")
                    continue
                keys.append(self._subscript_name(args[index]))
            return tuple(keys)
        return ()

    def _field_write_slots(
        self, code: object, base_expr: object, name_expr: object
    ) -> tuple[object, ...]:
        name = self._attr_name(name_expr)
        return tuple(
            self._slot_for_attr(base, name)
            for base in self.slots_for_expr(code, base_expr)
            if isinstance(base, SyntheticSlot)
        )

    def _subscript_write_slots(
        self, code: object, base_expr: object, key_expr: object
    ) -> tuple[object, ...]:
        key = self._subscript_name(key_expr)
        return tuple(
            self._slot_for_subscript(base, key)
            for base in self.slots_for_expr(code, base_expr)
            if isinstance(base, SyntheticSlot)
        )

    def _slice_write_slots(self, code: object, base_expr: object) -> tuple[object, ...]:
        return tuple(
            self._slot_for_subscript(base, "[slice]")
            for base in self.slots_for_expr(code, base_expr)
            if isinstance(base, SyntheticSlot)
        )

    def refs_for_node(self, code: object, node: object) -> tuple[object, ...]:
        if isinstance(node, ast.Local) and node.name is not None:
            return (self._slot_for_local(code, node),)
        if isinstance(node, ast.Cell):
            return (self._slot_for_cell(node),)
        if isinstance(node, ast.Existing):
            return (self._slot_for_global(node),)
        return ()

    def allocates_for_node(self, node: object) -> tuple[object, ...]:
        if node is None or isinstance(node, ast.leafTypes):
            return ()
        if isinstance(node, (list, tuple)):
            return self._dedupe(
                allocation
                for child in node
                for allocation in self.allocates_for_node(child)
            )
        if not hasattr(node, "visitChildren"):
            return ()

        direct = (
            (self._allocation_for_expr(node),)
            if self._is_allocation_expr(node)
            else ()
        )
        nested: list[object] = []
        node.visitChildren(lambda child: nested.extend(self.allocates_for_node(child)))
        return self._dedupe((*direct, *nested))

    def _is_allocation_expr(self, node: object) -> bool:
        return isinstance(
            node,
            (
                ast.Import,
                ast.BuildTuple,
                ast.BuildList,
                ast.BuildMap,
                ast.BuildSet,
                ast.BuildSlice,
                ast.MakeFunction,
                ast.FunctionDef,
                ast.ClassDef,
                ast.Allocate,
            ),
        )

    def _allocation_label(self, node: object) -> str:
        if isinstance(node, ast.Import):
            return f"module {node.name}"
        if isinstance(node, ast.BuildTuple):
            return "tuple literal"
        if isinstance(node, ast.BuildList):
            return "list literal"
        if isinstance(node, ast.BuildMap):
            return "dict literal"
        if isinstance(node, ast.BuildSet):
            return "set literal"
        if isinstance(node, ast.BuildSlice):
            return "slice literal"
        if isinstance(node, ast.MakeFunction):
            return "function"
        if isinstance(node, ast.FunctionDef):
            return f"function {node.name}"
        if isinstance(node, ast.ClassDef):
            return f"class {node.name}"
        if isinstance(node, ast.Allocate):
            return "allocate"
        return type(node).__name__

    def _visit(self, code: object, node: object) -> None:
        if node is None or isinstance(node, ast.leafTypes):
            return
        if isinstance(node, (list, tuple)):
            for child in node:
                self._visit(code, child)
            return
        if not hasattr(node, "visitChildren"):
            return

        self._rewrite_node_annotations(code, node)

        if isinstance(node, ast.Code):
            if getattr(node.annotation, "contexts", None) is None:
                node.rewriteAnnotation(contexts=(object(),))
            params = getattr(node, "codeparameters", None)
            if params is not None:
                self._visit(node, getattr(params, "selfparam", None))
                self._visit(node, getattr(params, "posonlyparams", ()))
                self._visit(node, getattr(params, "params", ()))
                self._visit(node, getattr(params, "defaults", ()))
                self._visit(node, getattr(params, "vparam", None))
                self._visit(node, getattr(params, "kparam", None))
                self._visit(node, getattr(params, "returnparams", ()))
                self._visit(node, getattr(params, "type_params", None))
            self._visit(node, node.ast)
            return

        node.visitChildren(lambda child: self._visit(code, child))

    def _rewrite_node_annotations(self, code: object, node: object) -> None:
        annotation = getattr(node, "annotation", None)
        if annotation is None or not hasattr(annotation, "rewrite"):
            return

        rewrite: dict[str, object] = {}
        count = self._context_count(code)
        reads = self.reads_for_node(code, node)
        modifies = self.modifies_for_node(code, node)
        allocates = self.allocates_for_node(node)
        refs = self.refs_for_node(code, node)

        existing_reads = getattr(annotation, "opReads", None)
        if hasattr(annotation, "opReads") and (
            existing_reads is None
            or (reads and not getattr(existing_reads, "merged", ()))
        ):
            rewrite["opReads"] = self._contextual(*reads, count=count)

        existing_modifies = getattr(annotation, "opModifies", None)
        if hasattr(annotation, "opModifies") and (
            existing_modifies is None
            or (modifies and not getattr(existing_modifies, "merged", ()))
        ):
            rewrite["opModifies"] = self._contextual(*modifies, count=count)

        existing_allocates = getattr(annotation, "opAllocates", None)
        if hasattr(annotation, "opAllocates") and (
            existing_allocates is None
            or (allocates and not getattr(existing_allocates, "merged", ()))
        ):
            rewrite["opAllocates"] = self._contextual(*allocates, count=count)

        existing_refs = getattr(annotation, "references", None)
        if hasattr(annotation, "references") and (
            existing_refs is None or (refs and not getattr(existing_refs, "merged", ()))
        ):
            rewrite["references"] = self._contextual(*refs, count=count)

        if rewrite:
            node.rewriteAnnotation(**rewrite)
