"""Shared helpers for IFDS clients over annotation-complete PyFlow CFGs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, Iterable, Sequence, TypeVar

from pyflow.application.errors import TemporaryLimitation
from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from ..cfg_adapter import CFGNode, CFGSupergraphAdapter, assigned_locals
from ..transfers import resolve_call_name


FactT = TypeVar("FactT")


class AnnotatedFactProblemBase(Generic[FactT], ABC):
    """Reusable slot/call/annotation helpers for IFDS clients."""

    analysis_name = "IFDS analysis"

    def __init__(self, adapter: CFGSupergraphAdapter) -> None:
        self.adapter = adapter
        self._require_complete_annotations()

    @abstractmethod
    def _make_slot_fact(self, slot: object) -> FactT:
        raise NotImplementedError

    @abstractmethod
    def _make_expression_fact(
        self,
        procedure: cfg_graph.Code,
        expression: py_ast.PythonASTNode,
        result_index: int = 0,
    ) -> FactT:
        raise NotImplementedError

    @abstractmethod
    def _slot_from_fact(self, fact: FactT) -> object | None:
        raise NotImplementedError

    @abstractmethod
    def _expression_fact_result(
        self, fact: FactT
    ) -> tuple[cfg_graph.Code, py_ast.PythonASTNode, int] | None:
        raise NotImplementedError

    def local_slots(self, procedure: cfg_graph.Code, local: py_ast.Local) -> tuple[object, ...]:
        return tuple(self._slot_from_fact(fact) for fact in self._facts_for_locals(procedure, (local,)))

    def _direct_expression_fact(
        self,
        expr: py_ast.PythonASTNode | None,
        fact: FactT,
    ):
        result = self._expression_fact_result(fact)
        if result is None or expr is None:
            return None
        expression = result[1]
        if expression is not expr:
            return None
        return result

    def _facts_for_locals(self, procedure: cfg_graph.Code, locals_: Iterable[object]) -> set[FactT]:
        facts: set[FactT] = set()
        for local in locals_:
            if not isinstance(local, py_ast.Local) or local.name is None:
                continue
            slots = self._slots_for_local(procedure, local)
            facts.update(self._make_slot_fact(slot) for slot in slots)
        return facts

    def _facts_for_assigned_locals(
        self,
        procedure: cfg_graph.Code,
        locals_: Sequence[object],
        result_index: int,
    ) -> set[FactT]:
        if result_index >= len(locals_):
            return set()
        return self._facts_for_locals(procedure, (locals_[result_index],))

    def _facts_for_return_slot(self, procedure: cfg_graph.Code, index: int) -> set[FactT]:
        returnparams = tuple(procedure.code.codeparameters.returnparams)
        if index >= len(returnparams):
            return set()
        return self._facts_for_locals(procedure, (returnparams[index],))

    def _facts_for_expression_node(
        self, procedure: cfg_graph.Code, current: object
    ) -> tuple[FactT, ...]:
        if current is None or isinstance(current, py_ast.leafTypes):
            return ()
        if isinstance(current, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            return (self._make_expression_fact(procedure, current),)
        return tuple(
            self._make_slot_fact(slot)
            for slot in self._slots_read_by_node(procedure, current)
        )

    def _facts_for_nested_call_result(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        call_expression: py_ast.PythonASTNode | None,
        return_index: int,
        *,
        nested: bool,
    ) -> set[FactT]:
        if operation is None or call_expression is None:
            return set()

        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)) and operation.expr is call_expression:
            if not nested:
                return {self._make_expression_fact(procedure, call_expression, return_index)}
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                return_index,
            )
        if isinstance(operation, py_ast.AnnAssign) and operation.value is call_expression:
            if not nested:
                return {self._make_expression_fact(procedure, call_expression, return_index)}
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                return_index,
            )

        if isinstance(operation, py_ast.Return):
            if not nested:
                return {self._make_expression_fact(procedure, call_expression, return_index)}
            target_index = self._call_result_target_index(
                operation, call_expression, return_index
            )
            if target_index is not None:
                return self._facts_for_return_slot(procedure, target_index)

        if isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetGlobal,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ) and getattr(operation, "value", None) is call_expression:
            if not nested:
                return {self._make_expression_fact(procedure, call_expression, return_index)}
            return self._facts_for_modified_operation(operation)

        for child in self._nested_operations(operation):
            child_result = self._facts_for_nested_call_result(
                procedure,
                child,
                call_expression,
                return_index,
                nested=True,
            )
            if child_result:
                return child_result

        return {self._make_expression_fact(procedure, call_expression, return_index)}

    def _return_fact_index(self, procedure: cfg_graph.Code, fact: FactT) -> int | None:
        slot = self._slot_from_fact(fact)
        if slot is None:
            return None
        for index, local in enumerate(procedure.code.codeparameters.returnparams):
            if any(candidate == slot for candidate in self._slots_for_local(procedure, local)):
                return index
        return None

    def _call_result_target_index(
        self,
        operation: object,
        call_expression: py_ast.PythonASTNode | None,
        return_index: int,
    ) -> int | None:
        if not isinstance(operation, py_ast.Return):
            return return_index
        if len(operation.exprs) <= 1:
            return return_index
        for index, expr in enumerate(operation.exprs):
            if expr is call_expression:
                return index
        return None

    def _killed_slots_for_operation(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[object, ...]:
        if operation is None:
            return ()
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)):
            return tuple(
                slot
                for fact in self._facts_for_locals(procedure, assigned_locals(operation))
                for slot in (self._slot_from_fact(fact),)
                if slot is not None
            )
        if isinstance(operation, py_ast.Delete):
            return tuple(
                slot
                for fact in self._facts_for_locals(procedure, (operation.lcl,))
                for slot in (self._slot_from_fact(fact),)
                if slot is not None
            )
        if isinstance(operation, py_ast.InputBlock):
            locals_ = []
            for input_ in getattr(operation, "inputs", ()):
                lcl = getattr(input_, "lcl", None)
                if isinstance(lcl, py_ast.Local):
                    locals_.append(lcl)
            return tuple(
                slot
                for fact in self._facts_for_locals(procedure, locals_)
                for slot in (self._slot_from_fact(fact),)
                if slot is not None
            )
        if isinstance(
            operation,
            (py_ast.SetGlobal, py_ast.DeleteGlobal, py_ast.SetCellDeref),
        ):
            return tuple(
                slot
                for fact in self._facts_for_modified_operation(operation)
                for slot in (self._slot_from_fact(fact),)
                if slot is not None
            )
        return ()

    def _killed_slots_for_call_expression(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        call_expression: py_ast.PythonASTNode | None,
    ) -> tuple[object, ...]:
        if operation is None or call_expression is None:
            return ()

        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)) and operation.expr is call_expression:
            return tuple(
                slot
                for fact in self._facts_for_locals(procedure, assigned_locals(operation))
                for slot in (self._slot_from_fact(fact),)
                if slot is not None
            )
        if isinstance(operation, py_ast.AnnAssign) and operation.value is call_expression:
            return tuple(
                slot
                for fact in self._facts_for_locals(procedure, assigned_locals(operation))
                for slot in (self._slot_from_fact(fact),)
                if slot is not None
            )

        if isinstance(operation, (py_ast.SetGlobal, py_ast.SetCellDeref)) and operation.value is call_expression:
            return tuple(
                slot
                for fact in self._facts_for_modified_operation(operation)
                for slot in (self._slot_from_fact(fact),)
                if slot is not None
            )

        for child in self._nested_operations(operation):
            child_kills = self._killed_slots_for_call_expression(
                procedure, child, call_expression
            )
            if child_kills:
                return child_kills

        # The current call node only models one call expression within an
        # operation. If this expression is not the assignment/modification RHS,
        # defer strong updates until the terminal operation node executes.
        return ()

    def _nested_operations(self, operation: object) -> tuple[object, ...]:
        if isinstance(operation, py_ast.Suite):
            return tuple(operation.blocks)
        if isinstance(operation, py_ast.TryExceptFinally):
            nested = list(operation.body.blocks)
            for handler in operation.handlers:
                nested.extend(handler.preamble.blocks)
                if handler.value is not None:
                    nested.append(handler.value)
                nested.extend(handler.body.blocks)
            if operation.defaultHandler is not None:
                nested.extend(operation.defaultHandler.blocks)
            if operation.else_ is not None:
                nested.extend(operation.else_.blocks)
            if operation.finally_ is not None:
                nested.extend(operation.finally_.blocks)
            return tuple(nested)
        if isinstance(operation, py_ast.ExceptionHandler):
            nested = list(operation.preamble.blocks)
            nested.append(operation.type)
            if operation.value is not None:
                nested.append(operation.value)
            nested.extend(operation.body.blocks)
            return tuple(nested)
        return ()

    def _facts_for_modified_operation(self, operation: object) -> set[FactT]:
        slots = self._annotation_slots(getattr(getattr(operation, "annotation", None), "opModifies", None))
        return {self._make_slot_fact(slot) for slot in slots}

    def _slots_for_local(self, procedure: cfg_graph.Code, local: object) -> tuple[object, ...]:
        del procedure
        refs = getattr(getattr(local, "annotation", None), "references", None)
        return self._annotation_slots(refs)

    def _slots_read_by_node(
        self, procedure: cfg_graph.Code, node: object
    ) -> tuple[object, ...]:
        if isinstance(node, py_ast.Local):
            return self._slots_for_local(procedure, node)
        if isinstance(node, (py_ast.GetGlobal, py_ast.GetCellDeref)):
            return self._annotation_slots(getattr(node.annotation, "opReads", None))
        annotation = getattr(node, "annotation", None)
        return self._annotation_slots(getattr(annotation, "opReads", None))

    def _annotation_slots(self, annotation) -> tuple[object, ...]:
        if annotation is None:
            return ()
        merged = getattr(annotation, "merged", None)
        if merged is None:
            # Some pipelines may store a plain annotationSet/tuple here rather
            # than a ContextualAnnotation. In that case, treat the entire
            # iterable as the slot list (not just annotation[0]).
            if isinstance(annotation, (str, bytes)):
                return ()
            if isinstance(annotation, (list, tuple, set, frozenset)):
                merged = tuple(annotation)
            else:
                return ()
        return tuple(self._canonical_slot(slot) for slot in merged)

    def _canonical_slot(self, slot: object) -> object:
        get_forward = getattr(slot, "getForward", None)
        if callable(get_forward):
            return get_forward()
        return slot

    def _call_name(self, node: CFGNode) -> str | None:
        call = self.adapter.call_expression_of(node)
        return resolve_call_name(
            call,
            fallback_callee_names=tuple(
                cfg.code.codeName()
                for cfg in self.adapter.callees_of(node)
                if cfg.code is not None
            ),
        )

    def _call_name_from_expression(self, expr: object) -> str | None:
        if isinstance(expr, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            return resolve_call_name(expr)
        return None

    def describe_slot(self, slot: object) -> str:
        label = getattr(slot, "label", None)
        if isinstance(label, str):
            return label
        slot_name = getattr(slot, "slotName", None)
        if slot_name is not None:
            if hasattr(slot_name, "isLocal") and slot_name.isLocal():
                local = getattr(slot_name, "local", None)
                name = getattr(local, "name", None)
                if name is not None:
                    return name
            if hasattr(slot_name, "isExisting") and slot_name.isExisting():
                obj = getattr(slot_name, "object", None)
                name = self._object_name(obj)
                if name is not None:
                    return name
        return repr(slot)

    def describe_expression(self, expr: object) -> str:
        call_name = self._call_name_from_expression(expr)
        if call_name is not None:
            return f"{call_name}()"
        if isinstance(expr, py_ast.GetAttr):
            return f"{self.describe_expression(expr.expr)}.{self._path_component(expr.name)}"
        if isinstance(expr, py_ast.Load):
            return f"{self.describe_expression(expr.expr)}.{self._path_component(expr.name)}"
        if isinstance(expr, py_ast.GetSubscript):
            return f"{self.describe_expression(expr.expr)}{self._subscript_component(expr.subscript)}"
        if isinstance(expr, py_ast.GetGlobal):
            return self._global_name(expr.name) or "<global>"
        if isinstance(expr, py_ast.GetCellDeref):
            return expr.cell.name if isinstance(expr.cell, py_ast.Cell) else "<cell>"
        if isinstance(expr, py_ast.Local) and expr.name is not None:
            return expr.name
        return "<expr>"

    def _object_name(self, obj) -> str | None:
        if obj is None:
            return None
        constant_value = getattr(obj, "constantValue", None)
        if callable(constant_value):
            value = constant_value()
            if value is not None:
                return str(value)
        identifier = getattr(obj, "id", None)
        if isinstance(identifier, str):
            return identifier
        pyobj = getattr(obj, "pyobj", None)
        if isinstance(pyobj, str):
            return pyobj
        return None

    def _path_component(self, node) -> str:
        if isinstance(node, py_ast.Local) and node.name:
            return node.name
        if isinstance(node, py_ast.Existing):
            name = self._object_name(node.object)
            if name is not None:
                return name
        return "*"

    def _subscript_component(self, node) -> str:
        if isinstance(node, py_ast.Existing):
            value = self._object_name(node.object)
            if value is not None:
                return f"[{value!r}]"
        return "[*]"

    def _global_name(self, existing) -> str | None:
        if not isinstance(existing, py_ast.Existing):
            return None
        return self._object_name(existing.object)

    def _require_complete_annotations(self) -> None:
        problems: list[str] = []
        seen_codes: set[object] = set()
        for cfg in self.adapter.cfgs:
            code = getattr(cfg, "code", None)
            if code is None or code in seen_codes:
                continue
            seen_codes.add(code)
            code_annotation = getattr(code, "annotation", None)
            if getattr(code_annotation, "contexts", None) is None:
                problems.append(f"{code.codeName()}: missing code contexts")
                continue

            for node in self._iter_ast_nodes(code):
                annotation = getattr(node, "annotation", None)
                if annotation is None:
                    continue
                if hasattr(annotation, "opReads") and getattr(annotation, "opReads", None) is None:
                    problems.append(f"{code.codeName()}: {type(node).__name__} missing opReads")
                    break
                if hasattr(annotation, "opModifies") and getattr(annotation, "opModifies", None) is None:
                    problems.append(
                        f"{code.codeName()}: {type(node).__name__} missing opModifies"
                    )
                    break
                if hasattr(annotation, "references") and getattr(annotation, "references", None) is None:
                    name = getattr(node, "name", None)
                    problems.append(
                        f"{code.codeName()}: local {name if name is not None else '<anon>'} missing references"
                    )
                    break

        if problems:
            raise TemporaryLimitation(
                f"{self.analysis_name} requires annotation-complete programs (run IPA/CPA first): "
                + "; ".join(problems[:5])
            )

    def _iter_ast_nodes(self, node):
        if node is None or isinstance(node, py_ast.leafTypes):
            return
        yield node
        if isinstance(node, (list, tuple)):
            for child in node:
                yield from self._iter_ast_nodes(child)
            return
        if isinstance(node, py_ast.Code):
            params = getattr(node, "codeparameters", None)
            if params is not None:
                yield from self._iter_ast_nodes(getattr(params, "selfparam", None))
                yield from self._iter_ast_nodes(getattr(params, "posonlyparams", ()))
                yield from self._iter_ast_nodes(getattr(params, "params", ()))
                yield from self._iter_ast_nodes(getattr(params, "defaults", ()))
                yield from self._iter_ast_nodes(getattr(params, "vparam", None))
                yield from self._iter_ast_nodes(getattr(params, "kparam", None))
                yield from self._iter_ast_nodes(getattr(params, "returnparams", ()))
            yield from self._iter_ast_nodes(node.ast)
            return

        children: list[object] = []

        def collect(child) -> None:
            children.append(child)

        node.visitChildren(collect)
        for child in children:
            yield from self._iter_ast_nodes(child)
