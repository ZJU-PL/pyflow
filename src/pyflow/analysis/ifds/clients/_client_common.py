"""Shared helpers for IFDS clients over annotation-complete PyFlow CFGs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, Iterable, Sequence, TypeVar

from pyflow.application.errors import TemporaryLimitation
from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from ..cfg_adapter import CFGNode, CFGSupergraphAdapter, CallEffect, GuardEffect, assigned_locals
from ..transfers import actual_argument_expressions, collect_locals, resolve_call_name
from ._call_model import CallModelRegistry


FactT = TypeVar("FactT")
DYNAMIC_ATTRIBUTE_WILDCARD = "*"
DYNAMIC_SUBSCRIPT_WILDCARD = "[*]"


def build_entry_seeds(entry_nodes: Sequence[CFGNode], zero_fact: object):
    """Build standard zero-fact seeds for entry-rooted IFDS analyses."""
    return {node: frozenset({zero_fact}) for node in entry_nodes}


@dataclass(frozen=True)
class DynamicAttributeSlot:
    """Synthetic field slot for reflection through getattr/setattr."""

    base: object
    attribute: str


@dataclass(frozen=True)
class DynamicSubscriptSlot:
    """Synthetic element slot for subscript reads/writes."""

    base: object
    subscript: str


class AnnotatedFactProblemBase(Generic[FactT], ABC):
    """Reusable slot/call/annotation helpers for IFDS clients."""

    analysis_name = "IFDS analysis"

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        *,
        call_models: CallModelRegistry | None = None,
    ) -> None:
        self.adapter = adapter
        self.call_models = call_models or CallModelRegistry()
        self._slot_overrides: dict[tuple, tuple[object, ...]] = {}
        self._site_counter: int = 0
        self._allocation_sites: dict[tuple, int] = {}
        self._site_slots: dict[int, tuple[object, ...]] = {}
        self._require_complete_annotations()

    def _alias_locals(
        self, procedure: cfg_graph.Code, target: object, source: object
    ) -> None:
        """Make *target* share slot identity and allocation site with *source*.

        After this call, ``_slots_for_local(procedure, target)`` returns the
        same objects as ``_slots_for_local(procedure, source)``, so facts
        created for *source* are also visible through *target*.  The
        allocation site is also shared, so ``x = Foo(); y = x`` gives *y*
        the same abstract cell as *x*, while ``z = Foo()`` gets a distinct
        cell.
        """
        if not isinstance(target, py_ast.Local) or target.name is None:
            return
        if not isinstance(source, py_ast.Local) or source.name is None:
            return
        source_slots = self._slots_for_local(procedure, source)
        if not source_slots:
            return
        self._slot_overrides[(id(procedure), id(target))] = source_slots
        source_site = self._allocation_sites.get((id(procedure), id(source)))
        if source_site is not None:
            self._allocation_sites[(id(procedure), id(target))] = source_site

    def _unalias_locals(self, procedure: cfg_graph.Code, local: object) -> None:
        """Break any slot alias for *local*, restoring its own identity.

        Called on strong updates (assignment, delete) so that overwriting
        one variable does not clear facts for variables it was aliased to.
        Also assigns a fresh allocation site so the variable no longer
        shares abstract state with its previous alias source.
        """
        if not isinstance(local, py_ast.Local) or local.name is None:
            return
        self._slot_overrides.pop((id(procedure), id(local)), None)
        raw = self._slots_for_local_raw(procedure, local)
        site = self._site_counter
        self._site_counter += 1
        self._allocation_sites[(id(procedure), id(local))] = site
        self._site_slots[site] = raw

    def _update_aliases_for_assignment(
        self,
        procedure: cfg_graph.Code,
        targets: tuple[object, ...],
        expr: object,
    ) -> None:
        """Handle alias tracking for ``targets = expr``.

        Strong updates break any existing aliases and assign fresh
        allocation sites on *targets*.  When *expr* is a plain local
        reference the targets are aliased to it, sharing both slots and
        allocation site.
        """
        for target in targets:
            self._unalias_locals(procedure, target)
        if isinstance(expr, py_ast.Local) and expr.name is not None:
            for target in targets:
                self._alias_locals(procedure, target, expr)

    def _slots_for_local(self, procedure: cfg_graph.Code, local: object) -> tuple[object, ...]:
        override = self._slot_overrides.get((id(procedure), id(local)))
        if override is not None:
            return override
        site = self._allocation_sites.get((id(procedure), id(local)))
        if site is not None:
            return self._site_slots[site]
        raw = self._slots_for_local_raw(procedure, local)
        site = self._site_counter
        self._site_counter += 1
        self._allocation_sites[(id(procedure), id(local))] = site
        self._site_slots[site] = raw
        return raw

    def _slots_for_local_raw(self, procedure: cfg_graph.Code, local: object) -> tuple[object, ...]:
        del procedure
        refs = getattr(getattr(local, "annotation", None), "references", None)
        return self._annotation_slots(refs)

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

    def _access_path_from_fact(self, fact: FactT) -> tuple[str, ...]:
        return getattr(fact, "access_path", ())

    @staticmethod
    def _fact_prefix_matches(stored: object, query: object) -> bool:
        """True when *stored* implies *query* via access-path prefix.

        ``stored`` is the known fact (from reached set or current flow).
        ``query`` is the fact being checked against.  When *stored* has
        ``access_path=()`` it means the whole object is affected, so ANY
        sub-path matches.  When *stored* has a specific path like
        ``("f",)`` only that exact path and its descendants match —
        the base object and sibling fields do NOT.
        """
        if stored == query:
            return True
        s_slot = getattr(stored, "slot", None)
        q_slot = getattr(query, "slot", None)
        if s_slot is None or q_slot is None or s_slot != q_slot:
            return False
        s_path = getattr(stored, "access_path", ())
        q_path = getattr(query, "access_path", ())
        if s_path == q_path:
            return True
        return len(s_path) <= len(q_path) and q_path[: len(s_path)] == s_path

    def _make_slot_fact_with_path(
        self, slot: object, access_path: tuple[str, ...]
    ) -> FactT:
        return self._make_slot_fact(slot)

    @abstractmethod
    def _expression_fact_result(
        self, fact: FactT
    ) -> tuple[cfg_graph.Code, py_ast.PythonASTNode, int] | None:
        raise NotImplementedError

    def local_slots(
        self, procedure: cfg_graph.Code, local: py_ast.Local
    ) -> tuple[object, ...]:
        return tuple(
            self._slot_from_fact(fact)
            for fact in self._facts_for_locals(procedure, (local,))
        )

    def _call_effect(self, node: CFGNode) -> CallEffect | None:
        effect = self.adapter.effect_of(node)
        if isinstance(effect, CallEffect):
            return effect
        return None

    def _guard_effect(self, node: CFGNode) -> GuardEffect | None:
        effect = self.adapter.effect_of(node)
        if isinstance(effect, GuardEffect):
            return effect
        return None

    def _killed_slots_for_node(self, node: CFGNode) -> tuple[object, ...]:
        effect = self.adapter.effect_of(node)
        operation = getattr(effect, "operation", self.adapter.operation_of(node))
        dynamic_kills = self._dynamic_delete_slots(node.procedure, operation)
        strong_update_slots = getattr(effect, "strong_update_slots", None)
        if strong_update_slots:
            return tuple(dict.fromkeys((*strong_update_slots, *dynamic_kills)))
        kill_slots = getattr(effect, "kill_slots", None)
        if kill_slots:
            return tuple(dict.fromkeys((*kill_slots, *dynamic_kills)))
        return dynamic_kills

    def _call_model_for_node(self, node: CFGNode):
        return self.call_models.model_for_name(self._call_name(node))

    def _call_model_for_expression(self, expr: object):
        return self.call_models.model_for_name(self._call_name_from_expression(expr))

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

    def _facts_for_locals(
        self, procedure: cfg_graph.Code, locals_: Iterable[object]
    ) -> set[FactT]:
        facts: set[FactT] = set()
        for local in locals_:
            if not isinstance(local, py_ast.Local) or local.name is None:
                continue
            slots = self._slots_for_local(procedure, local)
            facts.update(self._make_slot_fact(slot) for slot in slots)
        return facts

    def _facts_for_locals_with_path(
        self,
        procedure: cfg_graph.Code,
        locals_: Iterable[object],
        access_path: tuple[str, ...],
    ) -> set[FactT]:
        facts: set[FactT] = set()
        for local in locals_:
            if not isinstance(local, py_ast.Local) or local.name is None:
                continue
            slots = self._slots_for_local(procedure, local)
            facts.update(
                self._make_slot_fact_with_path(slot, access_path)
                for slot in slots
            )
        return facts

    def _access_path_for_expression(self, expr: object) -> tuple[str, ...]:
        path: list[str] = []
        current = expr
        while isinstance(current, py_ast.GetAttr):
            path.append(self._path_component(current.name))
            current = current.expr
        path.reverse()
        return tuple(path)

    def _facts_for_assigned_locals(
        self,
        procedure: cfg_graph.Code,
        locals_: Sequence[object],
        result_index: int,
    ) -> set[FactT]:
        if result_index >= len(locals_):
            return set()
        return self._facts_for_locals(procedure, (locals_[result_index],))

    def _facts_for_return_slot(
        self, procedure: cfg_graph.Code, index: int,
        access_path: tuple[str, ...] = (),
    ) -> set[FactT]:
        returnparams = tuple(procedure.code.codeparameters.returnparams)
        if index >= len(returnparams):
            return set()
        if not access_path:
            return self._facts_for_locals(procedure, (returnparams[index],))
        return self._facts_for_locals_with_path(
            procedure, (returnparams[index],), access_path,
        )

    def _facts_for_expression_node(
        self, procedure: cfg_graph.Code, current: object,
        extend_paths: bool = False,
    ) -> tuple[FactT, ...]:
        if current is None or isinstance(current, py_ast.leafTypes):
            return ()
        if extend_paths and isinstance(current, py_ast.GetAttr):
            attr = self._path_component(current.name)
            base = self._facts_for_expression_node(
                procedure, current.expr, extend_paths=True,
            )
            return tuple(
                self._make_slot_fact_with_path(
                    self._slot_from_fact(f),
                    (*self._access_path_from_fact(f), attr),
                )
                for f in base
                if self._slot_from_fact(f) is not None
            )
        if isinstance(current, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            dynamic_facts = tuple(
                self._make_slot_fact(slot)
                for slot in (
                    *self._dynamic_getattr_slots(procedure, current),
                    *self._dynamic_subscript_read_slots(procedure, current),
                    *self._collection_access_slots(
                        procedure,
                        current,
                        self._collection_accessor_names(),
                    ),
                )
            )
            return (*dynamic_facts, self._make_expression_fact(procedure, current))
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

        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
            if not nested:
                return {
                    self._make_expression_fact(
                        procedure, call_expression, return_index
                    )
                }
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                return_index,
            )
        if isinstance(operation, py_ast.AnnAssign) and operation.value is call_expression:
            if not nested:
                return {
                    self._make_expression_fact(
                        procedure, call_expression, return_index
                    )
                }
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

        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
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

        if (
            isinstance(operation, (py_ast.SetGlobal, py_ast.SetCellDeref))
            and operation.value is call_expression
        ):
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

    def _facts_for_modified_operation(
        self, operation: object, access_path: tuple[str, ...] = (),
    ) -> set[FactT]:
        slots = self._annotation_slots(
            getattr(getattr(operation, "annotation", None), "opModifies", None)
        )
        if not access_path:
            return {self._make_slot_fact(slot) for slot in slots}
        return {
            self._make_slot_fact_with_path(slot, access_path)
            for slot in slots
        }

    def _dynamic_getattr_slots(
        self, procedure: cfg_graph.Code, expr: object
    ) -> tuple[DynamicAttributeSlot, ...]:
        call = self._dynamic_attribute_call(expr, {"getattr", "builtins.getattr"})
        if call is None:
            return ()
        actuals = actual_argument_expressions(call)
        if len(actuals) < 2:
            return ()
        attribute = self._constant_string(actuals[1])
        attributes = (DYNAMIC_ATTRIBUTE_WILDCARD,)
        if attribute is not None:
            attributes = (attribute, DYNAMIC_ATTRIBUTE_WILDCARD)
        return self._dynamic_attribute_slots(procedure, actuals[0], attributes)

    def _dynamic_setattr_slots(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[DynamicAttributeSlot, ...]:
        call = self._dynamic_attribute_call(operation, {"setattr", "builtins.setattr"})
        if call is None:
            return ()
        actuals = actual_argument_expressions(call)
        if len(actuals) < 2:
            return ()
        attribute = self._constant_string(actuals[1]) or DYNAMIC_ATTRIBUTE_WILDCARD
        attributes = (attribute,)
        if attribute != DYNAMIC_ATTRIBUTE_WILDCARD:
            attributes = (attribute, DYNAMIC_ATTRIBUTE_WILDCARD)
        return self._dynamic_attribute_slots(procedure, actuals[0], attributes)

    def _dynamic_attribute_slots(
        self,
        procedure: cfg_graph.Code,
        base_expr: object,
        attributes: tuple[str, ...],
    ) -> tuple[DynamicAttributeSlot, ...]:
        slots: list[DynamicAttributeSlot] = []
        seen: set[DynamicAttributeSlot] = set()
        for base in self._slots_read_by_node(procedure, base_expr):
            for attribute in attributes:
                slot = DynamicAttributeSlot(base, attribute)
                if slot in seen:
                    continue
                seen.add(slot)
                slots.append(slot)
        return tuple(slots)

    def _dynamic_subscript_read_slots(
        self, procedure: cfg_graph.Code, expr: object
    ) -> tuple[DynamicSubscriptSlot, ...]:
        if isinstance(expr, py_ast.GetSubscript):
            container = expr.expr
            key = expr.subscript
        else:
            call = self._call_from_expression_or_statement(expr)
            if call is None or resolve_call_name(call) != "interpreter_getitem":
                return ()
            actuals = actual_argument_expressions(call)
            if len(actuals) < 2:
                return ()
            container = actuals[0]
            key = actuals[1]
        return self._dynamic_subscript_slots_for_key(procedure, container, key)

    def _dynamic_subscript_write_slots(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[DynamicSubscriptSlot, ...]:
        target = self._dynamic_subscript_write_target(operation)
        if target is None:
            return ()
        container, key, _value = target
        return self._dynamic_subscript_slots_for_key(procedure, container, key)

    def _dynamic_subscript_slots_for_key(
        self,
        procedure: cfg_graph.Code,
        container: object,
        key: object,
    ) -> tuple[DynamicSubscriptSlot, ...]:
        subscript = self._constant_subscript(key)
        subscripts = (DYNAMIC_SUBSCRIPT_WILDCARD,)
        if subscript is not None:
            subscripts = (subscript, DYNAMIC_SUBSCRIPT_WILDCARD)
        return self._dynamic_subscript_slots(procedure, container, subscripts)

    def _dynamic_subscript_value(self, operation: object) -> object | None:
        target = self._dynamic_subscript_write_target(operation)
        if target is None:
            return None
        return target[2]

    def _dynamic_delete_slots(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[object, ...]:
        slots = [
            *self._dynamic_subscript_delete_slots(procedure, operation),
            *self._dynamic_attribute_delete_slots(procedure, operation),
        ]
        return tuple(dict.fromkeys(slots))

    def _dynamic_subscript_delete_slots(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[DynamicSubscriptSlot, ...]:
        if isinstance(operation, py_ast.DeleteSubscript):
            return self._dynamic_subscript_slots_for_key(
                procedure,
                operation.expr,
                operation.subscript,
            )
        call = self._call_from_expression_or_statement(operation)
        if call is None or resolve_call_name(call) != "interpreter_delitem":
            return ()
        actuals = actual_argument_expressions(call)
        if len(actuals) < 2:
            return ()
        return self._dynamic_subscript_slots_for_key(procedure, actuals[0], actuals[1])

    def _dynamic_attribute_delete_slots(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[DynamicAttributeSlot, ...]:
        if not isinstance(operation, py_ast.DeleteAttr):
            return ()
        attribute = self._constant_string(operation.name) or DYNAMIC_ATTRIBUTE_WILDCARD
        attributes = (attribute,)
        if attribute != DYNAMIC_ATTRIBUTE_WILDCARD:
            attributes = (attribute, DYNAMIC_ATTRIBUTE_WILDCARD)
        return self._dynamic_attribute_slots(procedure, operation.expr, attributes)

    def _dynamic_subscript_write_target(
        self, operation: object
    ) -> tuple[object, object, object] | None:
        if isinstance(operation, py_ast.SetSubscript):
            return operation.expr, operation.subscript, operation.value
        call = self._call_from_expression_or_statement(operation)
        if call is None or resolve_call_name(call) != "interpreter_setitem":
            return None
        actuals = actual_argument_expressions(call)
        if len(actuals) < 3:
            return None
        return actuals[0], actuals[1], actuals[2]

    def _dynamic_subscript_slots(
        self,
        procedure: cfg_graph.Code,
        base_expr: object,
        subscripts: tuple[str, ...],
    ) -> tuple[DynamicSubscriptSlot, ...]:
        slots: list[DynamicSubscriptSlot] = []
        seen: set[DynamicSubscriptSlot] = set()
        for base in self._slots_read_by_node(procedure, base_expr):
            for subscript in subscripts:
                slot = DynamicSubscriptSlot(base, subscript)
                if slot in seen:
                    continue
                seen.add(slot)
                slots.append(slot)
        return tuple(slots)

    def _collection_mutation(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        mutator_names: frozenset[str],
    ) -> tuple[tuple[DynamicSubscriptSlot, ...], tuple[object, ...]]:
        call = self._call_from_expression_or_statement(operation)
        if call is None or resolve_call_name(call) not in mutator_names:
            return (), ()

        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall):
            container = call.expr
            values = actuals
        else:
            if len(actuals) < 2:
                return (), ()
            container = actuals[0]
            values = actuals[1:]

        slots = self._dynamic_subscript_slots(
            procedure,
            container,
            (DYNAMIC_SUBSCRIPT_WILDCARD,),
        )
        return slots, tuple(values)

    def _collection_copy_mutation(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        mutator_names: frozenset[str],
    ) -> tuple[tuple[DynamicSubscriptSlot, ...], tuple[DynamicSubscriptSlot, ...]]:
        call = self._call_from_expression_or_statement(operation)
        call_name = resolve_call_name(call) if call is not None else None
        if call is None or call_name not in mutator_names:
            return (), ()
        if call_name not in {"extend", "update"}:
            return (), ()

        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall):
            container = call.expr
            sources = actuals
        else:
            if len(actuals) < 2:
                return (), ()
            container = actuals[0]
            sources = actuals[1:]

        destination_slots = self._dynamic_subscript_slots(
            procedure,
            container,
            (DYNAMIC_SUBSCRIPT_WILDCARD,),
        )
        source_slots = tuple(
            slot
            for source in sources
            for slot in self._dynamic_subscript_slots(
                procedure,
                source,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
        )
        return destination_slots, tuple(dict.fromkeys(source_slots))

    def _collection_constructor_writes(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[tuple[tuple[DynamicSubscriptSlot, ...], object], ...]:
        expr = None
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            expr = operation.expr
        elif isinstance(operation, py_ast.AnnAssign):
            expr = operation.value
        if expr is None:
            return ()

        target_slots = tuple(
            slot
            for target in assigned_locals(operation)
            for slot in self._slots_for_local(procedure, target)
        )
        if not target_slots:
            return ()

        writes: list[tuple[tuple[DynamicSubscriptSlot, ...], object]] = []
        if isinstance(expr, py_ast.BuildTuple):
            for index, value in enumerate(expr.args):
                writes.append(
                    (
                        self._collection_constructor_slots(
                            target_slots,
                            (f"[{index!r}]", DYNAMIC_SUBSCRIPT_WILDCARD),
                        ),
                        value,
                    )
                )
        elif isinstance(expr, (py_ast.BuildList, py_ast.BuildSet)):
            for value in expr.args:
                writes.append(
                    (
                        self._collection_constructor_slots(
                            target_slots,
                            (DYNAMIC_SUBSCRIPT_WILDCARD,),
                        ),
                        value,
                    )
                )
        elif isinstance(expr, py_ast.BuildMap):
            pairs = zip(expr.args[0::2], expr.args[1::2])
            for key, value in pairs:
                subscript = self._constant_subscript(key)
                subscripts = (DYNAMIC_SUBSCRIPT_WILDCARD,)
                if subscript is not None:
                    subscripts = (subscript, DYNAMIC_SUBSCRIPT_WILDCARD)
                writes.append(
                    (
                        self._collection_constructor_slots(target_slots, subscripts),
                        value,
                    )
                )
        return tuple(writes)

    def _collection_constructor_slots(
        self,
        bases: tuple[object, ...],
        subscripts: tuple[str, ...],
    ) -> tuple[DynamicSubscriptSlot, ...]:
        slots: list[DynamicSubscriptSlot] = []
        seen: set[DynamicSubscriptSlot] = set()
        for base in bases:
            for subscript in subscripts:
                slot = DynamicSubscriptSlot(base, subscript)
                if slot in seen:
                    continue
                seen.add(slot)
                slots.append(slot)
        return tuple(slots)

    def _aliased_dynamic_slots_for_assignment(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        fact: FactT,
    ) -> tuple[object, ...]:
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            expr = operation.expr
        elif isinstance(operation, py_ast.AnnAssign):
            expr = operation.value
        else:
            return ()

        source_slot = self._slot_from_fact(fact)
        if not isinstance(source_slot, (DynamicAttributeSlot, DynamicSubscriptSlot)):
            return ()

        expr_bases = self._slots_read_by_node(procedure, expr)
        if not any(base == source_slot.base for base in expr_bases):
            return ()

        target_bases = tuple(
            slot
            for target in assigned_locals(operation)
            for slot in self._slots_for_local(procedure, target)
        )
        if isinstance(source_slot, DynamicAttributeSlot):
            return tuple(
                DynamicAttributeSlot(base, source_slot.attribute)
                for base in target_bases
            )
        return tuple(
            DynamicSubscriptSlot(base, source_slot.subscript)
            for base in target_bases
        )

    def _collection_copy_result_slots_for_assignment(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        fact: FactT,
    ) -> tuple[DynamicSubscriptSlot, ...]:
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            expr = operation.expr
        elif isinstance(operation, py_ast.AnnAssign):
            expr = operation.value
        else:
            return ()

        source_slot = self._slot_from_fact(fact)
        if not isinstance(source_slot, DynamicSubscriptSlot):
            return ()

        source_exprs = self._collection_copy_result_sources(expr)
        if not source_exprs:
            return ()
        source_slots = tuple(
            slot
            for source_expr in source_exprs
            for slot in self._dynamic_subscript_slots(
                procedure,
                source_expr,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
        )
        if not any(source_slot == candidate for candidate in source_slots):
            return ()

        target_bases = tuple(
            slot
            for target in assigned_locals(operation)
            for slot in self._slots_for_local(procedure, target)
        )
        return tuple(
            DynamicSubscriptSlot(base, DYNAMIC_SUBSCRIPT_WILDCARD)
            for base in target_bases
        )

    def _collection_copy_result_sources(self, expr: object) -> tuple[object, ...]:
        call = self._call_from_expression_or_statement(expr)
        if call is None:
            return ()
        call_name = resolve_call_name(call)
        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall) and call_name == "copy":
            return (call.expr,)
        if call_name in {"copy", "list", "tuple", "set", "dict"} and actuals:
            return (actuals[0],)
        return ()

    def _collection_accessor_names(self) -> frozenset[str]:
        configuration = getattr(self, "configuration", None)
        return getattr(configuration, "collection_accessor_names", frozenset())

    def _collection_access_slots(
        self,
        procedure: cfg_graph.Code,
        expr: object,
        accessor_names: frozenset[str],
    ) -> tuple[DynamicSubscriptSlot, ...]:
        call = self._call_from_expression_or_statement(expr)
        if call is None or resolve_call_name(call) not in accessor_names:
            return ()

        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall):
            container = call.expr
            key = actuals[0] if actuals else None
        else:
            if len(actuals) < 1:
                return ()
            container = actuals[0]
            key = actuals[1] if len(actuals) > 1 else None

        subscript = (
            self._constant_subscript(key)
            if key is not None
            else None
        )
        subscripts = (DYNAMIC_SUBSCRIPT_WILDCARD,)
        if subscript is not None:
            subscripts = (subscript, DYNAMIC_SUBSCRIPT_WILDCARD)
        return self._dynamic_subscript_slots(procedure, container, subscripts)

    def _dynamic_setattr_value(self, operation: object) -> object | None:
        call = self._dynamic_attribute_call(operation, {"setattr", "builtins.setattr"})
        if call is None:
            return None
        actuals = actual_argument_expressions(call)
        if len(actuals) < 3:
            return None
        return actuals[2]

    def _dynamic_attribute_call(
        self, expr: object, names: set[str]
    ) -> py_ast.PythonASTNode | None:
        candidate = self._call_from_expression_or_statement(expr)
        if candidate is None:
            return None
        if resolve_call_name(candidate) not in names:
            return None
        return candidate

    def _call_from_expression_or_statement(
        self, expr: object
    ) -> py_ast.PythonASTNode | None:
        candidate = expr
        if not isinstance(candidate, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            wrapped = getattr(expr, "expr", None)
            if isinstance(wrapped, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
                candidate = wrapped
        if not isinstance(candidate, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            return None
        return candidate

    def _constant_string(self, expr: object) -> str | None:
        if not isinstance(expr, py_ast.Existing):
            return None
        value = getattr(expr.object, "pyobj", None)
        return value if isinstance(value, str) else None

    def _constant_subscript(self, expr: object) -> str | None:
        if not isinstance(expr, py_ast.Existing):
            return None
        value = getattr(expr.object, "pyobj", None)
        return f"[{value!r}]"

    def _slots_read_by_node(
        self, procedure: cfg_graph.Code, node: object
    ) -> tuple[object, ...]:
        if isinstance(node, py_ast.Local):
            return self._slots_for_local(procedure, node)
        if isinstance(node, (py_ast.GetGlobal, py_ast.GetCellDeref)):
            return self._annotation_slots(getattr(node.annotation, "opReads", None))
        annotation = getattr(node, "annotation", None)
        slots = list(self._annotation_slots(getattr(annotation, "opReads", None)))
        slots.extend(self._dynamic_getattr_slots(procedure, node))
        slots.extend(self._dynamic_subscript_read_slots(procedure, node))
        return tuple(dict.fromkeys(slots))

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
        if isinstance(slot, DynamicAttributeSlot):
            return f"{self.describe_slot(slot.base)}.{slot.attribute}"
        if isinstance(slot, DynamicSubscriptSlot):
            return f"{self.describe_slot(slot.base)}{slot.subscript}"
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
            base = self.describe_expression(expr.expr)
            return f"{base}.{self._path_component(expr.name)}"
        if isinstance(expr, py_ast.Load):
            base = self.describe_expression(expr.expr)
            return f"{base}.{self._path_component(expr.name)}"
        if isinstance(expr, py_ast.GetSubscript):
            base = self.describe_expression(expr.expr)
            return f"{base}{self._subscript_component(expr.subscript)}"
        if isinstance(expr, py_ast.GetGlobal):
            return self._global_name(expr.name) or "<global>"
        if isinstance(expr, py_ast.GetCellDeref):
            return expr.cell.name if isinstance(expr.cell, py_ast.Cell) else "<cell>"
        if isinstance(expr, py_ast.Local) and expr.name is not None:
            return expr.name
        local_names = sorted(
            {local.name for local in collect_locals(expr) if local.name is not None}
        )
        if local_names:
            return ", ".join(local_names)
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
                if (
                    hasattr(annotation, "opReads")
                    and getattr(annotation, "opReads", None) is None
                ):
                    problems.append(
                        f"{code.codeName()}: {type(node).__name__} missing opReads"
                    )
                    break
                if (
                    hasattr(annotation, "opModifies")
                    and getattr(annotation, "opModifies", None) is None
                ):
                    problems.append(
                        f"{code.codeName()}: {type(node).__name__} missing opModifies"
                    )
                    break
                if (
                    hasattr(annotation, "references")
                    and getattr(annotation, "references", None) is None
                ):
                    name = getattr(node, "name", None)
                    label = name if name is not None else "<anon>"
                    problems.append(
                        f"{code.codeName()}: local {label} missing references"
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
