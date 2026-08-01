"""Shared helpers for IFDS clients over annotation-complete PyFlow CFGs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, Iterable, Sequence, TypeVar

from pyflow.application.errors import TemporaryLimitation
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.ir.core import LocalStorage, ensure_code_indexed
from pyflow.language.python import ast as py_ast

from ...alias.flow_sensitive.domain.abstraction import HeapAbstraction
from ...alias.flow_sensitive.model import HeapLocation
from ...alias.flow_sensitive.semantics.effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_OPAQUE,
    CALL_RETURN_SUMMARY,
    HeapEffect,
    HeapEffectBuilder,
)
from ...alias.flow_sensitive.domain.summary import HeapSummary, HeapSummaryBuilder
from ..frontend.cfg_adapter import (
    CFGNode,
    CFGSupergraphAdapter,
    CallEffect,
    GuardEffect,
    assigned_locals,
)
from ..core.transfers import (
    actual_argument_expressions,
    bind_call_arguments,
    collect_locals,
    formal_parameters,
)
from ..modeling.calls import CallModelRegistry


FactT = TypeVar("FactT")
DYNAMIC_SUBSCRIPT_WILDCARD = "[*]"


def build_entry_seeds(entry_nodes: Sequence[CFGNode], zero_fact: object):
    """Build standard zero-fact seeds for entry-rooted IFDS analyses."""
    return {node: frozenset({zero_fact}) for node in entry_nodes}


class AnnotatedFactProblemBase(Generic[FactT], ABC):
    """Reusable location/call/annotation helpers for IFDS clients."""

    analysis_name = "IFDS analysis"

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        *,
        call_models: CallModelRegistry | None = None,
    ) -> None:
        self.adapter = adapter
        self.call_models = call_models or CallModelRegistry()
        self._storage_overrides: dict[tuple, tuple[object, ...]] = {}
        self._site_counter: int = 0
        self._allocation_sites: dict[tuple, int] = {}
        self._site_storage: dict[int, tuple[object, ...]] = {}
        self._heap_summaries: dict[int, HeapSummary] = {}
        self.heap = HeapAbstraction(
            self._locations_for_local_raw,
            storage_overrides=self._storage_overrides,
            allocation_sites=self._allocation_sites,
            site_storage=self._site_storage,
            next_site=self._site_counter,
        )
        self._require_semantics()

    def _heap(self) -> HeapAbstraction:
        heap = getattr(self, "heap", None)
        if heap is None:
            heap = HeapAbstraction(
                self._locations_for_local_raw,
                storage_overrides=getattr(self, "_storage_overrides", None),
                allocation_sites=getattr(self, "_allocation_sites", None),
                site_storage=getattr(self, "_site_storage", None),
                next_site=getattr(self, "_site_counter", 0),
            )
            self.heap = heap
            self._storage_overrides = heap.storage_overrides
            self._allocation_sites = heap.allocation_sites
            self._site_storage = heap.site_storage
        self._site_counter = heap.next_site
        return heap

    def _alias_locals(
        self, procedure: cfg_graph.Code, target: object, source: object
    ) -> None:
        """Make *target* share location identity and allocation site with *source*."""
        heap = self._heap()
        heap.alias_locals(procedure, target, source)
        self._site_counter = heap.next_site

    def _unalias_locals(self, procedure: cfg_graph.Code, local: object) -> None:
        """Break any location alias for *local*, restoring its own identity."""
        heap = self._heap()
        heap.unalias_local(procedure, local)
        self._site_counter = heap.next_site

    def _update_aliases_for_assignment(
        self,
        procedure: cfg_graph.Code,
        targets: tuple[object, ...],
        expr: object,
    ) -> None:
        """Handle alias tracking for ``targets = expr``.

        Strong updates break any existing aliases and assign fresh
        allocation sites on *targets*.  When *expr* is a plain local
        reference the targets are aliased to it, sharing both locations and
        allocation site.
        """
        heap = self._heap()
        if self._is_allocation_expression(expr):
            heap.bind_allocation_targets(
                procedure,
                targets,
                expr,
                label=self._allocation_label(expr),
                type_hint=self._allocation_type_hint(expr),
            )
        elif heap.policy.bind_call_results and self._is_call_expression(expr):
            return
        else:
            heap.update_assignment_aliases(procedure, targets, expr)
        self._site_counter = heap.next_site

    def _locations_for_local(
        self, procedure: cfg_graph.Code, local: object
    ) -> tuple[object, ...]:
        heap = self._heap()
        locations = heap.locations_for_local(procedure, local)
        self._site_counter = heap.next_site
        return locations

    def _locations_for_local_raw(
        self, procedure: cfg_graph.Code, local: object
    ) -> tuple[object, ...]:
        code = getattr(procedure, "code", None)
        if code is None:
            return ()
        catalog = ensure_code_indexed(code)
        if not catalog.has_symbol(local, code):
            return ()
        return (LocalStorage(catalog.symbol_id(local, code)),)

    def _semantic_locations(
        self,
        procedure: cfg_graph.Code | None,
        operation: object,
        attribute: str,
    ) -> tuple[object, ...]:
        code = getattr(procedure, "code", None) if procedure is not None else None
        if code is None:
            return ()
        catalog = ensure_code_indexed(code)
        try:
            semantics = catalog.semantics.operation(
                catalog.node_id(operation, code)
            )
        except KeyError:
            return ()
        return tuple(
            self._heap().location_for_raw(location)
            for location in getattr(semantics, attribute)
        )

    @abstractmethod
    def _make_location_fact(
        self, location: object, template_fact: FactT | None = None
    ) -> FactT:
        raise NotImplementedError

    @abstractmethod
    def _make_expression_fact(
        self,
        procedure: cfg_graph.Code,
        expression: py_ast.PythonASTNode,
        result_index: int = 0,
        template_fact: FactT | None = None,
    ) -> FactT:
        raise NotImplementedError

    @abstractmethod
    def _location_from_fact(self, fact: FactT) -> object | None:
        raise NotImplementedError

    def _access_path_from_fact(self, fact: FactT) -> tuple[str, ...]:
        return getattr(fact, "access_path", ())

    @staticmethod
    def _fact_prefix_matches(stored: object, query: object) -> bool:
        """True when *stored* implies *query* via access-path prefix."""
        return HeapAbstraction.access_path_prefix_matches(stored, query)

    def _make_location_fact_with_path(
        self,
        location: object,
        access_path: tuple[str, ...],
        template_fact: FactT | None = None,
    ) -> FactT:
        return self._make_location_fact(location, template_fact)

    @abstractmethod
    def _expression_fact_result(
        self, fact: FactT
    ) -> tuple[cfg_graph.Code, py_ast.PythonASTNode, int] | None:
        raise NotImplementedError

    def local_locations(
        self, procedure: cfg_graph.Code, local: py_ast.Local
    ) -> tuple[object, ...]:
        return tuple(
            self._location_from_fact(fact)
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

    def _heap_effect_builder(self) -> HeapEffectBuilder:
        return HeapEffectBuilder(self._heap(), self._locations_read_by_node)

    def _heap_effect_for_operation(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> HeapEffect:
        return (
            self._heap_effect_builder()
            .operation_semantics(
                procedure,
                operation,
                collection_mutator_names=self._collection_mutator_names(),
            )
            .effect
        )

    def _heap_summary_for_procedure(self, procedure: cfg_graph.Code) -> HeapSummary:
        key = procedure
        summaries = getattr(self, "_heap_summaries", None)
        if summaries is None:
            summaries = {}
            self._heap_summaries = summaries
        summary = summaries.get(key)
        if summary is None:
            flow_sensitive_summary = self.adapter.procedure_heap_summary(procedure)
            summary = getattr(flow_sensitive_summary, "effects", None)
            if not isinstance(summary, HeapSummary):
                summary = HeapSummaryBuilder(
                    self._heap_effect_builder(),
                    collection_mutator_names=self._collection_mutator_names(),
                ).summarize(procedure)
            summaries[key] = summary
        return summary

    def _killed_locations_for_node(
        self,
        node: CFGNode,
        *,
        include_semantic: bool = True,
    ) -> tuple[object, ...]:
        effect = self.adapter.effect_of(node)
        operation = getattr(effect, "operation", self.adapter.operation_of(node))
        if include_semantic:
            self._mark_escaped_values_for_operation(node.procedure, operation)
        semantic_kills = (
            self._killed_locations_for_operation(node.procedure, operation)
            if include_semantic
            else ()
        )
        strong_dynamic_kills = (
            self._strong_dynamic_write_locations_for_operation(
                node.procedure, operation
            )
            if include_semantic
            else ()
        )
        dynamic_kills = self._dynamic_delete_locations(node.procedure, operation)
        strong_update_slots = getattr(effect, "strong_update_slots", None)
        if strong_update_slots:
            kills = tuple(
                dict.fromkeys(
                    (
                        *self._canonical_locations(strong_update_slots),
                        *semantic_kills,
                        *strong_dynamic_kills,
                        *dynamic_kills,
                    )
                )
            )
        else:
            kill_slots = getattr(effect, "kill_slots", None)
            if kill_slots:
                kills = tuple(
                    dict.fromkeys(
                        (
                            *self._canonical_locations(kill_slots),
                            *semantic_kills,
                            *strong_dynamic_kills,
                            *dynamic_kills,
                        )
                    )
                )
            else:
                kills = tuple(
                    dict.fromkeys(
                        (*semantic_kills, *strong_dynamic_kills, *dynamic_kills)
                    )
                )
        return self._expand_kills_through_aliases(kills)

    def _expand_kills_through_aliases(
        self, kills: tuple[object, ...]
    ) -> tuple[object, ...]:
        heap = self._heap()
        expanded: list[object] = list(kills)
        seen: set[object] = set(kills)
        for kill in kills:
            if not isinstance(kill, HeapLocation):
                continue
            if kill.is_nested():
                continue
            for aliased in heap.aliased_locations(kill):
                if aliased not in seen:
                    seen.add(aliased)
                    expanded.append(aliased)
        return tuple(expanded)

    def _mark_escaped_values_for_operation(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> None:
        if operation is None or not self._heap().policy.track_escapes:
            return
        self._heap().mark_all_escaped(
            self._heap_effect_for_operation(procedure, operation).escapes
        )

    def _mark_unresolved_call_arguments_escaped(
        self,
        node: CFGNode,
        call_expression: py_ast.PythonASTNode | None,
    ) -> None:
        """Mark arguments passed to no-body calls as escaped."""
        heap = self._heap()
        if (
            call_expression is None
            or not heap.policy.track_escapes
            or not heap.policy.escape_on_unresolved_call
        ):
            return
        call_effect = self._call_effect(node)
        if call_effect is None or call_effect.callees:
            return

        effect = self._heap_effect_builder().unresolved_call_effect(
            node.procedure,
            call_expression,
        )
        heap.mark_all_escaped(effect.escapes)

    def _bind_callee_formals(self, call_node: CFGNode, callee: cfg_graph.Code) -> None:
        """Bind callee parameters to caller heap roots before call-flow queries."""
        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return
        self._materialize_call_result_location(
            call_node.procedure,
            call_effect.operation if call_effect is not None else None,
            call,
            0,
        )
        heap = self._heap()
        formals = formal_parameters(callee.code.codeparameters)
        formal_indices = {formal: index for index, formal in enumerate(formals)}
        bound_formals: set[py_ast.Local] = set()
        for actual, formal in self._bind_call_arguments_for_callee(call_node, callee):
            actual_locations = tuple(
                location
                for location in self._locations_read_by_node(
                    call_node.procedure, actual
                )
                if location is not None
            )
            heap.bind_parameter(
                callee,
                formal,
                formal_indices.get(formal, 0),
                actual_locations,
            )
            bound_formals.add(formal)
        self._bind_constructor_self_formal(call_node, callee, bound_formals)
        self._site_counter = heap.next_site

    def _bind_call_arguments_for_callee(
        self,
        call_node: CFGNode,
        callee: cfg_graph.Code,
    ) -> tuple[tuple[object, py_ast.Local], ...]:
        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return ()
        params = callee.code.codeparameters
        if self._should_bind_constructor_self_to_result(call_node, callee):
            params = py_ast.CodeParameters(
                selfparam=None,
                posonlyparams=params.posonlyparams,
                posonlynames=params.posonlynames,
                params=params.params,
                paramnames=params.paramnames,
                defaults=params.defaults,
                vparam=params.vparam,
                kparam=params.kparam,
                returnparams=params.returnparams,
                type_params=getattr(params, "type_params", None),
            )
        return bind_call_arguments(call, params)

    def _should_bind_constructor_self_to_result(
        self,
        call_node: CFGNode,
        callee: cfg_graph.Code,
    ) -> bool:
        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return False
        selfparam = getattr(callee.code.codeparameters, "selfparam", None)
        if not isinstance(selfparam, py_ast.Local):
            return False
        if getattr(call, "selfarg", None) is not None:
            return False
        return self._heap_effect_builder().call_return_kind(call) in {
            CALL_RETURN_FRESH,
            CALL_RETURN_COPY,
        }

    def _bind_constructor_self_formal(
        self,
        call_node: CFGNode,
        callee: cfg_graph.Code,
        bound_formals: set[py_ast.Local],
    ) -> None:
        """Bind an unbound constructor ``self`` formal to the fresh call result."""
        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return
        selfparam = getattr(callee.code.codeparameters, "selfparam", None)
        if not isinstance(selfparam, py_ast.Local) or selfparam in bound_formals:
            return
        builder = self._heap_effect_builder()
        if not self._should_bind_constructor_self_to_result(call_node, callee):
            return
        obj = builder.call_return_object(
            call_node.procedure,
            call,
            label=self._call_result_label(call),
        )
        self._heap().bind_local_to_object(
            callee,
            selfparam,
            obj,
            include_provider_storage=True,
        )

    def _project_constructor_heap_fact_to_caller(
        self,
        call_node: CFGNode,
        exit_fact: FactT,
    ) -> FactT | None:
        """Keep facts written through constructor self on the caller result root."""
        location = self._location_from_fact(exit_fact)
        if not isinstance(location, HeapLocation):
            return None
        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return None
        builder = self._heap_effect_builder()
        if builder.call_return_kind(call) not in {CALL_RETURN_FRESH, CALL_RETURN_COPY}:
            return None
        result = HeapLocation(
            builder.call_return_object(
                call_node.procedure,
                call,
                label=self._call_result_label(call),
            )
        )
        if location.root != result.root:
            return None
        return exit_fact

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
        self,
        procedure: cfg_graph.Code,
        locals_: Iterable[object],
        template_fact: FactT | None = None,
    ) -> set[FactT]:
        facts: set[FactT] = set()
        for local in locals_:
            if not isinstance(local, py_ast.Local) or local.name is None:
                continue
            locations = self._locations_for_local(procedure, local)
            facts.update(
                self._make_location_fact(location, template_fact)
                for location in locations
            )
        return facts

    def _facts_for_locals_with_path(
        self,
        procedure: cfg_graph.Code,
        locals_: Iterable[object],
        access_path: tuple[str, ...],
        template_fact: FactT | None = None,
    ) -> set[FactT]:
        facts: set[FactT] = set()
        for local in locals_:
            if not isinstance(local, py_ast.Local) or local.name is None:
                continue
            locations = self._locations_for_local(procedure, local)
            facts.update(
                self._make_location_fact_with_path(location, access_path, template_fact)
                for location in locations
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
        template_fact: FactT | None = None,
    ) -> set[FactT]:
        if result_index >= len(locals_):
            return set()
        return self._facts_for_locals(
            procedure, (locals_[result_index],), template_fact
        )

    def _facts_for_return_location(
        self,
        procedure: cfg_graph.Code,
        index: int,
        access_path: tuple[str, ...] = (),
        template_fact: FactT | None = None,
    ) -> set[FactT]:
        returnparams = tuple(procedure.code.codeparameters.returnparams)
        if index >= len(returnparams):
            return set()
        if not access_path:
            return self._facts_for_locals(
                procedure, (returnparams[index],), template_fact
            )
        return self._facts_for_locals_with_path(
            procedure,
            (returnparams[index],),
            access_path,
            template_fact,
        )

    def _facts_for_expression_node(
        self,
        procedure: cfg_graph.Code,
        current: object,
        extend_paths: bool = False,
        template_fact: FactT | None = None,
    ) -> tuple[FactT, ...]:
        if current is None or isinstance(current, py_ast.leafTypes):
            return ()
        if extend_paths and isinstance(current, py_ast.GetAttr):
            attr = self._path_component(current.name)
            base = self._facts_for_expression_node(
                procedure,
                current.expr,
                extend_paths=True,
                template_fact=template_fact,
            )
            return tuple(
                self._make_location_fact_with_path(
                    self._location_from_fact(f),
                    (*self._access_path_from_fact(f), attr),
                    template_fact,
                )
                for f in base
                if self._location_from_fact(f) is not None
            )
        if isinstance(current, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            dynamic_facts = tuple(
                self._make_location_fact(location, template_fact)
                for location in (
                    *self._dynamic_getattr_locations(procedure, current),
                    *self._dynamic_subscript_read_locations(procedure, current),
                    *self._collection_access_locations(
                        procedure,
                        current,
                        self._collection_accessor_names(),
                    ),
                )
            )
            return (
                *dynamic_facts,
                self._make_expression_fact(
                    procedure, current, template_fact=template_fact
                ),
            )
        return tuple(
            self._make_location_fact(location, template_fact)
            for location in self._locations_read_by_node(procedure, current)
        )

    def _facts_for_nested_call_result(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        call_expression: py_ast.PythonASTNode | None,
        return_index: int,
        *,
        nested: bool,
        template_fact: FactT | None = None,
    ) -> set[FactT]:
        if operation is None or call_expression is None:
            return set()
        self._materialize_call_result_location(
            procedure,
            operation,
            call_expression,
            return_index,
        )

        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
            if not nested:
                facts = {
                    self._make_expression_fact(
                        procedure,
                        call_expression,
                        return_index,
                        template_fact,
                    )
                }
                if self._heap().policy.bind_call_results:
                    facts.update(
                        self._facts_for_assigned_locals(
                            procedure,
                            assigned_locals(operation),
                            return_index,
                            template_fact,
                        )
                    )
                return facts
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                return_index,
                template_fact,
            )
        if (
            isinstance(operation, py_ast.AnnAssign)
            and operation.value is call_expression
        ):
            if not nested:
                facts = {
                    self._make_expression_fact(
                        procedure,
                        call_expression,
                        return_index,
                        template_fact,
                    )
                }
                if self._heap().policy.bind_call_results:
                    facts.update(
                        self._facts_for_assigned_locals(
                            procedure,
                            assigned_locals(operation),
                            return_index,
                            template_fact,
                        )
                    )
                return facts
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                return_index,
                template_fact,
            )

        if isinstance(operation, py_ast.Return):
            if not nested:
                return {
                    self._make_expression_fact(
                        procedure,
                        call_expression,
                        return_index,
                        template_fact,
                    )
                }
            target_index = self._call_result_target_index(
                operation, call_expression, return_index
            )
            if target_index is not None:
                return self._facts_for_return_location(
                    procedure, target_index, template_fact=template_fact
                )

        if (
            isinstance(
                operation,
                (
                    py_ast.SetAttr,
                    py_ast.SetSubscript,
                    py_ast.SetSlice,
                    py_ast.SetGlobal,
                    py_ast.SetCellDeref,
                    py_ast.Store,
                ),
            )
            and getattr(operation, "value", None) is call_expression
        ):
            if not nested:
                return {
                    self._make_expression_fact(
                        procedure,
                        call_expression,
                        return_index,
                        template_fact,
                    )
                }
            return self._facts_for_modified_operation(
                operation,
                procedure=procedure,
                template_fact=template_fact,
            )

        for child in self._nested_operations(operation):
            child_result = self._facts_for_nested_call_result(
                procedure,
                child,
                call_expression,
                return_index,
                nested=True,
                template_fact=template_fact,
            )
            if child_result:
                return child_result

        return {
            self._make_expression_fact(
                procedure, call_expression, return_index, template_fact
            )
        }

    def _materialize_call_result_location(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        call_expression: py_ast.PythonASTNode | None,
        return_index: int,
    ) -> None:
        """Bind direct call-assignment targets to fixed call-result roots."""
        if call_expression is None or not self._heap().policy.bind_call_results:
            return
        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
            targets = assigned_locals(operation)
        elif (
            isinstance(operation, py_ast.AnnAssign)
            and operation.value is call_expression
        ):
            targets = assigned_locals(operation)
        else:
            return
        if return_index >= len(targets):
            return
        target = targets[return_index]
        if not isinstance(target, py_ast.Local) or target.name is None:
            return
        self._bind_call_return_target(
            procedure,
            target,
            call_expression,
            return_index,
            default_to_summary=False,
        )

    def _bind_call_return_target(
        self,
        procedure: cfg_graph.Code,
        target: py_ast.Local,
        call_expression: py_ast.PythonASTNode,
        return_index: int,
        *,
        default_to_summary: bool,
    ) -> None:
        heap = self._heap()
        builder = self._heap_effect_builder()
        model = self.call_models.model_for_name(
            self.adapter.call_name(call_expression, procedure)
        )
        kind = (
            model.return_kind
            if model is not None and model.return_kind is not None
            else (
                CALL_RETURN_FRESH
                if model is not None and model.source_kinds
                else builder.call_return_kind(call_expression)
            )
        )
        site = builder.call_return_site(call_expression, return_index, kind)
        label = self._call_result_label(call_expression)
        if kind in {CALL_RETURN_FRESH, CALL_RETURN_COPY}:
            heap.bind_fresh_return_targets(procedure, (target,), site, label=label)
        elif kind == CALL_RETURN_SUMMARY or default_to_summary:
            heap.bind_summary_targets(procedure, (target,), site, label=label)
        elif kind == CALL_RETURN_OPAQUE:
            # A resolved opaque call must not eagerly sever the target's
            # current binding: call/return flow will project the actual return
            # facts.  Truly unresolved calls are materialized separately as
            # summaries by ``_materialize_unresolved_call_summary``.
            return
        self._site_counter = heap.next_site

    def _materialize_unresolved_call_summary(
        self,
        node: CFGNode,
        operation: object,
        call_expression: py_ast.PythonASTNode | None,
    ) -> None:
        """Bind no-body call assignment targets to a fixed summary object."""
        call_effect = self._call_effect(node)
        if (
            call_expression is None
            or not self._heap().policy.bind_call_results
            or call_effect is None
            or call_effect.callees
        ):
            return
        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
            targets = assigned_locals(operation)
        elif (
            isinstance(operation, py_ast.AnnAssign)
            and operation.value is call_expression
        ):
            targets = assigned_locals(operation)
        else:
            return
        for index, target in enumerate(targets):
            if not isinstance(target, py_ast.Local) or target.name is None:
                continue
            self._bind_call_return_target(
                node.procedure,
                target,
                call_expression,
                index,
                default_to_summary=True,
            )

    def _return_fact_index(self, procedure: cfg_graph.Code, fact: FactT) -> int | None:
        location = self._location_from_fact(fact)
        if location is None:
            return None
        for index, local in enumerate(procedure.code.codeparameters.returnparams):
            if any(
                candidate == location
                for candidate in self._locations_for_local(procedure, local)
            ):
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

    def _killed_locations_for_operation(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[object, ...]:
        if operation is None:
            return ()
        if isinstance(
            operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)
        ):
            return tuple(
                location
                for fact in self._facts_for_locals(
                    procedure, assigned_locals(operation)
                )
                for location in (self._location_from_fact(fact),)
                if location is not None
            )
        if isinstance(operation, py_ast.Delete):
            return tuple(
                location
                for fact in self._facts_for_locals(procedure, (operation.lcl,))
                for location in (self._location_from_fact(fact),)
                if location is not None
            )
        if isinstance(operation, py_ast.InputBlock):
            locals_ = []
            for input_ in getattr(operation, "inputs", ()):
                lcl = getattr(input_, "lcl", None)
                if isinstance(lcl, py_ast.Local):
                    locals_.append(lcl)
            return tuple(
                location
                for fact in self._facts_for_locals(procedure, locals_)
                for location in (self._location_from_fact(fact),)
                if location is not None
            )
        if isinstance(
            operation,
            (py_ast.SetGlobal, py_ast.DeleteGlobal, py_ast.SetCellDeref),
        ):
            return tuple(
                location
                for fact in self._facts_for_modified_operation(
                    operation,
                    procedure=procedure,
                )
                for location in (self._location_from_fact(fact),)
                if location is not None
            )
        return ()

    def _killed_locations_for_call_expression(
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
                location
                for fact in self._facts_for_locals(
                    procedure, assigned_locals(operation)
                )
                for location in (self._location_from_fact(fact),)
                if location is not None
            )
        if (
            isinstance(operation, py_ast.AnnAssign)
            and operation.value is call_expression
        ):
            return tuple(
                location
                for fact in self._facts_for_locals(
                    procedure, assigned_locals(operation)
                )
                for location in (self._location_from_fact(fact),)
                if location is not None
            )

        if (
            isinstance(operation, (py_ast.SetGlobal, py_ast.SetCellDeref))
            and operation.value is call_expression
        ):
            return tuple(
                location
                for fact in self._facts_for_modified_operation(
                    operation,
                    procedure=procedure,
                )
                for location in (self._location_from_fact(fact),)
                if location is not None
            )

        for child in self._nested_operations(operation):
            child_kills = self._killed_locations_for_call_expression(
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
        self,
        operation: object,
        access_path: tuple[str, ...] = (),
        *,
        procedure: cfg_graph.Code | None = None,
        template_fact: FactT | None = None,
    ) -> set[FactT]:
        locations = tuple(
            dict.fromkeys(
                (
                    *self._semantic_locations(procedure, operation, "writes"),
                    *self._static_attribute_write_locations(procedure, operation),
                )
            )
        )
        if not access_path:
            return {
                self._make_location_fact(location, template_fact)
                for location in locations
            }
        return {
            self._make_location_fact_with_path(location, access_path, template_fact)
            for location in locations
        }

    def _dynamic_getattr_locations(
        self, procedure: cfg_graph.Code, expr: object
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().dynamic_getattr_locations(procedure, expr)

    def _dynamic_setattr_locations(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().dynamic_setattr_locations(
            procedure,
            operation,
        )

    def _dynamic_attribute_locations(
        self,
        procedure: cfg_graph.Code,
        base_expr: object,
        attributes: tuple[str, ...],
    ) -> tuple[HeapLocation, ...]:
        return self._heap().dynamic_attribute_locations(
            self._locations_read_by_node(procedure, base_expr),
            attributes,
        )

    def _static_attribute_read_locations(
        self,
        procedure: cfg_graph.Code,
        expr: object,
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().static_attribute_read_locations(
            procedure,
            expr,
        )

    def _static_attribute_write_locations(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().static_attribute_write_locations(
            procedure,
            operation,
        )

    def _dynamic_subscript_read_locations(
        self, procedure: cfg_graph.Code, expr: object
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().dynamic_subscript_read_locations(
            procedure,
            expr,
        )

    def _dynamic_subscript_write_locations(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().dynamic_subscript_write_locations(
            procedure,
            operation,
        )

    def _dynamic_subscript_locations_for_key(
        self,
        procedure: cfg_graph.Code,
        container: object,
        key: object,
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().dynamic_subscript_locations_for_key(
            procedure,
            container,
            key,
        )

    def _dynamic_subscript_value(self, operation: object) -> object | None:
        return self._heap_effect_builder().dynamic_subscript_value(operation)

    def _dynamic_delete_locations(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[object, ...]:
        return self._heap_effect_for_operation(procedure, operation).deletes

    def _strong_dynamic_write_locations_for_operation(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        """Return dynamic write targets that are singleton enough to kill."""
        return self._heap_effect_for_operation(
            procedure,
            operation,
        ).strong_write_locations()

    def _dynamic_subscript_delete_locations(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().dynamic_subscript_delete_locations(
            procedure,
            operation,
        )

    def _dynamic_attribute_delete_locations(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().dynamic_attribute_delete_locations(
            procedure,
            operation,
        )

    def _dynamic_subscript_write_target(
        self, operation: object
    ) -> tuple[object, object, object] | None:
        return self._heap_effect_builder().dynamic_subscript_write_target(operation)

    def _dynamic_subscript_locations(
        self,
        procedure: cfg_graph.Code,
        base_expr: object,
        subscripts: tuple[str, ...],
    ) -> tuple[HeapLocation, ...]:
        return self._heap_effect_builder().dynamic_subscript_locations(
            procedure,
            base_expr,
            subscripts,
        )

    def _collection_mutation(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        mutator_names: frozenset[str],
    ) -> tuple[tuple[HeapLocation, ...], tuple[object, ...]]:
        return self._heap_effect_builder().collection_mutation(
            procedure,
            operation,
            mutator_names,
        )

    def _collection_copy_mutation(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        mutator_names: frozenset[str],
    ) -> tuple[tuple[HeapLocation, ...], tuple[HeapLocation, ...]]:
        call = self._call_from_expression_or_statement(operation)
        call_name = self.adapter.call_name(call, procedure) if call is not None else None
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

        destination_locations = self._dynamic_subscript_locations(
            procedure,
            container,
            (DYNAMIC_SUBSCRIPT_WILDCARD,),
        )
        source_locations = tuple(
            location
            for source in sources
            for location in self._dynamic_subscript_locations(
                procedure,
                source,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
        )
        return destination_locations, tuple(dict.fromkeys(source_locations))

    def _collection_constructor_writes(
        self,
        procedure: cfg_graph.Code,
        operation: object,
    ) -> tuple[tuple[tuple[HeapLocation, ...], object], ...]:
        expr = None
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            expr = operation.expr
        elif isinstance(operation, py_ast.AnnAssign):
            expr = operation.value
        if expr is None:
            return ()

        target_locations = tuple(
            location
            for target in assigned_locals(operation)
            for location in self._locations_for_local(procedure, target)
        )
        if not target_locations:
            return ()

        writes: list[tuple[tuple[HeapLocation, ...], object]] = []
        if isinstance(expr, py_ast.BuildTuple):
            for index, value in enumerate(expr.args):
                writes.append(
                    (
                        self._collection_constructor_locations(
                            target_locations,
                            (f"[{index!r}]", DYNAMIC_SUBSCRIPT_WILDCARD),
                        ),
                        value,
                    )
                )
        elif isinstance(expr, (py_ast.BuildList, py_ast.BuildSet)):
            for value in expr.args:
                writes.append(
                    (
                        self._collection_constructor_locations(
                            target_locations,
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
                        self._collection_constructor_locations(
                            target_locations, subscripts
                        ),
                        value,
                    )
                )
        return tuple(writes)

    def _collection_constructor_locations(
        self,
        bases: tuple[object, ...],
        subscripts: tuple[str, ...],
    ) -> tuple[HeapLocation, ...]:
        return self._heap().dynamic_subscript_locations(bases, subscripts)

    def _aliased_dynamic_locations_for_assignment(
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

        source_location = self._location_from_fact(fact)
        if (
            not isinstance(source_location, HeapLocation)
            or not source_location.is_nested()
        ):
            return ()

        expr_bases = self._locations_read_by_node(procedure, expr)
        if not any(base == source_location.root_location() for base in expr_bases):
            return ()

        target_bases = tuple(
            location
            for target in assigned_locals(operation)
            for location in self._locations_for_local(procedure, target)
        )
        return tuple(
            self._heap().extend_location(base, source_location.selectors)
            for base in target_bases
        )

    def _collection_copy_result_locations_for_assignment(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        fact: FactT,
    ) -> tuple[HeapLocation, ...]:
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            expr = operation.expr
        elif isinstance(operation, py_ast.AnnAssign):
            expr = operation.value
        else:
            return ()

        source_location = self._location_from_fact(fact)
        if not (
            isinstance(source_location, HeapLocation) and source_location.selectors
        ):
            return ()

        source_exprs = self._collection_copy_result_sources(procedure, expr)
        if not source_exprs:
            return ()
        source_roots = tuple(
            location
            for source_expr in source_exprs
            for location in self._locations_read_by_node(procedure, source_expr)
        )
        if not any(root == source_location.root_location() for root in source_roots):
            return ()

        target_bases = tuple(
            location
            for target in assigned_locals(operation)
            for location in self._locations_for_local(procedure, target)
        )
        return tuple(
            self._heap().extend_location(base, source_location.selectors)
            for base in target_bases
        )

    def _collection_copy_result_sources(
        self, procedure: cfg_graph.Code, expr: object
    ) -> tuple[object, ...]:
        call = self._call_from_expression_or_statement(expr)
        if call is None:
            return ()
        call_name = self.adapter.call_name(call, procedure)
        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall) and call_name == "copy":
            return (call.expr,)
        if call_name in {"copy", "list", "tuple", "set", "dict"} and actuals:
            return (actuals[0],)
        return ()

    def _collection_accessor_names(self) -> frozenset[str]:
        configuration = getattr(self, "configuration", None)
        return getattr(configuration, "collection_accessor_names", frozenset())

    def _collection_mutator_names(self) -> frozenset[str]:
        configuration = getattr(self, "configuration", None)
        return getattr(configuration, "collection_mutator_names", frozenset())

    def _collection_access_locations(
        self,
        procedure: cfg_graph.Code,
        expr: object,
        accessor_names: frozenset[str],
    ) -> tuple[HeapLocation, ...]:
        call = self._call_from_expression_or_statement(expr)
        if call is None or self.adapter.call_name(call, procedure) not in accessor_names:
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

        subscript = self._constant_subscript(key) if key is not None else None
        subscripts = (DYNAMIC_SUBSCRIPT_WILDCARD,)
        if subscript is not None:
            subscripts = (subscript, DYNAMIC_SUBSCRIPT_WILDCARD)
        return self._dynamic_subscript_locations(procedure, container, subscripts)

    def _dynamic_setattr_value(
        self, procedure: cfg_graph.Code, operation: object
    ) -> object | None:
        call = self._dynamic_attribute_call(
            procedure, operation, {"setattr", "builtins.setattr"}
        )
        if call is None:
            return None
        actuals = actual_argument_expressions(call)
        if len(actuals) < 3:
            return None
        return actuals[2]

    def _dynamic_attribute_call(
        self, procedure: cfg_graph.Code, expr: object, names: set[str]
    ) -> py_ast.PythonASTNode | None:
        candidate = self._call_from_expression_or_statement(expr)
        if candidate is None:
            return None
        if self.adapter.call_name(candidate, procedure) not in names:
            return None
        return candidate

    def _call_from_expression_or_statement(
        self, expr: object
    ) -> py_ast.PythonASTNode | None:
        candidate = expr
        if not isinstance(
            candidate, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)
        ):
            wrapped = getattr(expr, "expr", None)
            if isinstance(wrapped, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
                candidate = wrapped
        if not isinstance(
            candidate, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)
        ):
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

    def _locations_read_by_node(
        self, procedure: cfg_graph.Code, node: object
    ) -> tuple[object, ...]:
        if isinstance(node, py_ast.Local):
            return self._locations_for_local(procedure, node)
        locations = list(self._semantic_locations(procedure, node, "reads"))
        locations.extend(self._static_attribute_read_locations(procedure, node))
        locations.extend(self._dynamic_getattr_locations(procedure, node))
        locations.extend(self._dynamic_subscript_read_locations(procedure, node))
        return tuple(dict.fromkeys(locations))

    def _canonical_location(self, location: object) -> object:
        return self._heap().location_for_raw(location)

    def _canonical_locations(
        self, locations: Iterable[object]
    ) -> tuple[HeapLocation, ...]:
        return tuple(self._heap().location_for_raw(location) for location in locations)

    def _call_name(self, node: CFGNode) -> str | None:
        call = self.adapter.call_expression_of(node)
        return self.adapter.call_name(call, node.procedure)

    def _call_name_from_expression(self, expr: object) -> str | None:
        if isinstance(expr, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            return self.adapter.call_name(expr)
        if isinstance(expr, (py_ast.GetAttr, py_ast.Load)):
            base = self._symbolic_expression_name(expr.expr)
            component = self._path_component(expr.name)
            if base and component != "*":
                return f"{base}.{component}"
        return None

    def _symbolic_expression_name(self, expr: object) -> str | None:
        """Return a qualified spelling for a static attribute expression."""
        if isinstance(expr, py_ast.Local) and expr.name:
            return expr.name
        if isinstance(expr, py_ast.GetGlobal):
            return self._global_name(expr.name)
        if isinstance(expr, (py_ast.GetAttr, py_ast.Load)):
            base = self._symbolic_expression_name(expr.expr)
            component = self._path_component(expr.name)
            if base and component != "*":
                return f"{base}.{component}"
        return None

    def _is_allocation_expression(self, expr: object) -> bool:
        return isinstance(
            expr,
            (
                py_ast.BuildTuple,
                py_ast.BuildList,
                py_ast.BuildSet,
                py_ast.BuildMap,
            ),
        )

    def _is_call_expression(self, expr: object) -> bool:
        return isinstance(expr, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall))

    def _allocation_label(self, expr: object) -> str:
        if isinstance(expr, py_ast.BuildTuple):
            return "tuple literal"
        if isinstance(expr, py_ast.BuildList):
            return "list literal"
        if isinstance(expr, py_ast.BuildSet):
            return "set literal"
        if isinstance(expr, py_ast.BuildMap):
            return "dict literal"
        return f"allocation:{type(expr).__name__}"

    def _allocation_type_hint(self, expr: object) -> str | None:
        if isinstance(expr, py_ast.BuildTuple):
            return "tuple"
        if isinstance(expr, py_ast.BuildList):
            return "list"
        if isinstance(expr, py_ast.BuildSet):
            return "set"
        if isinstance(expr, py_ast.BuildMap):
            return "dict"
        return None

    def _call_result_label(self, expr: object) -> str:
        call_name = self._call_name_from_expression(expr)
        if call_name is not None:
            return f"{call_name}()"
        return f"call:{type(expr).__name__}"

    def describe_location(self, location: object) -> str:
        if isinstance(location, HeapLocation):
            return self._heap().display_label_for_location(location)
        label = getattr(location, "label", None)
        if isinstance(label, str):
            return label
        slot_name = getattr(location, "slotName", None)
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
        return repr(location)

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

    def _require_semantics(self) -> None:
        problems: list[str] = []
        for cfg in self.adapter.cfgs:
            code = getattr(cfg, "code", None)
            if code is None:
                continue
            catalog = self.adapter.catalog_by_procedure[cfg]
            for cfg_node in self.adapter.supergraph.nodes_of(cfg):
                operation = self.adapter.operation_of(cfg_node)
                if operation is None:
                    continue
                try:
                    catalog.semantics.operation(catalog.node_id(operation, code))
                except KeyError:
                    problems.append(
                        f"{code.codeName()}: {type(operation).__name__} missing semantics"
                    )
                    break

        if problems:
            raise TemporaryLimitation(
                f"{self.analysis_name} requires indexed IR semantics: "
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
