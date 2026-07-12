"""Standalone heap transfer engine.

This module applies operation-level heap effects to :class:`HeapAbstraction`.
It intentionally stays conservative: unresolved calls escape their arguments,
unknown assigned values break precise local aliases, and modeled constructors
or collection literals allocate fresh heap roots.
"""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.ir_utils import (
    actual_argument_expressions,
    assigned_locals,
)
from pyflow.language.python import ast as py_ast

from .abstraction import HeapAbstraction
from .heap_effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_OPAQUE,
    CALL_RETURN_SUMMARY,
    DEFAULT_HEAP_INTRINSICS,
    DYNAMIC_SUBSCRIPT_WILDCARD,
    HeapEffectBuilder,
)
from .heap_state import HeapState
from .intrinsics import HeapIntrinsicModels
from .model import HeapLocation, HeapObjectKind
from .model import UpdatePolicy


@dataclass(frozen=True)
class _CallSummary:
    state: HeapState
    returns: tuple[HeapLocation, ...]
    deletes: tuple[HeapLocation, ...] = ()


class HeapTransferEngine:
    """Apply Python IR operations to a heap abstraction."""

    def __init__(
        self,
        heap: HeapAbstraction,
        *,
        intrinsics: HeapIntrinsicModels = DEFAULT_HEAP_INTRINSICS,
        collection_mutator_names: frozenset[str] | None = None,
        max_loop_iterations: int = 8,
    ) -> None:
        self.heap = heap
        self.intrinsics = intrinsics
        self.collection_mutator_names = (
            collection_mutator_names
            if collection_mutator_names is not None
            else intrinsics.collection_mutator_names()
        )
        self.max_loop_iterations = max_loop_iterations
        self.effect_builder = HeapEffectBuilder(
            heap,
            self.locations_for_expression,
            intrinsics=intrinsics,
        )
        self._active_codes: set[int] = set()
        self._summary_cache: dict[object, _CallSummary] = {}
        self._summary_in_progress: set[object] = set()
        self._summary_delete_stack: list[list[HeapLocation]] = []
        self.state = HeapState()

    def analyze_program(self, program: object) -> None:
        """Analyze every discoverable code object in *program*."""
        for code in self.iter_code_objects(program):
            self.analyze_code(code)

    def analyze_code(self, code: object) -> None:
        """Analyze one ``py_ast.Code`` or code-like object."""
        code_id = id(code)
        if code_id in self._active_codes:
            return
        self._active_codes.add(code_id)
        self.bind_parameters(code)
        try:
            self.analyze_node(code, getattr(code, "ast", None))
        finally:
            self._active_codes.discard(code_id)

    def analyze_node(self, procedure: object, node: object) -> None:
        if node is None or isinstance(node, py_ast.leafTypes):
            return
        if isinstance(node, py_ast.Code):
            self.analyze_node(node, node.ast)
            return
        if isinstance(node, py_ast.Suite):
            for block in node.blocks:
                self.analyze_node(procedure, block)
            return
        if isinstance(node, py_ast.Switch):
            self._analyze_switch(procedure, node)
            return
        if isinstance(node, py_ast.While):
            self._analyze_while(procedure, node)
            return
        if isinstance(node, py_ast.For):
            self._analyze_for(procedure, node)
            return
        if isinstance(node, py_ast.TryExceptFinally):
            self._analyze_try_except_finally(procedure, node)
            return
        if isinstance(node, py_ast.Condition):
            self.analyze_node(procedure, node.preamble)
            return
        if isinstance(node, py_ast.PythonASTNode):
            self.apply_operation(procedure, node)

    def bind_parameters(self, procedure: object) -> None:
        code_parameters = getattr(procedure, "codeparameters", None)
        if code_parameters is None:
            return
        parameters = []
        selfparam = getattr(code_parameters, "selfparam", None)
        if isinstance(selfparam, py_ast.Local):
            parameters.append(selfparam)
        parameters.extend(
            param
            for param in getattr(code_parameters, "posonlyparams", ())
            if isinstance(param, py_ast.Local)
        )
        parameters.extend(
            param
            for param in getattr(code_parameters, "params", ())
            if isinstance(param, py_ast.Local)
        )
        vparam = getattr(code_parameters, "vparam", None)
        kparam = getattr(code_parameters, "kparam", None)
        if isinstance(vparam, py_ast.Local):
            parameters.append(vparam)
        if isinstance(kparam, py_ast.Local):
            parameters.append(kparam)
        for index, formal in enumerate(dict.fromkeys(parameters)):
            if not self.heap.locations_for_local(procedure, formal):
                self.heap.bind_parameter(procedure, formal, index, ())

    def apply_operation(self, procedure: object, operation: object) -> None:
        """Apply the heap transfer for one operation."""
        self._materialize_assignment_result(procedure, operation)
        effect = self.effect_builder.operation_effect(
            procedure,
            operation,
            collection_mutator_names=self.collection_mutator_names,
        )
        self._apply_writes(procedure, operation, effect.writes)
        self._record_summary_deletes(effect.deletes)
        self._apply_deletes(effect.deletes)
        self.heap.mark_all_escaped(effect.escapes)
        self.state.mark_escaped(effect.escapes)
        if isinstance(operation, py_ast.Return):
            self._materialize_return_values(procedure, effect.returns)
        self._apply_call_transfer(procedure, operation)
        self._materialize_collection_literal_values(procedure, operation)

    def locations_for_expression(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        """Best-effort locations read by an expression."""
        if expression is None:
            return ()
        if isinstance(expression, HeapLocation):
            return (expression,)
        if isinstance(expression, py_ast.Local):
            locations = self.heap.locations_for_local(procedure, expression)
            if locations:
                return locations
            obj = self.heap.local_object(procedure, expression)
            self.heap.bind_local_to_object(procedure, expression, obj)
            return self.heap.locations_for_local(procedure, expression)
        if isinstance(expression, py_ast.GetGlobal):
            location = self.effect_builder.global_location(procedure, expression.name)
            return self.state.read(location)
        if isinstance(expression, (py_ast.GetCell, py_ast.GetCellDeref)):
            location = self.effect_builder.cell_location(expression.cell)
            return self.state.read(location)
        if isinstance(expression, py_ast.GetAttr):
            attribute = self.effect_builder._path_component(expression.name)
            locations = self.heap.dynamic_attribute_locations(
                self.locations_for_expression(procedure, expression.expr),
                (attribute,),
            )
            return self.state.read_many(locations)
        if isinstance(expression, py_ast.GetSubscript):
            subscript = self.effect_builder._constant_subscript(expression.subscript)
            subscripts = (DYNAMIC_SUBSCRIPT_WILDCARD,)
            if subscript is not None:
                subscripts = (subscript, DYNAMIC_SUBSCRIPT_WILDCARD)
            locations = self.heap.dynamic_subscript_locations(
                self.locations_for_expression(procedure, expression.expr),
                subscripts,
            )
            return self.state.read_many(locations)
        if isinstance(expression, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return (
                HeapLocation(
                    self.effect_builder.call_return_object(procedure, expression)
                ),
            )
        return ()

    @classmethod
    def iter_code_objects(cls, root: object):
        """Yield code objects reachable from *root* without recursing into bodies."""
        seen: set[int] = set()

        def visit(value: object):
            if value is None or isinstance(value, py_ast.leafTypes):
                return
            if isinstance(value, py_ast.Code):
                key = id(value)
                if key not in seen:
                    seen.add(key)
                    yield value
                return
            if isinstance(value, (list, tuple, set, frozenset)):
                for item in value:
                    yield from visit(item)
                return
            for attr in ("liveCode", "entryPoints", "codes", "procedures", "functions"):
                child = getattr(value, attr, None)
                if child is not None:
                    yield from visit(child)
            code = getattr(value, "code", None)
            if code is not value:
                yield from visit(code)

        yield from visit(root)

    @classmethod
    def iter_operations(cls, node: object):
        """Yield operation nodes inside a code body."""
        if node is None or isinstance(node, py_ast.leafTypes):
            return
        if isinstance(node, py_ast.Code):
            return
        if isinstance(node, py_ast.Suite):
            for block in node.blocks:
                yield from cls.iter_operations(block)
            return
        if isinstance(node, py_ast.PythonASTNode):
            yield node
            if hasattr(node, "visitChildren"):
                children: list[object] = []
                node.visitChildren(children.append)
                for child in children:
                    yield from cls.iter_operations(child)

    def _analyze_switch(self, procedure: object, node: py_ast.Switch) -> None:
        self.analyze_node(procedure, node.condition)
        base = self.state.copy()
        true_state = self._state_after(procedure, node.t, base)
        false_state = self._state_after(procedure, node.f, base)
        self.state = true_state.join(false_state)

    def _analyze_while(self, procedure: object, node: py_ast.While) -> None:
        self.analyze_node(procedure, node.condition)
        entry = self.state.copy()
        current = entry.copy()
        for _ in range(self.max_loop_iterations):
            body_state = self._state_after(procedure, node.body, current)
            next_state = entry.join(body_state)
            if next_state.equivalent(current):
                current = next_state
                break
            current = next_state
        self.state = current
        self.analyze_node(procedure, node.else_)

    def _analyze_for(self, procedure: object, node: py_ast.For) -> None:
        self.analyze_node(procedure, node.loopPreamble)
        self.locations_for_expression(procedure, node.iterator)
        entry = self.state.copy()
        current = entry.copy()
        for _ in range(self.max_loop_iterations):
            body_state = current.copy()
            self.state = body_state
            self.analyze_node(procedure, node.bodyPreamble)
            self.analyze_node(procedure, node.body)
            body_state = self.state
            next_state = entry.join(body_state)
            if next_state.equivalent(current):
                current = next_state
                break
            current = next_state
        self.state = current
        self.analyze_node(procedure, node.else_)

    def _analyze_try_except_finally(
        self,
        procedure: object,
        node: py_ast.TryExceptFinally,
    ) -> None:
        base = self.state.copy()
        states = [self._state_after(procedure, node.body, base)]
        for handler in getattr(node, "handlers", ()):
            handler_state = base.copy()
            self.state = handler_state
            self.analyze_node(procedure, getattr(handler, "preamble", None))
            self.analyze_node(procedure, getattr(handler, "body", None))
            states.append(self.state)
        default_handler = getattr(node, "defaultHandler", None)
        if default_handler is not None:
            states.append(self._state_after(procedure, default_handler, base))
        else_suite = getattr(node, "else_", None)
        if else_suite is not None:
            states.append(self._state_after(procedure, else_suite, states[0]))
        joined = states[0]
        for state in states[1:]:
            joined = joined.join(state)
        self.state = joined
        self.analyze_node(procedure, getattr(node, "finally_", None))

    def _state_after(
        self,
        procedure: object,
        node: object,
        state: HeapState,
    ) -> HeapState:
        previous = self.state
        self.state = state.copy()
        self.analyze_node(procedure, node)
        result = self.state
        self.state = previous
        return result

    def _materialize_assignment_result(
        self, procedure: object, operation: object
    ) -> None:
        targets = assigned_locals(operation)
        if not targets:
            return
        expr = self._assigned_expression(operation)
        if isinstance(
            expr,
            (py_ast.BuildTuple, py_ast.BuildList, py_ast.BuildSet, py_ast.BuildMap),
        ):
            self.heap.bind_allocation_targets(
                procedure,
                targets,
                expr,
                label=self.effect_builder._allocation_label(expr),
            )
            return
        if isinstance(expr, py_ast.Import):
            module = self.effect_builder.import_object(expr)
            for target in targets:
                self.heap.bind_local_to_object(
                    procedure,
                    target,
                    module,
                    include_raw_fallback=True,
                )
            return
        if isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            self._bind_call_result_targets(procedure, targets, expr)
            return
        if expr is not None and not isinstance(expr, py_ast.Local):
            expr_locations = self.locations_for_expression(procedure, expr)
            if expr_locations:
                for target in targets:
                    self.heap.bind_local_to_locations(
                        procedure,
                        target,
                        expr_locations,
                    )
                return
        self.heap.update_assignment_aliases(procedure, targets, expr)

    def _apply_call_transfer(self, procedure: object, operation: object) -> None:
        call = self._call_expression(operation)
        if call is None:
            return
        if isinstance(call, py_ast.DirectCall) and isinstance(call.code, py_ast.Code):
            self._bind_direct_call(procedure, operation, call)
            return
        effect = self.effect_builder.unresolved_call_effect(procedure, call)
        self.heap.mark_all_escaped(effect.escapes)

    def _bind_direct_call(
        self,
        caller: object,
        operation: object,
        call: py_ast.DirectCall,
    ) -> None:
        callee = call.code
        summary_key = self._summary_key(caller, callee, call)
        self._bind_callee_formals(caller, callee, call)
        summary = self._callee_summary(callee, summary_key)
        self._apply_callee_summary(summary)
        targets = assigned_locals(operation)
        if not targets:
            return
        for index, target in enumerate(targets):
            if index >= len(summary.returns):
                continue
            self.heap.bind_local_to_locations(
                caller,
                target,
                (summary.returns[index],),
            )

    def _callee_summary(
        self,
        callee: py_ast.Code,
        summary_key: object,
    ) -> _CallSummary:
        cached = self._summary_cache.get(summary_key)
        if cached is not None:
            return cached
        if summary_key in self._summary_in_progress:
            return self._conservative_return_summary(callee)

        self._summary_in_progress.add(summary_key)
        caller_state = self.state
        self.state = HeapState()
        summary_deletes: list[HeapLocation] = []
        self._summary_delete_stack.append(summary_deletes)
        try:
            self.bind_parameters(callee)
            self.analyze_node(callee, callee.ast)
            summary_state = self.state
            return_locations = self._return_locations(callee)
            result = _CallSummary(
                state=summary_state.copy(),
                returns=return_locations,
                deletes=tuple(dict.fromkeys(summary_deletes)),
            )
            self._summary_cache[summary_key] = result
            return result
        finally:
            self._summary_delete_stack.pop()
            self.state = caller_state
            self._summary_in_progress.discard(summary_key)

    def _apply_callee_summary(self, summary: _CallSummary) -> None:
        self._record_summary_deletes(summary.deletes)
        self._apply_deletes(summary.deletes)
        self.state = self.state.join(summary.state)
        self.heap.mark_all_escaped(tuple(summary.state.escaped))

    def _record_summary_deletes(self, deletes: tuple[HeapLocation, ...]) -> None:
        if self._summary_delete_stack and deletes:
            self._summary_delete_stack[-1].extend(deletes)

    def _summary_key(
        self,
        caller: object,
        callee: py_ast.Code,
        call: py_ast.DirectCall,
    ) -> tuple[object, ...]:
        actual_key = tuple(
            self.locations_for_expression(caller, actual)
            for actual in actual_argument_expressions(call)
        )
        return callee, actual_key

    def _return_locations(self, callee: py_ast.Code) -> tuple[HeapLocation, ...]:
        code_parameters = getattr(callee, "codeparameters", None)
        if code_parameters is None:
            return ()
        locations: list[HeapLocation] = []
        for index, target in enumerate(getattr(code_parameters, "returnparams", ())):
            if isinstance(target, py_ast.Local):
                target_locations = self.heap.locations_for_local(callee, target)
                if target_locations:
                    locations.append(target_locations[0])
                    continue
            locations.append(HeapLocation(self.heap.return_object(callee, index)))
        return tuple(locations)

    def _conservative_return_summary(
        self,
        callee: py_ast.Code,
    ) -> _CallSummary:
        state = HeapState()
        returns = self._return_locations(callee)
        if not returns:
            code_parameters = getattr(callee, "codeparameters", None)
            returns = tuple(
                HeapLocation(self.heap.return_object(callee, index))
                for index, _target in enumerate(
                    getattr(code_parameters, "returnparams", ())
                    if code_parameters is not None
                    else ()
                )
            )
        return _CallSummary(state=state, returns=returns)

    def _bind_callee_formals(
        self,
        caller: object,
        callee: py_ast.Code,
        call: py_ast.DirectCall,
    ) -> None:
        params = callee.codeparameters
        formals = []
        selfparam = getattr(params, "selfparam", None)
        if isinstance(selfparam, py_ast.Local):
            formals.append(selfparam)
        formals.extend(
            param
            for param in getattr(params, "posonlyparams", ())
            if isinstance(param, py_ast.Local)
        )
        formals.extend(
            param
            for param in getattr(params, "params", ())
            if isinstance(param, py_ast.Local)
        )
        actuals = actual_argument_expressions(call)
        for index, formal in enumerate(formals):
            actual_locations = ()
            if index < len(actuals):
                actual_locations = self.locations_for_expression(caller, actuals[index])
            self.heap.bind_parameter(callee, formal, index, actual_locations)

    def _bind_call_result_targets(
        self,
        procedure: object,
        targets: tuple[py_ast.Local, ...],
        call_expression: object,
    ) -> None:
        if not self.heap.policy.bind_call_results:
            return
        kind = self.effect_builder.call_return_kind(call_expression)
        label = self.effect_builder._call_result_label(call_expression)
        for index, target in enumerate(targets):
            site = self.effect_builder.call_return_site(call_expression, index, kind)
            if kind in {CALL_RETURN_FRESH, CALL_RETURN_COPY}:
                self.heap.bind_fresh_return_targets(
                    procedure,
                    (target,),
                    site,
                    label=label,
                )
            elif kind == CALL_RETURN_SUMMARY:
                self.heap.bind_summary_targets(procedure, (target,), site, label=label)
            elif kind == CALL_RETURN_OPAQUE:
                self.heap.bind_call_result_targets(
                    procedure,
                    (target,),
                    site,
                    label=label,
                )

    def _materialize_return_values(
        self,
        procedure: object,
        returns: tuple[HeapLocation, ...],
    ) -> None:
        code_parameters = getattr(procedure, "codeparameters", None)
        if code_parameters is None:
            return
        returnparams = tuple(
            param
            for param in getattr(code_parameters, "returnparams", ())
            if isinstance(param, py_ast.Local)
        )
        for index, target in enumerate(returnparams):
            if index < len(returns):
                self.heap.bind_local_to_locations(procedure, target, (returns[index],))
            else:
                obj = self.heap.return_object(procedure, index, label=target.name)
                self.heap.bind_local_to_object(procedure, target, obj)
        self.state.set_returns(procedure, returns)

    def _apply_writes(
        self,
        procedure: object,
        operation: object,
        writes: tuple[object, ...],
    ) -> None:
        value = self._stored_value_expression(operation)
        if value is None:
            return
        value_locations = self.locations_for_expression(procedure, value)
        if not value_locations:
            return
        for write in writes:
            location = getattr(write, "location", None)
            policy = getattr(write, "policy", None)
            if not isinstance(location, HeapLocation):
                continue
            self.state.write(
                location,
                tuple(dict.fromkeys(value_locations)),
                policy if isinstance(policy, UpdatePolicy) else UpdatePolicy.WEAK,
            )

    def _apply_deletes(self, deletes: tuple[HeapLocation, ...]) -> None:
        for deleted in deletes:
            self.state.delete(deleted)

    def _materialize_collection_literal_values(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        expr = self._assigned_expression(operation)
        if not isinstance(
            expr,
            (py_ast.BuildTuple, py_ast.BuildList, py_ast.BuildSet, py_ast.BuildMap),
        ):
            return
        targets = assigned_locals(operation)
        target_locations = tuple(
            location
            for target in targets
            for location in self.heap.locations_for_local(procedure, target)
        )
        for location in target_locations:
            if location.root.kind is HeapObjectKind.ALLOCATION:
                self.heap.mark_all_escaped(
                    tuple(
                        value_location
                        for value in self._collection_literal_values(expr)
                        for value_location in self.locations_for_expression(
                            procedure, value
                        )
                    )
                )

    @staticmethod
    def _collection_literal_values(expr: object) -> tuple[object, ...]:
        if isinstance(expr, py_ast.BuildMap):
            return tuple(expr.args[1::2])
        return tuple(getattr(expr, "args", ()))

    def _stored_value_expression(self, operation: object) -> object | None:
        values = self.effect_builder._stored_value_expressions(operation)
        if values:
            return values[0]
        collection_value = self.effect_builder.dynamic_subscript_value(operation)
        if collection_value is not None:
            return collection_value
        dynamic_attr_value = self.effect_builder._dynamic_setattr_value(operation)
        if dynamic_attr_value is not None:
            return dynamic_attr_value
        return None

    @staticmethod
    def _assigned_expression(operation: object) -> object | None:
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            return operation.expr
        if isinstance(operation, py_ast.AnnAssign):
            return operation.value
        return None

    @staticmethod
    def _call_expression(operation: object) -> object | None:
        expr = HeapTransferEngine._assigned_expression(operation)
        if isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return expr
        wrapped = getattr(operation, "expr", None)
        if isinstance(wrapped, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return wrapped
        if isinstance(operation, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return operation
        return None
