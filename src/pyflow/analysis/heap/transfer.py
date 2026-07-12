"""Standalone heap transfer engine.

This module applies operation-level heap effects to :class:`HeapAbstraction`.
It intentionally stays conservative: unresolved calls escape their arguments,
unknown assigned values break precise local aliases, and modeled constructors
or collection literals allocate fresh heap roots.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pyflow.analysis.ir_utils import (
    actual_argument_expressions,
    assigned_locals,
    resolve_call_name,
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

    # Maps return index -> formal parameter index when the callee directly
    # returns a formal parameter without modification (e.g., "def id(x): return x").
    # The caller can use this to bind the actual argument's location directly.
    param_returns: dict[int, int] = field(default_factory=dict)

    # Set of formal parameter indices whose locations escape the callee.
    # Callers can use this to precisely mark actual arguments as escaped
    # without relying solely on the merged escaped set in summary.state.
    param_escapes: frozenset[int] = field(default_factory=frozenset)


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
                if isinstance(block, (py_ast.Break, py_ast.Continue)):
                    break
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
        if isinstance(node, py_ast.TypeSwitch):
            self._analyze_type_switch(procedure, node)
            return
        if isinstance(node, py_ast.Condition):
            self.analyze_node(procedure, node.preamble)
            return
        if isinstance(node, (py_ast.Break, py_ast.Continue)):
            return  # No heap effects; Suite traversal stops at these.
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
        self._handle_local_delete(procedure, operation)
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
        if isinstance(expression, py_ast.MakeFunction):
            return (
                HeapLocation(
                    self.heap.allocation_object(
                        procedure, expression, label="function"
                    )
                ),
            )
        if isinstance(expression, (py_ast.ShortCircutAnd, py_ast.ShortCircutOr)):
            return self._merge_expression_locations(procedure, *expression.terms)
        if isinstance(expression, py_ast.NamedExpr):
            return self.locations_for_expression(procedure, expression.value)
        return ()

    def _merge_expression_locations(self, procedure, *expressions):
        """Return the deduplicated union of heap locations from multiple expressions."""
        locations: list[HeapLocation] = []
        for expr in expressions:
            if expr is not None:
                locations.extend(self.locations_for_expression(procedure, expr))
        return tuple(dict.fromkeys(locations))

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
        self._bind_for_index(procedure, node)
        self.analyze_node(procedure, node.else_)

    def _bind_for_index(self, procedure: object, node: py_ast.For) -> None:
        if not isinstance(node.index, py_ast.Local):
            return
        iter_locations = self.locations_for_expression(procedure, node.iterator)
        if not iter_locations:
            return
        element_locations: list[HeapLocation] = []
        seen: set[HeapLocation] = set()
        for loc in iter_locations:
            wildcard_loc = self.heap.dynamic_subscript_location(
                loc, DYNAMIC_SUBSCRIPT_WILDCARD
            )
            for val in self.state.read_contained(wildcard_loc):
                if val not in seen:
                    seen.add(val)
                    element_locations.append(val)
        if element_locations:
            self.heap.bind_local_to_locations(
                procedure, node.index, tuple(element_locations),
                include_raw_fallback=True,
            )

    def _analyze_try_except_finally(
        self,
        procedure: object,
        node: py_ast.TryExceptFinally,
    ) -> None:
        base = self.state.copy()
        states = [self._state_after(procedure, node.body, base)]
        # Exception handlers see try body heap mutations (path-insensitive
        # overapproximation: the handler could be entered after any mutation
        # within the try body).
        body_state = states[0]
        for handler in getattr(node, "handlers", ()):
            handler_state = body_state.copy()
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

    def _analyze_type_switch(
        self,
        procedure: object,
        node: py_ast.TypeSwitch,
    ) -> None:
        base = self.state.copy()
        conditional_locs = ()
        cond_ref = getattr(node, "conditional", None)
        if cond_ref is not None:
            conditional_locs = self.locations_for_expression(procedure, cond_ref)
        states: list[HeapState] = []
        for case in getattr(node, "cases", ()):
            case_state = base.copy()
            self.state = case_state
            if conditional_locs and case.expr is not None:
                self.heap.bind_local_to_locations(
                    procedure,
                    case.expr,
                    conditional_locs,
                    include_raw_fallback=True,
                )
            self.analyze_node(procedure, case.body)
            states.append(self.state)
        if states:
            joined = states[0]
            for s in states[1:]:
                joined = joined.join(s)
            self.state = joined

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
            (py_ast.BuildTuple, py_ast.BuildList, py_ast.BuildSet, py_ast.BuildMap, py_ast.MakeFunction),
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
        if summary.param_escapes:
            actuals = actual_argument_expressions(call)
            for param_idx in summary.param_escapes:
                if param_idx < len(actuals):
                    actual_locations = self.locations_for_expression(
                        caller, actuals[param_idx]
                    )
                    if actual_locations:
                        self.heap.mark_all_escaped(tuple(actual_locations))
        targets = assigned_locals(operation)
        if not targets:
            return
        actuals = actual_argument_expressions(call)
        for index, target in enumerate(targets):
            if index >= len(summary.returns):
                continue
            if index in summary.param_returns:
                param_idx = summary.param_returns[index]
                if param_idx < len(actuals):
                    actual_locations = self.locations_for_expression(
                        caller, actuals[param_idx]
                    )
                    if actual_locations:
                        self.heap.bind_local_to_locations(
                            caller, target, actual_locations
                        )
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
            param_returns = self._compute_param_returns(callee, return_locations)
            param_escapes = self._compute_param_escapes(callee, summary_state)
            result = _CallSummary(
                state=summary_state.copy(),
                returns=return_locations,
                deletes=tuple(dict.fromkeys(summary_deletes)),
                param_returns=param_returns,
                param_escapes=param_escapes,
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

    def _callee_formal_locations(
        self,
        callee: py_ast.Code,
    ) -> dict[int, tuple[HeapLocation, ...]]:
        """Return a dict mapping formal param index -> its heap locations."""
        code_parameters = getattr(callee, "codeparameters", None)
        if code_parameters is None:
            return {}
        formals: list[py_ast.Local] = []
        selfparam = getattr(code_parameters, "selfparam", None)
        if isinstance(selfparam, py_ast.Local):
            formals.append(selfparam)
        formals.extend(
            param
            for param in getattr(code_parameters, "posonlyparams", ())
            if isinstance(param, py_ast.Local)
        )
        formals.extend(
            param
            for param in getattr(code_parameters, "params", ())
            if isinstance(param, py_ast.Local)
        )
        vparam = getattr(code_parameters, "vparam", None)
        kparam = getattr(code_parameters, "kparam", None)
        if isinstance(vparam, py_ast.Local):
            formals.append(vparam)
        if isinstance(kparam, py_ast.Local):
            formals.append(kparam)
        # Deduplicate while preserving order
        seen: set[int] = set()
        unique_formals: list[py_ast.Local] = []
        for f in formals:
            fid = id(f)
            if fid not in seen:
                seen.add(fid)
                unique_formals.append(f)

        formal_locations: dict[int, tuple[HeapLocation, ...]] = {}
        for idx, formal in enumerate(unique_formals):
            locs = self.heap.locations_for_local(callee, formal)
            if locs:
                formal_locations[idx] = locs
        return formal_locations

    def _compute_param_returns(
        self,
        callee: py_ast.Code,
        return_locations: tuple[HeapLocation, ...],
    ) -> dict[int, int]:
        """Return a dict mapping return_index -> formal_param_index when a
        return directly carries a formal parameter's location."""
        if not return_locations:
            return {}
        formal_locations = self._callee_formal_locations(callee)
        if not formal_locations:
            return {}
        param_returns: dict[int, int] = {}
        for ret_idx, ret_loc in enumerate(return_locations):
            for formal_idx, formal_locs in formal_locations.items():
                if ret_loc in formal_locs:
                    param_returns[ret_idx] = formal_idx
                    break
        return param_returns

    def _compute_param_escapes(
        self,
        callee: py_ast.Code,
        summary_state: HeapState,
    ) -> frozenset[int]:
        """Return the set of formal parameter indices whose locations escape."""
        if not summary_state.escaped:
            return frozenset()
        formal_locations = self._callee_formal_locations(callee)
        if not formal_locations:
            return frozenset()
        escaped: set[int] = set()
        for idx, locs in formal_locations.items():
            for loc in locs:
                if loc in summary_state.escaped:
                    escaped.add(idx)
                    break
        return frozenset(escaped)

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
        if value is not None:
            value_locations = self.locations_for_expression(procedure, value)
            # Don't return early when value_locations is empty: write()
            # handles STRONG+empty (pop to clear the binding) and
            # WEAK+empty (no-op) correctly.
        else:
            # No direct stored-value expression.  Check whether this operation
            # wraps a collection mutator call (e.g. ``list.append(x)``) whose
            # value arguments should be written to the container's wildcard
            # location generated by HeapEffectBuilder.collection_mutation().
            coll_value_locs = self._collection_mutator_value_locations(
                procedure, operation
            )
            if not coll_value_locs:
                return
            value_locations = coll_value_locs
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

    def _collection_mutator_value_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        """Extract value locations for collection mutator calls.

        When a ``Discard(MethodCall(container, "append", [value]))`` is
        processed, :meth:`HeapEffectBuilder.operation_effect` generates
        wildcard writes to the container but the write values are buried
        in the method-call arguments rather than in a ``value`` attribute.
        This helper extracts those value expressions and resolves them
        to heap locations.
        """
        call = self._call_expression(operation)
        if call is None:
            return ()
        call_name = resolve_call_name(call)
        if call_name is None or call_name not in self.collection_mutator_names:
            return ()
        model = self.intrinsics.collection_mutator(call_name)
        if model is None or not model.writes_value:
            return ()
        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall):
            value_exprs = model.value_args(actuals)
        else:
            remaining = actuals[1:] if len(actuals) > 1 else ()
            value_exprs = model.value_args(remaining)
        return tuple(
            loc
            for val_expr in value_exprs
            for loc in self.locations_for_expression(procedure, val_expr)
        )

    def _apply_deletes(self, deletes: tuple[HeapLocation, ...]) -> None:
        for deleted in deletes:
            self.state.delete(deleted)

    def _handle_local_delete(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        """Handle ``del x`` — break aliasing and remove the local's heap state."""
        if not isinstance(operation, py_ast.Delete):
            return
        self.heap.unalias_local(procedure, operation.lcl)

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
        value_exprs = self._collection_literal_values(expr)
        value_locations = tuple(
            value_location
            for value in value_exprs
            for value_location in self.locations_for_expression(procedure, value)
        )
        for location in target_locations:
            if location.root.kind is HeapObjectKind.ALLOCATION:
                self.heap.mark_all_escaped(value_locations)
                # Also write the literal element values into the container's
                # heap state so subsequent reads (e.g. ``lst[0]``) can find them.
                self._write_collection_literal_elements(
                    procedure, location, expr, value_exprs
                )

    def _write_collection_literal_elements(
        self,
        procedure: object,
        container: HeapLocation,
        expr: object,
        value_exprs: tuple[object, ...],
    ) -> None:
        if isinstance(expr, py_ast.BuildMap):
            keys = tuple(expr.args[0::2])
            for key_expr, val_expr in zip(keys, value_exprs):
                subscript = self.effect_builder._constant_subscript(key_expr)
                if subscript:
                    key_loc = self.heap.dynamic_subscript_location(
                        container, subscript
                    )
                    val_locs = self.locations_for_expression(
                        procedure, val_expr
                    )
                    if key_loc and val_locs:
                        self.state.write(key_loc, val_locs, UpdatePolicy.STRONG)
        elif isinstance(expr, py_ast.BuildSet):
            set_loc = self.heap.dynamic_subscript_location(
                container, DYNAMIC_SUBSCRIPT_WILDCARD
            )
            all_val_locs: list[HeapLocation] = []
            for val_expr in value_exprs:
                all_val_locs.extend(
                    self.locations_for_expression(procedure, val_expr)
                )
            if all_val_locs:
                self.state.write(
                    set_loc, tuple(dict.fromkeys(all_val_locs)), UpdatePolicy.WEAK
                )
        else:
            for index, val_expr in enumerate(value_exprs):
                index_loc = self.heap.dynamic_subscript_location(
                    container, f"[{index}]"
                )
                val_locs = self.locations_for_expression(procedure, val_expr)
                if index_loc and val_locs:
                    self.state.write(
                        index_loc, val_locs, UpdatePolicy.STRONG
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
