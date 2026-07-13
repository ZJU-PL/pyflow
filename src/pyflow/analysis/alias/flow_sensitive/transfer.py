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

from .abstraction import HeapAbstraction, HeapEnvironment
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
    returns: tuple[tuple[HeapLocation, ...], ...]
    deletes: tuple[HeapLocation, ...] = ()

    # Maps return index -> formal parameter index when the callee directly
    # returns a formal parameter without modification (e.g., "def id(x): return x").
    # The caller can use this to bind the actual argument's location directly.
    param_returns: dict[int, frozenset[int]] = field(default_factory=dict)

    # Set of formal parameter indices whose locations escape the callee.
    # Callers can use this to precisely mark actual arguments as escaped
    # without relying solely on the merged escaped set in summary.state.
    param_escapes: frozenset[int] = field(default_factory=frozenset)


@dataclass(frozen=True)
class _FlowState:
    """Complete flow value: heap contents plus local binding environment."""

    heap_state: HeapState
    environment: HeapEnvironment


@dataclass(frozen=True)
class _FlowOutcome:
    """Normal successor plus path-insensitive abrupt control-flow exits."""

    normal: _FlowState | None
    abrupt: dict[str, _FlowState] = field(default_factory=dict)


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
        self._exception_prefix_stack: list[list[_FlowState]] = []
        self._direct_call_evaluation_cache: dict[
            tuple[object, ...], tuple[HeapLocation, ...]
        ] = {}
        self._definition_default_locations: dict[
            tuple[int, int], tuple[HeapLocation, ...]
        ] = {}
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
            outcome = self.analyze_node(code, getattr(code, "ast", None))
            self._restore_flow_state(self._joined_outcome_state(outcome))
            self._propagate_escapes_transitively()
        finally:
            self._active_codes.discard(code_id)

    def analyze_node(self, procedure: object, node: object) -> _FlowOutcome:
        outcome = self._analyze_node(procedure, node)
        self._position_outcome(outcome)
        return outcome

    def _analyze_node(self, procedure: object, node: object) -> _FlowOutcome:
        if node is None or isinstance(node, py_ast.leafTypes):
            return self._normal_outcome()
        if isinstance(node, py_ast.Code):
            return self.analyze_node(node, node.ast)
        if isinstance(node, py_ast.Suite):
            abrupt: dict[str, _FlowState] = {}
            for block in node.blocks:
                outcome = self.analyze_node(procedure, block)
                abrupt = self._merge_abrupt_maps(abrupt, outcome.abrupt)
                if outcome.normal is None:
                    return _FlowOutcome(None, abrupt)
            return _FlowOutcome(self._capture_flow_state(), abrupt)
        if isinstance(node, py_ast.Switch):
            return self._analyze_switch(procedure, node)
        if isinstance(node, py_ast.While):
            return self._analyze_while(procedure, node)
        if isinstance(node, py_ast.For):
            return self._analyze_for(procedure, node)
        if isinstance(node, py_ast.TryExceptFinally):
            return self._analyze_try_except_finally(procedure, node)
        if isinstance(node, py_ast.TypeSwitch):
            return self._analyze_type_switch(procedure, node)
        if isinstance(node, py_ast.FunctionDef):
            self.apply_operation(procedure, node)
            return self._normal_outcome()
        if isinstance(node, py_ast.ClassDef):
            self._record_exception_prefix()
            for expression in self._definition_header_expressions(node):
                self.locations_for_expression(procedure, expression)
            self._record_exception_prefix()
            body_outcome = self.analyze_node(procedure, node.body)
            if body_outcome.normal is None:
                return body_outcome
            self._restore_flow_state(body_outcome.normal)
            # The class name is bound only after its body has completed.
            self._apply_definition_transfer(procedure, node)
            self._record_exception_prefix()
            return _FlowOutcome(
                self._capture_flow_state(),
                body_outcome.abrupt,
            )
        if isinstance(node, py_ast.Condition):
            outcome = self.analyze_node(procedure, node.preamble)
            if outcome.normal is not None:
                conditional = getattr(node, "conditional", None)
                if conditional is not None:
                    self.locations_for_expression(procedure, conditional)
                return _FlowOutcome(self._capture_flow_state(), outcome.abrupt)
            return outcome
        if isinstance(node, py_ast.Break):
            return self._abrupt_outcome("break")
        if isinstance(node, py_ast.Continue):
            return self._abrupt_outcome("continue")
        if isinstance(node, py_ast.PythonASTNode):
            self.apply_operation(procedure, node)
            if isinstance(node, py_ast.Return):
                return self._abrupt_outcome("return")
            if isinstance(node, py_ast.Raise):
                return self._abrupt_outcome("raise")
        return self._normal_outcome()

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
                current = self.heap.locations_for_local(procedure, formal)
                self.heap.bind_local_to_locations(
                    procedure,
                    formal,
                    (*current, self._external_value_location(procedure)),
                    include_raw_fallback=True,
                )

    def apply_operation(self, procedure: object, operation: object) -> None:
        """Apply the heap transfer for one operation."""
        self._record_exception_prefix()
        if isinstance(operation, py_ast.Discard):
            self.locations_for_expression(procedure, operation.expr)
        elif isinstance(operation, py_ast.Expression):
            self.locations_for_expression(procedure, operation)
        elif isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetGlobal,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            # Assignment RHS evaluation precedes evaluation of the target.
            # This matters when a named expression or direct call rebinds a
            # local subsequently used as the field/subscript base.
            self.locations_for_expression(procedure, operation.value)
        self._materialize_assignment_result(procedure, operation)
        self._apply_definition_transfer(procedure, operation)
        effect = self.effect_builder.operation_effect(
            procedure,
            operation,
            collection_mutator_names=self.collection_mutator_names,
        )
        self._apply_writes(procedure, operation, effect.writes)
        self._record_summary_deletes(effect.deletes)
        self._apply_deletes(effect.deletes)
        immediate_escapes = self._immediate_escape_locations(operation, effect)
        self.heap.mark_all_escaped(immediate_escapes)
        self.state.mark_escaped(immediate_escapes)
        if isinstance(operation, py_ast.Return):
            self._materialize_return_values(procedure, operation, effect.returns)
        if isinstance(operation, py_ast.Raise):
            raised_locations = tuple(
                location
                for expression in self.effect_builder.raise_escape_expressions(operation)
                for location in self.locations_for_expression(procedure, expression)
            )
            self.state.set_raised(procedure, raised_locations)
        self._apply_call_transfer(procedure, operation)
        self._handle_local_delete(procedure, operation)
        self._materialize_collection_literal_values(procedure, operation)
        self._materialize_function_default_values(procedure, operation)
        self._apply_external_boundary_transfer(procedure, operation)
        self._record_exception_prefix()

    @staticmethod
    def _immediate_escape_locations(
        operation: object,
        effect: object,
    ) -> tuple[HeapLocation, ...]:
        """Return effect escapes that are externally reachable immediately.

        Stores into fields, subscripts, cells, or collection mutators create
        heap reachability edges. The stored values escape only if the
        destination root is, or later becomes, escaped; the fixed-point escape
        propagation handles that through ``HeapState``.
        """
        escapes = getattr(effect, "escapes", ())
        writes = getattr(effect, "writes", ())
        if not writes or not escapes:
            return escapes
        if isinstance(operation, py_ast.SetGlobal):
            return escapes
        if isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            return ()
        call = HeapTransferEngine._call_expression(operation)
        if call is not None:
            return ()
        return escapes

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
        if isinstance(expression, py_ast.Input):
            return self.locations_for_expression(procedure, expression.lcl)
        if isinstance(expression, py_ast.Cell):
            return (self.effect_builder.cell_location(expression, procedure),)
        if isinstance(expression, py_ast.TypeParam):
            return self.locations_for_expression(procedure, expression.bound)
        if isinstance(expression, py_ast.TypeParams):
            return self._merge_expression_locations(
                procedure,
                *getattr(expression, "params", ()),
            )
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
            location = self.effect_builder.cell_location(expression.cell, procedure)
            return self.state.read(location)
        if isinstance(expression, (py_ast.GetAttr, py_ast.Load)):
            self.locations_for_expression(procedure, expression.name)
            attribute = self.effect_builder._path_component(expression.name)
            bases = self.locations_for_expression(procedure, expression.expr)
            if isinstance(expression, py_ast.Load) and getattr(
                expression, "fieldtype", None
            ) in {"Dictionary", "Array"}:
                locations = self.heap.dynamic_subscript_locations(
                    bases,
                    (f"[{attribute}]",),
                )
            else:
                locations = self.heap.dynamic_attribute_locations(
                    bases,
                    (attribute,),
                )
            return self.state.read_many(locations)
        if isinstance(expression, py_ast.GetSubscript):
            self.locations_for_expression(procedure, expression.subscript)
            subscript = self.effect_builder._constant_subscript(expression.subscript)
            subscripts = (DYNAMIC_SUBSCRIPT_WILDCARD,)
            if subscript is not None:
                subscripts = (subscript, DYNAMIC_SUBSCRIPT_WILDCARD)
            locations = self.heap.dynamic_subscript_locations(
                self.locations_for_expression(procedure, expression.expr),
                subscripts,
            )
            return self.state.read_many(locations)
        if isinstance(expression, py_ast.DirectCall) and isinstance(
            expression.code,
            py_ast.Code,
        ):
            return self._evaluate_direct_call_expression(procedure, expression)
        if isinstance(expression, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return (
                HeapLocation(
                    self.effect_builder.call_return_object(procedure, expression)
                ),
            )
        if isinstance(
            expression,
            (
                py_ast.BuildTuple,
                py_ast.BuildList,
                py_ast.BuildSet,
                py_ast.BuildMap,
                py_ast.BuildSlice,
                py_ast.Allocate,
            ),
        ):
            if isinstance(expression, py_ast.BuildSlice):
                for component in (
                    expression.start,
                    expression.stop,
                    expression.step,
                ):
                    self.locations_for_expression(procedure, component)
            elif isinstance(expression, py_ast.Allocate):
                self.locations_for_expression(procedure, expression.expr)
            allocation = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label=self.effect_builder._allocation_label(expression),
                )
            )
            if isinstance(
                expression,
                (py_ast.BuildTuple, py_ast.BuildList, py_ast.BuildSet, py_ast.BuildMap),
            ):
                for argument in getattr(expression, "args", ()):
                    self.locations_for_expression(procedure, argument)
                self._write_collection_literal_elements(
                    procedure,
                    allocation,
                    expression,
                    self._collection_literal_values(expression),
                )
            return (allocation,)
        if isinstance(expression, py_ast.MakeFunction):
            function = HeapLocation(
                self.heap.allocation_object(
                    procedure, expression, label="function"
                )
            )
            default_locations = self._merge_expression_locations(
                procedure,
                *getattr(expression, "defaults", ()),
            )
            if default_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(function, "__defaults__"),
                    default_locations,
                    UpdatePolicy.STRONG,
                )
            closure_locations = self._merge_expression_locations(
                procedure,
                *getattr(expression, "cells", ()),
            )
            if closure_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(function, "__closure__"),
                    closure_locations,
                    UpdatePolicy.STRONG,
                )
            return (function,)
        if isinstance(expression, (py_ast.GetIter, py_ast.AsyncGetIter)):
            return self._merge_expression_locations(
                procedure,
                expression.expr,
                self._external_value_location(procedure),
            )
        if isinstance(expression, py_ast.GetSlice):
            for component in (
                expression.start,
                expression.stop,
                expression.step,
            ):
                self.locations_for_expression(procedure, component)
            return self._merge_expression_locations(
                procedure,
                expression.expr,
                self._external_value_location(procedure),
            )
        if isinstance(expression, (py_ast.UnaryPrefixOp,)):
            return self._merge_expression_locations(
                procedure,
                expression.expr,
                self._external_value_location(procedure),
            )
        if isinstance(expression, py_ast.BinaryOp):
            return self._merge_expression_locations(
                procedure,
                expression.left,
                expression.right,
                self._external_value_location(procedure),
            )
        if isinstance(expression, (py_ast.ConvertToBool, py_ast.Not)):
            self.locations_for_expression(procedure, expression.expr)
            return ()
        if isinstance(expression, (py_ast.Is, py_ast.Check)):
            self.locations_for_expression(procedure, expression.left if isinstance(expression, py_ast.Is) else expression.expr)
            if isinstance(expression, py_ast.Is):
                self.locations_for_expression(procedure, expression.right)
            else:
                self.locations_for_expression(procedure, expression.name)
            return ()
        if isinstance(expression, py_ast.Await):
            return self._merge_expression_locations(
                procedure,
                expression.expr,
                self._external_value_location(procedure),
            )
        if isinstance(expression, (py_ast.Yield, py_ast.AsyncYield)):
            return (self._external_value_location(procedure),)
        if isinstance(expression, py_ast.YieldFrom):
            return self._merge_expression_locations(
                procedure,
                expression.expr,
                self._external_value_location(procedure),
            )
        if isinstance(expression, (py_ast.ShortCircutAnd, py_ast.ShortCircutOr)):
            terms = tuple(getattr(expression, "terms", ()))
            if not terms:
                return ()
            possible_locations: list[HeapLocation] = []
            prefix_states: list[_FlowState] = []
            for term in terms:
                possible_locations.extend(
                    self.locations_for_expression(procedure, term)
                )
                # Evaluation may stop after every term.  Joining all prefixes
                # preserves both skipped and executed side effects from later
                # terms without pretending they execute unconditionally.
                prefix_states.append(self._capture_flow_state())
            self._restore_flow_state(
                self._join_flow_states(tuple(prefix_states))
            )
            return tuple(dict.fromkeys(possible_locations))
        if isinstance(expression, py_ast.NamedExpr):
            locations = self.locations_for_expression(procedure, expression.value)
            if locations:
                self.heap.bind_local_to_locations(
                    procedure,
                    expression.target,
                    locations,
                )
            else:
                self.heap.unalias_local(procedure, expression.target)
            return locations
        if isinstance(expression, py_ast.Existing):
            value = getattr(expression.object, "pyobj", None)
            if isinstance(
                value,
                (str, bytes, int, float, complex, bool, type(None)),
            ):
                return ()
            return (
                HeapLocation(
                    self.heap.external_object(
                        ("existing", id(expression.object)),
                        label=repr(value),
                    )
                ),
            )
        return ()

    def _external_value_location(self, procedure: object) -> HeapLocation:
        return HeapLocation(
            self.heap.summary_object(
                ("external-value", id(procedure)),
                label="external value",
            )
        )

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

    def _analyze_switch(
        self,
        procedure: object,
        node: py_ast.Switch,
    ) -> _FlowOutcome:
        condition = self.analyze_node(procedure, node.condition)
        if condition.normal is None:
            return condition
        base = condition.normal
        true_outcome = self._outcome_after(procedure, node.t, base)
        false_outcome = self._outcome_after(procedure, node.f, base)
        normal = self._join_optional_flow_states(
            (true_outcome.normal, false_outcome.normal)
        )
        abrupt = self._merge_abrupt_maps(
            condition.abrupt,
            true_outcome.abrupt,
            false_outcome.abrupt,
        )
        return _FlowOutcome(normal, abrupt)

    def _analyze_while(
        self,
        procedure: object,
        node: py_ast.While,
    ) -> _FlowOutcome:
        condition = self.analyze_node(procedure, node.condition)
        if condition.normal is None:
            return condition
        entry = condition.normal
        current = entry
        breaks: list[_FlowState] = []
        abrupt = dict(condition.abrupt)
        for _ in range(self.max_loop_iterations):
            body_outcome = self._outcome_after(procedure, node.body, current)
            if "break" in body_outcome.abrupt:
                breaks.append(body_outcome.abrupt["break"])
            abrupt = self._merge_abrupt_maps(
                abrupt,
                {
                    kind: state
                    for kind, state in body_outcome.abrupt.items()
                    if kind not in {"break", "continue"}
                },
            )
            back_edges = tuple(
                state
                for state in (
                    body_outcome.normal,
                    body_outcome.abrupt.get("continue"),
                )
                if state is not None
            )
            if not back_edges:
                break
            body_state = self._join_flow_states(back_edges)
            next_state = self._join_flow_states((entry, body_state))
            if self._flow_states_equivalent(next_state, current):
                current = next_state
                break
            current = next_state
        else_outcome = self._outcome_after(procedure, node.else_, current)
        normal = self._join_optional_flow_states(
            (else_outcome.normal, *breaks)
        )
        abrupt = self._merge_abrupt_maps(abrupt, else_outcome.abrupt)
        return _FlowOutcome(normal, abrupt)

    def _analyze_for(
        self,
        procedure: object,
        node: py_ast.For,
    ) -> _FlowOutcome:
        preamble = self.analyze_node(procedure, node.loopPreamble)
        if preamble.normal is None:
            return preamble
        self.locations_for_expression(procedure, node.iterator)
        entry = self._capture_flow_state()
        current = entry
        breaks: list[_FlowState] = []
        abrupt = dict(preamble.abrupt)
        for _ in range(self.max_loop_iterations):
            self._restore_flow_state(current)
            self._bind_for_index(procedure, node)
            iteration_entry = self._capture_flow_state()
            body_outcome = self._outcome_after(
                procedure,
                py_ast.Suite([node.bodyPreamble, node.body]),
                iteration_entry,
            )
            if "break" in body_outcome.abrupt:
                breaks.append(body_outcome.abrupt["break"])
            abrupt = self._merge_abrupt_maps(
                abrupt,
                {
                    kind: state
                    for kind, state in body_outcome.abrupt.items()
                    if kind not in {"break", "continue"}
                },
            )
            back_edges = tuple(
                state
                for state in (
                    body_outcome.normal,
                    body_outcome.abrupt.get("continue"),
                )
                if state is not None
            )
            if not back_edges:
                break
            body_state = self._join_flow_states(back_edges)
            next_state = self._join_flow_states((entry, body_state))
            if self._flow_states_equivalent(next_state, current):
                current = next_state
                break
            current = next_state
        else_outcome = self._outcome_after(procedure, node.else_, current)
        normal = self._join_optional_flow_states(
            (else_outcome.normal, *breaks)
        )
        abrupt = self._merge_abrupt_maps(abrupt, else_outcome.abrupt)
        return _FlowOutcome(normal, abrupt)

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
    ) -> _FlowOutcome:
        base = self._capture_flow_state()
        exception_prefixes = [base]
        self._exception_prefix_stack.append(exception_prefixes)
        try:
            body_outcome = self._outcome_after(procedure, node.body, base)
        finally:
            self._exception_prefix_stack.pop()

        # Any operation in the try body can raise.  Handlers therefore start
        # from the join of all observed prefixes, rather than only the body's
        # final state.
        explicit_raise = body_outcome.abrupt.get("raise")
        if explicit_raise is not None:
            exception_prefixes.append(explicit_raise)
        exception_state = self._join_flow_states(tuple(exception_prefixes))

        normal_states: list[_FlowState] = []
        abrupt = {
            kind: state
            for kind, state in body_outcome.abrupt.items()
            if kind != "raise"
        }

        else_suite = getattr(node, "else_", None)
        if body_outcome.normal is not None:
            if else_suite is None:
                normal_states.append(body_outcome.normal)
            else:
                else_outcome = self._outcome_after(
                    procedure,
                    else_suite,
                    body_outcome.normal,
                )
                if else_outcome.normal is not None:
                    normal_states.append(else_outcome.normal)
                abrupt = self._merge_abrupt_maps(abrupt, else_outcome.abrupt)

        handled_any = False
        for handler in getattr(node, "handlers", ()):
            handled_any = True
            handler_outcome = self._handler_outcome(
                procedure,
                handler,
                exception_state,
            )
            if handler_outcome.normal is not None:
                normal_states.append(handler_outcome.normal)
            abrupt = self._merge_abrupt_maps(abrupt, handler_outcome.abrupt)
        default_handler = getattr(node, "defaultHandler", None)
        if default_handler is not None:
            handled_any = True
            default_outcome = self._outcome_after(
                procedure,
                default_handler,
                exception_state,
            )
            if default_outcome.normal is not None:
                normal_states.append(default_outcome.normal)
            abrupt = self._merge_abrupt_maps(abrupt, default_outcome.abrupt)

        # Typed handlers may not match, and ordinary operations can throw even
        # without an explicit Raise node. Preserve an unhandled exceptional exit.
        if handled_any or exception_prefixes:
            abrupt = self._merge_abrupt_maps(
                abrupt,
                {"raise": exception_state},
            )

        outcome = _FlowOutcome(
            self._join_optional_flow_states(tuple(normal_states)),
            abrupt,
        )
        finally_suite = getattr(node, "finally_", None)
        if finally_suite is None:
            return outcome
        return self._apply_finally_outcome(procedure, finally_suite, outcome)

    def _analyze_type_switch(
        self,
        procedure: object,
        node: py_ast.TypeSwitch,
    ) -> _FlowOutcome:
        base = self._capture_flow_state()
        conditional_locs = ()
        cond_ref = getattr(node, "conditional", None)
        if cond_ref is not None:
            conditional_locs = self.locations_for_expression(procedure, cond_ref)
        normal_states: list[_FlowState] = [base]
        abrupt: dict[str, _FlowState] = {}
        for case in getattr(node, "cases", ()):
            self._restore_flow_state(base)
            if conditional_locs and case.expr is not None:
                self.heap.bind_local_to_locations(
                    procedure,
                    case.expr,
                    conditional_locs,
                    include_raw_fallback=True,
                )
            case_outcome = self.analyze_node(procedure, case.body)
            if case_outcome.normal is not None:
                normal_states.append(case_outcome.normal)
            abrupt = self._merge_abrupt_maps(abrupt, case_outcome.abrupt)
        return _FlowOutcome(
            self._join_optional_flow_states(tuple(normal_states)),
            abrupt,
        )

    def _handler_outcome(
        self,
        procedure: object,
        handler: object,
        exception_state: _FlowState,
    ) -> _FlowOutcome:
        previous = self._capture_flow_state()
        self._restore_flow_state(exception_state)
        handler_type = getattr(handler, "type", None)
        if handler_type is not None:
            self.locations_for_expression(procedure, handler_type)
        caught = getattr(handler, "value", None)
        if isinstance(caught, py_ast.Local):
            raised = exception_state.heap_state.raised.get(procedure, ())
            if raised:
                self.heap.bind_local_to_locations(procedure, caught, raised)
        entry = self._capture_flow_state()
        handler_suite = py_ast.Suite(
            [
                getattr(handler, "preamble", None),
                getattr(handler, "body", None),
            ]
        )
        outcome = self._outcome_after(procedure, handler_suite, entry)
        self._restore_flow_state(previous)
        return outcome

    def _apply_finally_outcome(
        self,
        procedure: object,
        finally_suite: object,
        incoming: _FlowOutcome,
    ) -> _FlowOutcome:
        normal_states: list[_FlowState] = []
        abrupt: dict[str, _FlowState] = {}
        if incoming.normal is not None:
            final_outcome = self._outcome_after(
                procedure,
                finally_suite,
                incoming.normal,
            )
            if final_outcome.normal is not None:
                normal_states.append(final_outcome.normal)
            abrupt = self._merge_abrupt_maps(abrupt, final_outcome.abrupt)
        for original_kind, state in incoming.abrupt.items():
            prepared, prior_returns = self._without_procedure_returns(
                procedure,
                state,
            )
            final_outcome = self._outcome_after(
                procedure,
                finally_suite,
                prepared,
            )
            abrupt = self._merge_abrupt_maps(abrupt, final_outcome.abrupt)
            if final_outcome.normal is not None:
                resumed = self._with_procedure_returns(
                    procedure,
                    final_outcome.normal,
                    prior_returns,
                )
                abrupt = self._merge_abrupt_maps(
                    abrupt,
                    {original_kind: resumed},
                )
        return _FlowOutcome(
            self._join_optional_flow_states(tuple(normal_states)),
            abrupt,
        )

    @staticmethod
    def _without_procedure_returns(
        procedure: object,
        state: _FlowState,
    ) -> tuple[
        _FlowState,
        tuple[
            tuple[HeapLocation, ...],
            tuple[tuple[HeapLocation, ...], ...],
        ],
    ]:
        heap_state = state.heap_state.copy()
        prior = (
            heap_state.returns.pop(procedure, ()),
            heap_state.return_slots.pop(procedure, ()),
        )
        return _FlowState(heap_state, state.environment), prior

    @staticmethod
    def _with_procedure_returns(
        procedure: object,
        state: _FlowState,
        returns: tuple[
            tuple[HeapLocation, ...],
            tuple[tuple[HeapLocation, ...], ...],
        ],
    ) -> _FlowState:
        flat_returns, return_slots = returns
        if not flat_returns and not return_slots:
            return state
        heap_state = state.heap_state.copy()
        heap_state.set_returns(procedure, flat_returns)
        heap_state.set_return_slots(procedure, return_slots)
        return _FlowState(heap_state, state.environment)

    def _outcome_after(
        self,
        procedure: object,
        node: object,
        state: _FlowState,
    ) -> _FlowOutcome:
        previous = self._capture_flow_state()
        self._restore_flow_state(state)
        outcome = self.analyze_node(procedure, node)
        self._restore_flow_state(previous)
        return outcome

    def _state_after(
        self,
        procedure: object,
        node: object,
        state: _FlowState,
    ) -> _FlowState:
        outcome = self._outcome_after(procedure, node, state)
        if outcome.normal is not None:
            return outcome.normal
        return self._join_flow_states(tuple(outcome.abrupt.values()))

    def _capture_flow_state(self) -> _FlowState:
        return _FlowState(
            heap_state=self.state.copy(),
            environment=self.heap.snapshot_environment(),
        )

    def _record_exception_prefix(self) -> None:
        if not self._exception_prefix_stack:
            return
        prefix = self._capture_flow_state()
        for collector in self._exception_prefix_stack:
            collector.append(prefix)

    def _restore_flow_state(self, state: _FlowState) -> None:
        self.state = state.heap_state.copy()
        self.heap.restore_environment(state.environment)

    def _normal_outcome(self) -> _FlowOutcome:
        return _FlowOutcome(self._capture_flow_state())

    def _abrupt_outcome(self, kind: str) -> _FlowOutcome:
        return _FlowOutcome(None, {kind: self._capture_flow_state()})

    def _position_outcome(self, outcome: _FlowOutcome) -> None:
        if outcome.normal is not None:
            self._restore_flow_state(outcome.normal)
            return
        if outcome.abrupt:
            self._restore_flow_state(
                self._join_flow_states(tuple(outcome.abrupt.values()))
            )

    def _joined_outcome_state(self, outcome: _FlowOutcome) -> _FlowState:
        states = tuple(
            state
            for state in (outcome.normal, *outcome.abrupt.values())
            if state is not None
        )
        return self._join_flow_states(states)

    def _merge_abrupt_maps(
        self,
        *maps: dict[str, _FlowState],
    ) -> dict[str, _FlowState]:
        grouped: dict[str, list[_FlowState]] = {}
        for mapping in maps:
            for kind, state in mapping.items():
                grouped.setdefault(kind, []).append(state)
        return {
            kind: self._join_flow_states(tuple(states))
            for kind, states in grouped.items()
        }

    def _join_optional_flow_states(
        self,
        states: tuple[_FlowState | None, ...],
    ) -> _FlowState | None:
        concrete = tuple(state for state in states if state is not None)
        if not concrete:
            return None
        return self._join_flow_states(concrete)

    def _join_flow_states(self, states: tuple[_FlowState, ...]) -> _FlowState:
        if not states:
            return self._capture_flow_state()
        joined_heap = states[0].heap_state.copy()
        for state in states[1:]:
            joined_heap = joined_heap.join(state.heap_state)
        joined_environment = self.heap.join_environments(
            tuple(state.environment for state in states)
        )
        return _FlowState(joined_heap, joined_environment)

    @staticmethod
    def _flow_states_equivalent(a: _FlowState, b: _FlowState) -> bool:
        return (
            a.heap_state.equivalent(b.heap_state)
            and a.environment.storage_overrides == b.environment.storage_overrides
            and a.environment.escaped_objects == b.environment.escaped_objects
        )

    def _materialize_assignment_result(
        self, procedure: object, operation: object
    ) -> None:
        targets = self._direct_assigned_locals(operation)
        if not targets:
            return
        if isinstance(operation, py_ast.InputBlock):
            external = self._external_value_location(procedure)
            for target in targets:
                self.heap.bind_local_to_locations(procedure, target, (external,))
            return
        if isinstance(operation, py_ast.Phi):
            phi_locations = tuple(
                dict.fromkeys(
                    location
                    for argument in getattr(operation, "arguments", ())
                    if argument is not None
                    for location in self.locations_for_expression(procedure, argument)
                )
            )
            if phi_locations:
                self.heap.bind_local_to_locations(
                    procedure,
                    operation.target,
                    phi_locations,
                )
            else:
                self.heap.bind_local_to_locations(
                    procedure,
                    operation.target,
                    (self._external_value_location(procedure),),
                )
            return
        if isinstance(operation, py_ast.UnpackSequence):
            self._materialize_unpack_targets(procedure, operation)
            return
        expr = self._assigned_expression(operation)
        if isinstance(
            expr,
            (
                py_ast.BuildTuple,
                py_ast.BuildList,
                py_ast.BuildSet,
                py_ast.BuildMap,
                py_ast.BuildSlice,
                py_ast.MakeFunction,
                py_ast.Allocate,
            ),
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

    @staticmethod
    def _direct_assigned_locals(operation: object) -> tuple[py_ast.Local, ...]:
        if isinstance(operation, py_ast.Assign):
            return tuple(
                local for local in operation.lcls if isinstance(local, py_ast.Local)
            )
        if isinstance(operation, py_ast.UnpackSequence):
            return tuple(
                local
                for local in operation.targets
                if isinstance(local, py_ast.Local)
            )
        if isinstance(operation, py_ast.AnnAssign):
            if operation.value is not None and isinstance(operation.target, py_ast.Local):
                return (operation.target,)
            return ()
        if isinstance(operation, py_ast.InputBlock):
            return tuple(
                input_.lcl
                for input_ in getattr(operation, "inputs", ())
                if isinstance(getattr(input_, "lcl", None), py_ast.Local)
            )
        if isinstance(operation, py_ast.Phi) and isinstance(
            getattr(operation, "target", None), py_ast.Local
        ):
            return (operation.target,)
        return ()

    def _materialize_unpack_targets(
        self,
        procedure: object,
        operation: py_ast.UnpackSequence,
    ) -> None:
        sources = self.locations_for_expression(procedure, operation.expr)
        for index, target in enumerate(operation.targets):
            if not isinstance(target, py_ast.Local):
                continue
            values: list[HeapLocation] = []
            for source in sources:
                exact = self.heap.dynamic_subscript_location(source, f"[{index}]")
                wildcard = self.heap.dynamic_subscript_location(
                    source,
                    DYNAMIC_SUBSCRIPT_WILDCARD,
                )
                values.extend(self.state.read(exact, fallback=()))
                values.extend(self.state.read(wildcard, fallback=()))
                values.extend(self.state.read_contained(wildcard))
            if not values:
                values.extend(sources)
                values.append(self._external_value_location(procedure))
            self.heap.bind_local_to_locations(
                procedure,
                target,
                tuple(dict.fromkeys(values)),
            )

    def _apply_definition_transfer(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        if isinstance(operation, py_ast.TypeAlias):
            value_locations = self.locations_for_expression(
                procedure,
                operation.value,
            )
            target = self.effect_builder.global_location(procedure, operation.name)
            self.state.write(target, value_locations, UpdatePolicy.WEAK)
            self.heap.mark_all_escaped(value_locations)
            self.state.mark_escaped(value_locations)
            return
        if not isinstance(operation, (py_ast.FunctionDef, py_ast.ClassDef)):
            return

        label = (
            f"function {operation.name}"
            if isinstance(operation, py_ast.FunctionDef)
            else f"class {operation.name}"
        )
        definition = HeapLocation(
            self.heap.allocation_object(procedure, operation, label=label)
        )
        default_locations: list[HeapLocation] = []
        if isinstance(operation, py_ast.FunctionDef):
            defaults = tuple(
                getattr(operation.code.codeparameters, "defaults", ())
            )
            for index, default in enumerate(defaults):
                locations = self.locations_for_expression(procedure, default)
                self._definition_default_locations[
                    (id(operation.code), index)
                ] = locations
                default_locations.extend(locations)

        related_expressions = self._definition_header_expressions(operation)
        related_locations = tuple(
            dict.fromkeys(
                location
                for expression in related_expressions
                for location in self.locations_for_expression(procedure, expression)
            )
        )
        target = self.effect_builder.global_location(procedure, operation.name)
        decorated_or_dynamic = ()
        if related_expressions:
            decorated_or_dynamic = (self._external_value_location(procedure),)
        values = tuple(
            dict.fromkeys(
                (definition, *related_locations, *decorated_or_dynamic)
            )
        )
        self.state.write(target, values, UpdatePolicy.WEAK)
        self.heap.mark_all_escaped(values)
        self.state.mark_escaped(values)

        if default_locations:
            self.state.write(
                self.heap.dynamic_attribute_location(
                    definition,
                    "__defaults__",
                ),
                tuple(dict.fromkeys(default_locations)),
                UpdatePolicy.STRONG,
            )

    @staticmethod
    def _definition_header_expressions(operation: object) -> tuple[object, ...]:
        expressions: list[object] = []
        if isinstance(operation, py_ast.ClassDef):
            expressions.extend(getattr(operation, "bases", ()))
            expressions.extend(
                keyword[1]
                if isinstance(keyword, tuple) and len(keyword) == 2
                else keyword
                for keyword in getattr(operation, "keywords", ())
            )
        expressions.extend(getattr(operation, "decorators", ()))
        type_params = getattr(operation, "type_params", None)
        if type_params is not None:
            expressions.append(type_params)
        return tuple(expressions)

    def _apply_external_boundary_transfer(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        expressions: list[object] = []
        if isinstance(operation, py_ast.OutputBlock):
            expressions.extend(
                output.expr
                for output in getattr(operation, "outputs", ())
                if getattr(output, "expr", None) is not None
            )
        elif isinstance(operation, py_ast.Output):
            expressions.append(operation.expr)
        elif isinstance(operation, py_ast.Print):
            expressions.extend(
                expression
                for expression in (operation.target, operation.expr)
                if expression is not None
            )
        if not expressions:
            return
        escaped = tuple(
            dict.fromkeys(
                location
                for expression in expressions
                for location in self.locations_for_expression(procedure, expression)
            )
        )
        self.heap.mark_all_escaped(escaped)
        self.state.mark_escaped(escaped)

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
        actual_bindings = self._direct_call_actual_locations(caller, callee, call)
        possible_returns = self._evaluate_direct_call_with_bindings(
            caller,
            call,
            actual_bindings,
        )
        targets = assigned_locals(operation)
        if not targets:
            return
        if len(targets) == 1:
            if possible_returns:
                self.heap.bind_local_to_locations(
                    caller,
                    targets[0],
                    possible_returns,
                )
            return
        summary_key = self._summary_key(callee, actual_bindings)
        summary = self._callee_summary(callee, summary_key)
        for index, target in enumerate(targets):
            if index >= len(summary.returns):
                continue
            target_locations = list(summary.returns[index])
            for param_idx in summary.param_returns.get(index, frozenset()):
                target_locations.extend(actual_bindings.get(param_idx, ()))
            self.heap.bind_local_to_locations(
                caller,
                target,
                tuple(dict.fromkeys(target_locations)),
            )

    def _evaluate_direct_call_expression(
        self,
        caller: object,
        call: py_ast.DirectCall,
    ) -> tuple[HeapLocation, ...]:
        actual_bindings = self._direct_call_actual_locations(caller, call.code, call)
        return self._evaluate_direct_call_with_bindings(
            caller,
            call,
            actual_bindings,
        )

    def _evaluate_direct_call_with_bindings(
        self,
        caller: object,
        call: py_ast.DirectCall,
        actual_bindings: dict[int, tuple[HeapLocation, ...]],
    ) -> tuple[HeapLocation, ...]:
        del caller
        callee = call.code
        summary_key = self._summary_key(callee, actual_bindings)
        cache_key = ("direct-call", id(call), summary_key)
        cached = self._direct_call_evaluation_cache.get(cache_key)
        if cached is not None:
            return cached

        self._bind_callee_formals(callee, actual_bindings)
        summary = self._callee_summary(callee, summary_key)
        self._apply_callee_summary(summary)
        for param_idx in summary.param_escapes:
            actual_locations = actual_bindings.get(param_idx, ())
            if actual_locations:
                self.heap.mark_all_escaped(tuple(actual_locations))

        possible_returns: list[HeapLocation] = []
        for return_index, return_locations in enumerate(summary.returns):
            possible_returns.extend(return_locations)
            for param_idx in summary.param_returns.get(
                return_index,
                frozenset(),
            ):
                possible_returns.extend(actual_bindings.get(param_idx, ()))
        result = tuple(dict.fromkeys(possible_returns))
        self._direct_call_evaluation_cache[cache_key] = result
        return result

    def _propagate_escapes_transitively(self) -> None:
        """Propagate escape through container/closure values.

        If container location C is marked escaped, and C's heap state
        (values/contaminants) holds location V, then V's root should also
        be marked escaped — the value is reachable from outside the
        procedure via the escaped container.

        This is a fixed-point iteration because nested containers may
        transitively hold further values (e.g. outer -> inner -> value).
        """
        if not self.heap.policy.track_escapes:
            return
        changed = True
        while changed:
            changed = False
            new_escaped: list[HeapLocation] = []
            # Check all known location -> values mappings
            for mapping in (self.state.values, self.state.contaminants):
                for container_loc, value_locs in mapping.items():
                    if container_loc not in self.state.escaped:
                        # Also check whether the root object was directly
                        # marked escaped in the heap abstraction.
                        if container_loc.root not in self.heap._escaped_objects:
                            continue
                    for value_loc in value_locs:
                        if (value_loc not in self.state.escaped
                                and value_loc.root not in self.heap._escaped_objects):
                            new_escaped.append(value_loc)
            # Also propagate through return values: if a return slot (ret0)
            # contains locations, those are also reachable from outside.
            for ret_locs in self.state.returns.values():
                for ret_loc in ret_locs:
                    if (ret_loc not in self.state.escaped
                            and ret_loc.root not in self.heap._escaped_objects):
                        new_escaped.append(ret_loc)
            # Propagate from escaped cells to their referenced variables.
            # A cell captures a local/parameter (e.g. for closures).  When the
            # cell object is marked escaped (because the containing closure is
            # returned or otherwise escapes), the underlying variable's storage
            # must also be marked escaped: the variable is reachable from outside
            # through the escaped closure's cell reference.
            for escaped_obj in list(self.heap._escaped_objects):
                if escaped_obj.kind is not HeapObjectKind.CELL:
                    continue
                cell_name = escaped_obj.label  # e.g. "x"
                # Search storage_overrides for a local/parameter whose root
                # HeapObject has a matching name (via label or _object_labels).
                for (_proc_id, _local_id), storage in list(
                    self.heap.storage_overrides.items()
                ):
                    if not storage:
                        continue
                    root = storage[0]
                    if not self.heap._name_matches_object(root, cell_name):
                        continue
                    loc = self.heap.location_for_raw(root)
                    if (loc not in self.state.escaped
                            and loc.root not in self.heap._escaped_objects):
                        new_escaped.append(loc)
                    break

            if new_escaped:
                self.heap.mark_all_escaped(tuple(new_escaped))
                self.state.mark_escaped(tuple(new_escaped))
                changed = True

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
            initial_formal_locations = self._callee_formal_locations(callee)
            outcome = self.analyze_node(callee, callee.ast)
            self._restore_flow_state(self._joined_outcome_state(outcome))
            self._propagate_escapes_transitively()
            summary_state = self.state
            return_locations = summary_state.return_slots.get(
                callee,
                self._return_locations(callee),
            )
            param_returns = self._compute_param_returns(
                return_locations,
                initial_formal_locations,
            )
            param_escapes = self._compute_param_escapes(
                summary_state,
                initial_formal_locations,
            )
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
        # Propagate transitively after merging summary state: the caller
        # may now have new escaped containers holding values that should
        # also be considered escaped.
        self._propagate_escapes_transitively()

    def _record_summary_deletes(self, deletes: tuple[HeapLocation, ...]) -> None:
        if self._summary_delete_stack and deletes:
            self._summary_delete_stack[-1].extend(deletes)

    def _summary_key(
        self,
        callee: py_ast.Code,
        actual_bindings: dict[int, tuple[HeapLocation, ...]],
    ) -> tuple[object, ...]:
        actual_key = tuple(
            actual_bindings.get(index, ())
            for index, _formal in enumerate(self._callee_formals(callee))
        )
        return callee, actual_key

    def _return_locations(
        self,
        callee: py_ast.Code,
    ) -> tuple[tuple[HeapLocation, ...], ...]:
        code_parameters = getattr(callee, "codeparameters", None)
        if code_parameters is None:
            return ()
        locations: list[tuple[HeapLocation, ...]] = []
        for index, target in enumerate(getattr(code_parameters, "returnparams", ())):
            if isinstance(target, py_ast.Local):
                target_locations = self.heap.locations_for_local(callee, target)
                if target_locations:
                    locations.append(target_locations)
                    continue
            locations.append((HeapLocation(self.heap.return_object(callee, index)),))
        return tuple(locations)

    def _callee_formal_locations(
        self,
        callee: py_ast.Code,
    ) -> dict[int, tuple[HeapLocation, ...]]:
        """Return a dict mapping formal param index -> its heap locations."""
        formal_locations: dict[int, tuple[HeapLocation, ...]] = {}
        for idx, formal in enumerate(self._callee_formals(callee)):
            locs = self.heap.locations_for_local(callee, formal)
            if locs:
                formal_locations[idx] = locs
        return formal_locations

    def _compute_param_returns(
        self,
        return_locations: tuple[tuple[HeapLocation, ...], ...],
        formal_locations: dict[int, tuple[HeapLocation, ...]],
    ) -> dict[int, frozenset[int]]:
        """Return a dict mapping return_index -> formal_param_index when a
        return directly carries a formal parameter's location."""
        if not return_locations:
            return {}
        if not formal_locations:
            return {}
        param_returns: dict[int, frozenset[int]] = {}
        for ret_idx, ret_locs in enumerate(return_locations):
            matches: set[int] = set()
            for formal_idx, formal_locs in formal_locations.items():
                if any(ret_loc in formal_locs for ret_loc in ret_locs):
                    matches.add(formal_idx)
            if matches:
                param_returns[ret_idx] = frozenset(matches)
        return param_returns

    def _compute_param_escapes(
        self,
        summary_state: HeapState,
        formal_locations: dict[int, tuple[HeapLocation, ...]],
    ) -> frozenset[int]:
        """Return the set of formal parameter indices whose locations escape."""
        if not summary_state.escaped:
            return frozenset()
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
                (HeapLocation(self.heap.return_object(callee, index)),)
                for index, _target in enumerate(
                    getattr(code_parameters, "returnparams", ())
                    if code_parameters is not None
                    else ()
                )
            )
        return _CallSummary(state=state, returns=returns)

    def _bind_callee_formals(
        self,
        callee: py_ast.Code,
        actual_bindings: dict[int, tuple[HeapLocation, ...]],
    ) -> None:
        for index, formal in enumerate(self._callee_formals(callee)):
            actual_locations = actual_bindings.get(index, ())
            self.heap.bind_parameter(callee, formal, index, actual_locations)

    @staticmethod
    def _callee_formals(callee: py_ast.Code) -> tuple[py_ast.Local, ...]:
        params = getattr(callee, "codeparameters", None)
        if params is None:
            return ()
        formals: list[py_ast.Local] = []
        for candidate in (
            getattr(params, "selfparam", None),
            *getattr(params, "posonlyparams", ()),
            *getattr(params, "params", ()),
            getattr(params, "vparam", None),
            getattr(params, "kparam", None),
        ):
            if isinstance(candidate, py_ast.Local) and candidate not in formals:
                formals.append(candidate)
        return tuple(formals)

    def _direct_call_actual_locations(
        self,
        caller: object,
        callee: py_ast.Code,
        call: py_ast.DirectCall,
    ) -> dict[int, tuple[HeapLocation, ...]]:
        """Bind a resolved call according to Python's formal parameter layout."""
        params = callee.codeparameters
        formals = self._callee_formals(callee)
        formal_indices = {id(formal): index for index, formal in enumerate(formals)}
        bindings: dict[int, list[HeapLocation]] = {
            index: [] for index in range(len(formals))
        }

        def evaluate(expression_procedure, expression):
            return self.locations_for_expression(
                expression_procedure,
                expression,
            )

        def bind(formal, locations):
            bindings[formal_indices[id(formal)]].extend(locations)

        selfparam = getattr(params, "selfparam", None)
        selfarg = getattr(call, "selfarg", None)
        if isinstance(selfparam, py_ast.Local) and selfarg is not None:
            bind(selfparam, evaluate(caller, selfarg))

        positional_formals = [
            formal
            for formal in (
                *getattr(params, "posonlyparams", ()),
                *getattr(params, "params", ()),
            )
            if isinstance(formal, py_ast.Local)
        ]
        positional_actuals = list(getattr(call, "args", ()))
        extra_positional: list[tuple[HeapLocation, ...]] = []
        for index, actual in enumerate(positional_actuals):
            locations = evaluate(caller, actual)
            if index < len(positional_formals):
                bind(positional_formals[index], locations)
            else:
                extra_positional.append(locations)

        regular_params = [
            formal
            for formal in getattr(params, "params", ())
            if isinstance(formal, py_ast.Local)
        ]
        param_names = list(getattr(params, "paramnames", ()))
        named_formals = {
            name: formal
            for name, formal in zip(param_names, regular_params)
            if isinstance(name, str)
        }
        extra_keywords: list[tuple[HeapLocation, ...]] = []
        for keyword in getattr(call, "kwds", ()):
            if not (isinstance(keyword, tuple) and len(keyword) == 2):
                extra_keywords.append(evaluate(caller, keyword))
                continue
            name, actual = keyword
            locations = evaluate(caller, actual)
            formal = named_formals.get(name)
            if formal is None:
                extra_keywords.append(locations)
                continue
            bind(formal, locations)

        vargs_locations: tuple[HeapLocation, ...] = ()
        if getattr(call, "vargs", None) is not None:
            vargs_locations = evaluate(caller, call.vargs)

        kargs_locations: tuple[HeapLocation, ...] = ()
        if getattr(call, "kargs", None) is not None:
            kargs_locations = evaluate(caller, call.kargs)

        defaults = list(getattr(params, "defaults", ()))
        if defaults:
            default_formals = positional_formals[-len(defaults):]
            for default_index, (formal, default) in enumerate(
                zip(default_formals, defaults)
            ):
                index = formal_indices[id(formal)]
                if not bindings[index]:
                    locations = self._definition_default_locations.get(
                        (id(callee), default_index)
                    )
                    if locations is None:
                        locations = evaluate(callee, default)
                    bind(formal, locations)

        vparam = getattr(params, "vparam", None)
        if isinstance(vparam, py_ast.Local):
            for locations in extra_positional:
                bind(vparam, locations)
            bind(vparam, vargs_locations)

        kparam = getattr(params, "kparam", None)
        if isinstance(kparam, py_ast.Local):
            for locations in extra_keywords:
                bind(kparam, locations)
            bind(kparam, kargs_locations)

        return {
            index: tuple(dict.fromkeys(locations))
            for index, locations in bindings.items()
        }

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
        operation: py_ast.Return,
        returns: tuple[HeapLocation, ...],
    ) -> None:
        # HeapEffect exposes a flat return set for procedure summaries, but a
        # direct call with multiple result variables needs the values grouped
        # by result position.  Re-evaluate the expressions here and preserve
        # that grouping through branch joins.
        del returns
        code_parameters = getattr(procedure, "codeparameters", None)
        if code_parameters is None:
            return
        returnparams = tuple(getattr(code_parameters, "returnparams", ()))
        expression_locations = tuple(
            self.locations_for_expression(procedure, expression)
            for expression in getattr(operation, "exprs", ())
        )
        return_slots: list[tuple[HeapLocation, ...]] = []
        for index, target in enumerate(returnparams):
            if len(returnparams) == 1 and len(expression_locations) == 1:
                bind_locations = expression_locations[0]
            elif index < len(expression_locations):
                bind_locations = expression_locations[index]
            else:
                bind_locations = ()

            if not bind_locations:
                bind_locations = (
                    HeapLocation(
                        self.heap.return_object(
                            procedure,
                            index,
                            label=getattr(target, "name", None),
                        )
                    ),
                )
            return_slots.append(tuple(dict.fromkeys(bind_locations)))

            if isinstance(target, py_ast.Local):
                self.heap.bind_local_to_locations(
                    procedure,
                    target,
                    bind_locations,
                )
            # Any returned value is visible from outside the procedure,
            # including a slot represented by DoNotCare rather than a local.
            self.heap.mark_all_escaped(bind_locations)

        slots = tuple(return_slots)
        flat_returns = tuple(
            dict.fromkeys(
                location
                for slot in slots
                for location in slot
            )
        )
        self.state.set_return_slots(procedure, slots)
        self.state.set_returns(procedure, flat_returns)

    def _apply_writes(
        self,
        procedure: object,
        operation: object,
        writes: tuple[object, ...],
    ) -> None:
        value = self._stored_value_expression(operation)
        if value is not None:
            value_locations = self.locations_for_expression(procedure, value)
            if isinstance(operation, py_ast.SetSlice):
                value_locations = self._expand_contained_locations(
                    value_locations
                )
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
        return self._expand_contained_locations(
            tuple(
                loc
                for val_expr in value_exprs
                for loc in self.locations_for_expression(procedure, val_expr)
            )
        )

    def _expand_contained_locations(
        self,
        roots: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        """Include values reachable as elements of possible iterable roots.

        This deliberately retains the roots too: append-like mutators store
        the argument object itself, while extend/update and slice assignment
        store values obtained by iterating it.  Using their union is a sound
        may-approximation for the shared mutator model.
        """
        expanded = list(roots)
        for root in roots:
            wildcard = self.heap.dynamic_subscript_location(
                root,
                DYNAMIC_SUBSCRIPT_WILDCARD,
            )
            expanded.extend(self.state.read_contained(wildcard))
        return tuple(dict.fromkeys(expanded))

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
        for argument in getattr(expr, "args", ()):
            self.locations_for_expression(procedure, argument)
        targets = assigned_locals(operation)
        target_locations = tuple(
            location
            for target in targets
            for location in self.heap.locations_for_local(procedure, target)
        )
        value_exprs = self._collection_literal_values(expr)
        for location in target_locations:
            if location.root.kind is HeapObjectKind.ALLOCATION:
                # Write literal element values into the container's heap state
                # so subsequent reads and transitive escape propagation can
                # find them when the container itself escapes.
                self._write_collection_literal_elements(
                    procedure, location, expr, value_exprs
                )

    def _materialize_function_default_values(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        expr = self._assigned_expression(operation)
        if not isinstance(expr, py_ast.MakeFunction):
            return
        targets = assigned_locals(operation)
        target_locations = tuple(
            location
            for target in targets
            for location in self.heap.locations_for_local(procedure, target)
        )
        default_locations = tuple(
            location
            for default in getattr(expr, "defaults", ())
            for location in self.locations_for_expression(procedure, default)
        )
        if not default_locations:
            return
        for location in target_locations:
            defaults_location = self.heap.dynamic_attribute_location(
                location,
                "__defaults__",
            )
            self.state.write(
                defaults_location,
                tuple(dict.fromkeys(default_locations)),
                UpdatePolicy.STRONG,
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
                key_loc = self.heap.dynamic_subscript_location(
                    container,
                    subscript or DYNAMIC_SUBSCRIPT_WILDCARD,
                )
                val_locs = self.locations_for_expression(procedure, val_expr)
                if val_locs:
                    self.state.write(
                        key_loc,
                        val_locs,
                        (
                            UpdatePolicy.STRONG
                            if subscript
                            else UpdatePolicy.WEAK
                        ),
                    )
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
