"""Deferred activation and call-result materialization methods."""

from __future__ import annotations
from pyflow.analysis.ir_utils import actual_argument_expressions, resolve_call_name
from pyflow.language.python import ast as py_ast
from ..domain.state import HeapState
from ..semantics.effects import DYNAMIC_SUBSCRIPT_WILDCARD
from ..model import HeapLocation, UpdatePolicy
from .state import _FlowState


class _DeferredTransferMixin:
    """Internal mixin composed by HeapTransferEngine."""

    @staticmethod
    def _known_builtin_type_token(location: HeapLocation) -> str | None:
        if location.root.type_hint:
            return location.root.type_hint
        label = location.root.label
        return {
            "list literal": "list",
            "tuple literal": "tuple",
            "set literal": "set",
            "map literal": "dict",
            "slice": "slice",
        }.get(label)

    def _resume_deferred_activations(
        self,
        caller: object,
        roots: tuple[HeapLocation, ...],
        *,
        use_yields: bool,
        sent_values: tuple[HeapLocation, ...] = (),
    ) -> tuple[HeapLocation, ...]:
        values: list[HeapLocation] = []
        for root in roots:
            activation = self._deferred_activations.get(root.root)
            if activation is None:
                continue
            resume_base = self.state.copy()
            previous_context = self._current_context
            self._current_context = (
                *previous_context,
                "resume",
                root.root.key,
            )
            try:
                if activation.summary is None or sent_values or use_yields:
                    external_environment = self.heap.snapshot_environment()
                    if activation.frame_environment is not None:
                        self.heap.restore_environment(
                            self.heap.join_environments(
                                (
                                    external_environment,
                                    activation.frame_environment,
                                )
                            )
                        )
                    if sent_values:
                        self._resume_input_stack.append(
                            (max(activation.resume_index - 1, 0), sent_values)
                        )
                    try:
                        activation.summary = self._callee_summary(
                            activation.callee,
                            activation.actual_bindings,
                        )
                    finally:
                        if sent_values:
                            self._resume_input_stack.pop()
                        self.heap.restore_environment(external_environment)
                summary = activation.summary
            finally:
                self._current_context = previous_context
            if summary.raise_state is not None and self._operation_call_raises:
                raised_state = summary.raise_state.copy()
                if summary.raises:
                    raised_state.set_raised(caller, summary.raises)
                self._operation_call_raises[-1].append(
                    _FlowState(
                        raised_state,
                        summary.raise_environment
                        or summary.environment
                        or self.heap.snapshot_environment(),
                        dict(self._definition_default_locations),
                    )
                )
            if use_yields:
                if activation.resume_index < len(summary.yield_steps):
                    resume_index = activation.resume_index
                    step_state, step_environment, yielded = summary.yield_steps[
                        resume_index
                    ]
                    activation.resume_index += 1
                    activation.frame_environment = step_environment
                    caller_environment = self.heap.snapshot_environment()
                    caller_environment.object_labels.update(
                        step_environment.object_labels
                    )
                    caller_environment.escaped_objects.update(
                        step_environment.escaped_objects
                    )
                    previous_frontier = (
                        resume_base
                        if resume_index == 0
                        else summary.yield_steps[resume_index - 1][0]
                    )
                    self._apply_continuation_frontier(
                        previous_frontier,
                        step_state,
                    )
                    self.heap.restore_environment(caller_environment)
                    values.extend(yielded)
                else:
                    if summary.normal_state is None and self._operation_normal_possible:
                        self._operation_normal_possible[-1] = False
                    self._apply_callee_summary(
                        summary,
                        caller,
                        preserve_current=activation.resume_index > 0,
                    )
            else:
                if activation.resume_index == 0:
                    activation.resume_index = 1
                    if summary.normal_state is None and self._operation_normal_possible:
                        self._operation_normal_possible[-1] = False
                    self._apply_callee_summary(summary, caller)
                    for slot in summary.returns:
                        values.extend(slot)
                else:
                    # Re-awaiting a consumed coroutine raises at runtime.
                    values.append(self._external_value_location(caller))
        return tuple(dict.fromkeys(values))

    def _apply_continuation_frontier(
        self,
        previous: HeapState,
        current: HeapState,
    ) -> None:
        """Rebase the delta between two suspension frontiers onto the caller.

        Summaries are recomputed against the heap visible at each resume.  By
        applying only facts changed after the preceding yield, effects in the
        already-consumed generator prefix are not replayed into the caller.
        """
        rebased = self.state.copy()
        for attribute in ("values", "contaminants", "versions"):
            before_map = getattr(previous, attribute)
            after_map = getattr(current, attribute)
            target_map = getattr(rebased, attribute)
            for location in set(before_map) | set(after_map):
                if before_map.get(location) == after_map.get(location):
                    continue
                if location in after_map:
                    target_map[location] = after_map[location]
                else:
                    target_map.pop(location, None)
        changed_absence = previous.absent ^ current.absent
        for location in changed_absence:
            if location in current.absent:
                rebased.absent.add(location)
            else:
                rebased.absent.discard(location)
        changed_scalars = previous.scalar_present ^ current.scalar_present
        for location in changed_scalars:
            if location in current.scalar_present:
                rebased.scalar_present.add(location)
                rebased.absent.discard(location)
            else:
                rebased.scalar_present.discard(location)
        rebased.complete_roots.update(current.complete_roots - previous.complete_roots)
        rebased.escaped.update(current.escaped - previous.escaped)
        self.state = rebased

    @staticmethod
    def _context_token(node: object) -> object:
        origin = getattr(getattr(node, "annotation", None), "origin", ()) or ()
        meaningful_origin = tuple(item for item in origin if item is not None)
        if meaningful_origin:
            return (
                type(node).__name__,
                tuple(repr(item) for item in meaningful_origin),
                getattr(node, "name", None),
            )
        line = getattr(node, "line", None)
        column = getattr(node, "column", None)
        if line is not None or column is not None:
            return type(node).__name__, line, column
        return type(node).__name__, id(node)

    def _copy_call_result_contents(
        self,
        procedure: object,
        target: py_ast.Local | None,
        call: object,
        target_locations: tuple[HeapLocation, ...] | None = None,
    ) -> None:
        if target_locations is None:
            if target is None:
                return
            target_locations = self.heap.locations_for_local(procedure, target)
        actuals = tuple(actual_argument_expressions(call))
        call_name = resolve_call_name(call)
        source_exprs: tuple[object, ...]
        retain_all_arguments = {
            "functools.partial",
            "functools.lru_cache",
            "functools.cached_property",
            "functools.singledispatch",
            "functools.wraps",
            "collections.ChainMap",
            "collections.defaultdict",
            "collections.Counter",
            "collections.OrderedDict",
            "collections.deque",
            "collections.UserDict",
            "collections.UserList",
            "collections.UserString",
            "itertools.chain",
            "itertools.product",
            "itertools.compress",
            "itertools.starmap",
            "zip",
            "builtins.zip",
            "interpreter_build_map",
            "interpreter_merge_varargs",
            "interpreter_merge_kwargs",
        }
        if isinstance(call, py_ast.MethodCall):
            source_exprs = (call.expr,)
        elif call_name in retain_all_arguments:
            source_exprs = actuals
        elif call_name in {"map", "builtins.map", "filter", "builtins.filter"}:
            source_exprs = actuals[1:]
        else:
            source_exprs = actuals[:1]
        if not source_exprs:
            return
        evaluated = self._last_call_operands.get(id(call), {})
        source_locations = tuple(
            dict.fromkeys(
                location
                for source_expr in source_exprs
                for location in (
                    evaluated.get(id(source_expr))
                    if id(source_expr) in evaluated
                    else self.locations_for_expression(procedure, source_expr)
                )
            )
        )
        self._copy_locations(source_locations, target_locations)
        if source_locations:
            for target_location in target_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(
                        target_location,
                        "__source__",
                    ),
                    source_locations,
                    UpdatePolicy.WEAK,
                )
        contained = list(self._contained_values(source_locations))
        if call_name in {"keys", "dict.keys"}:
            contained.extend(
                value
                for source in source_locations
                for value in self.state.read(
                    self.heap.dynamic_attribute_location(source, "__keys__"),
                    fallback=(),
                )
            )
        elif call_name in {"items", "dict.items"}:
            contained.extend(
                value
                for source in source_locations
                for value in self.state.read(
                    self.heap.dynamic_attribute_location(source, "__keys__"),
                    fallback=(),
                )
            )
        if call_name in {"map", "builtins.map"}:
            contained.append(self._external_value_location(procedure))
        if contained:
            for target_location in target_locations:
                self.state.write(
                    self.heap.dynamic_subscript_location(
                        target_location,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    ),
                    tuple(dict.fromkeys(contained)),
                    UpdatePolicy.WEAK,
                )

    def _copy_locations(
        self,
        source_locations: tuple[HeapLocation, ...],
        target_locations: tuple[HeapLocation, ...],
    ) -> None:
        stored_items = (
            *self.state.values.items(),
            *self.state.contaminants.items(),
        )
        for target_location in target_locations:
            for source_location in source_locations:
                for stored, values in stored_items:
                    if stored.root != source_location.root or not stored.selectors:
                        continue
                    copied = HeapLocation(target_location.root, stored.selectors)
                    self.state.write(copied, values, UpdatePolicy.WEAK)
