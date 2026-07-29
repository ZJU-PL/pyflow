"""Control-flow expression resolution for await, yield, and branches."""

from __future__ import annotations

from ..model import HeapLocation


class _ExpressionControlMixin:
    def _resolve_await(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        awaitable = self.locations_for_expression(procedure, expression.expr)
        protocol_values = self._evaluate_known_protocol(
            procedure,
            awaitable,
            "__await__",
        )
        resumed = self._resume_deferred_activations(
            procedure,
            awaitable,
            use_yields=False,
        )
        self.heap.mark_all_escaped(awaitable)
        self.state.mark_escaped(awaitable)
        return tuple(
            dict.fromkeys(
                (
                    *resumed,
                    *protocol_values,
                    *awaitable,
                    self._external_value_location(procedure),
                )
            )
        )

    def _resolve_yield(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        yielded = self.locations_for_expression(procedure, expression.expr)
        self.state.set_yields(procedure, yielded)
        self.heap.mark_all_escaped(yielded)
        self.state.mark_escaped(yielded)
        if self._yield_state_stack:
            event_state = self._capture_flow_state()
            for depth in self.state.current_yield_depths(procedure):
                self._yield_state_stack[-1].append((depth, event_state, yielded))
        self.state.advance_yield_depths(procedure)
        if self._resume_input_stack:
            target_depth, sent = self._resume_input_stack[-1]
            if target_depth in self.state.current_yield_depths(procedure):
                return sent
        return (self._external_value_location(procedure),)

    def _resolve_yield_from(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        yielded = self.locations_for_expression(procedure, expression.expr)
        protocol_values = self._evaluate_known_protocol(
            procedure,
            yielded,
            "__iter__",
        )
        resumed = self._resume_deferred_activations(
            procedure,
            yielded,
            use_yields=True,
        )
        expanded = tuple(dict.fromkeys((*resumed, *self._contained_values(yielded))))
        self.state.set_yields(
            procedure,
            expanded or yielded,
        )
        self.heap.mark_all_escaped(yielded)
        self.state.mark_escaped(yielded)
        if self._yield_state_stack:
            event_state = self._capture_flow_state()
            for depth in self.state.current_yield_depths(procedure):
                self._yield_state_stack[-1].append(
                    (depth, event_state, expanded or yielded)
                )
        self.state.advance_yield_depths(procedure)
        return tuple(
            dict.fromkeys(
                (
                    *yielded,
                    *protocol_values,
                    self._external_value_location(procedure),
                )
            )
        )

    def _resolve_short_circuit(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        terms = tuple(getattr(expression, "terms", ()))
        if not terms:
            return ()
        possible_locations: list[HeapLocation] = []
        prefix_states: list[object] = []
        for term in terms:
            possible_locations.extend(self.locations_for_expression(procedure, term))
            # Evaluation may stop after every term.  Joining all prefixes
            # preserves both skipped and executed side effects from later
            # terms without pretending they execute unconditionally.
            prefix_states.append(self._capture_flow_state())
        self._restore_flow_state(self._join_flow_states(tuple(prefix_states)))
        return tuple(dict.fromkeys(possible_locations))

    def _resolve_conditional(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        self.locations_for_expression(procedure, expression.test)
        branch_entry = self._capture_flow_state()
        self._restore_flow_state(branch_entry)
        body_locations = self.locations_for_expression(
            procedure,
            expression.body,
        )
        body_state = self._capture_flow_state()
        self._restore_flow_state(branch_entry)
        else_locations = self.locations_for_expression(
            procedure,
            expression.orelse,
        )
        else_state = self._capture_flow_state()
        self._restore_flow_state(self._join_flow_states((body_state, else_state)))
        return tuple(dict.fromkeys((*body_locations, *else_locations)))

    def _resolve_named_expression(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        locations = self.locations_for_expression(procedure, expression.value)
        if locations:
            self._bind_runtime_local(
                procedure,
                expression.target,
                locations,
            )
        else:
            self._clear_runtime_local(procedure, expression.target)
        return locations

    def _resolve_existing(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        value = getattr(expression.object, "pyobj", None)
        if isinstance(
            value,
            (str, bytes, int, float, complex, bool, type(None)),
        ):
            return ()
        return (
            HeapLocation(
                self.heap.external_object(
                    (
                        "existing",
                        self._program_point_identity(procedure, expression),
                    ),
                    label=repr(value),
                    stable_identity=True,
                )
            ),
        )

    def _resolve_unsupported_expression(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        # The IR is extensible. A newly introduced reference-producing
        # expression must never silently become "no reference" merely
        # because this dispatcher has not gained a precision rule yet.
        if hasattr(expression, "visitChildren"):
            children: list[object] = []
            expression.visitChildren(children.append)
            for child in children:
                self.locations_for_expression(procedure, child)
        return (
            HeapLocation(
                self.heap.unknown_object(
                    (
                        "unsupported-expression",
                        type(expression).__name__,
                        self._context_token(expression),
                    ),
                    label=f"unknown {type(expression).__name__} result",
                )
            ),
        )
