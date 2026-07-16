"""Algebraic and cross-consumer contracts for the flow-sensitive heap."""

from __future__ import annotations

from types import SimpleNamespace

from pyflow.analysis.alias.flow_sensitive import (
    HeapAbstraction,
    HeapAnalysis,
    HeapEffectBuilder,
    HeapLocation,
    HeapState,
    HeapSummaryBuilder,
    HeapTransferEngine,
    HeapObjectKind,
    ProcedureHeapSummary,
    UpdatePolicy,
)
from pyflow.analysis.ifds.cfg_adapter import CFGSupergraphAdapter
from pyflow.language.python import ast as py_ast


class FutureReferenceExpression(py_ast.Expression):
    pass


def _heap():
    return HeapAbstraction(lambda _procedure, _local: ())


def test_heap_state_join_is_commutative_associative_and_idempotent():
    heap = _heap()
    root = HeapLocation(heap.allocation_object(None, "root", label="root"))
    field = heap.dynamic_attribute_location(root, "field")
    values = tuple(
        HeapLocation(heap.allocation_object(None, index, label=f"v{index}"))
        for index in range(3)
    )

    states = []
    for value in values:
        state = HeapState()
        state.write(field, (value,), UpdatePolicy.WEAK)
        states.append(state)
    left, middle, right = states

    assert left.join(left).equivalent(left)
    assert left.join(middle).equivalent(middle.join(left))
    assert left.join(middle).join(right).equivalent(
        left.join(middle.join(right))
    )


def test_scalar_presence_is_not_absence_or_unknown_reference():
    heap = _heap()
    root = HeapLocation(heap.allocation_object(None, "root", label="root"))
    field = heap.dynamic_attribute_location(root, "field")
    state = HeapState()
    state.write(
        field,
        (),
        UpdatePolicy.STRONG,
        has_non_reference=True,
    )
    graph = heap.to_points_to_graph(state=state)

    result = graph.possible_values_at(field)
    assert result.includes_non_reference
    assert not result.definitely_absent
    assert not result.includes_unknown


def test_summary_builder_and_effect_builder_share_operation_semantics():
    heap = _heap()
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")

    def locations(procedure, expression):
        if isinstance(expression, py_ast.Local):
            return heap.locations_for_local(procedure, expression)
        return ()

    operation = py_ast.SetAttr(
        value,
        obj,
        py_ast.Existing(py_ast.program.Object("field")),
    )
    code = py_ast.Code(
        "procedure",
        py_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[],
            type_params=None,
        ),
        py_ast.Suite([operation]),
    )
    heap.bind_allocation_targets(code, (obj,), "obj", label="obj")
    heap.bind_allocation_targets(code, (value,), "value", label="value")
    builder = HeapEffectBuilder(heap, locations)
    operation_semantics = builder.operation_semantics(code, operation)
    summary = HeapSummaryBuilder(builder).summarize(code)

    assert summary.writes == operation_semantics.effect.writes
    assert summary.escapes == operation_semantics.effect.escapes


def test_future_reference_expression_uses_explicit_unknown_fallback():
    heap = _heap()
    engine = HeapTransferEngine(heap)
    result = engine.locations_for_expression(
        None,
        FutureReferenceExpression(),
    )

    assert result
    assert result[0].root.kind is HeapObjectKind.UNKNOWN


def test_execution_summary_carries_effects_for_ifds_consumers():
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    callee = py_ast.Code(
        "callee",
        py_ast.CodeParameters(
            None,
            [],
            [],
            [obj, value],
            ["obj", "value"],
            [],
            None,
            None,
            [],
            None,
        ),
        py_ast.Suite(
            [py_ast.SetAttr(value, obj, py_ast.Existing(py_ast.program.Object("field")))]
        ),
    )
    actual_obj = py_ast.Local("actual_obj")
    actual_value = py_ast.Local("actual_value")
    caller = py_ast.Code(
        "caller",
        py_ast.CodeParameters(None, [], [], [], [], [], None, None, [], None),
        py_ast.Suite(
            [
                py_ast.Assign(py_ast.BuildList([]), [actual_obj]),
                py_ast.Assign(py_ast.BuildList([]), [actual_value]),
                py_ast.Discard(
                    py_ast.DirectCall(
                        callee,
                        None,
                        [actual_obj, actual_value],
                        [],
                        None,
                        None,
                    )
                ),
            ]
        ),
    )

    analysis = HeapAnalysis()
    analysis.analyze(None, caller)
    summary = analysis.procedure_summaries[callee]

    assert summary.effects.writes
    adapter = CFGSupergraphAdapter(
        [],
        procedure_heap_summaries=analysis.procedure_summaries,
    )
    assert adapter.procedure_heap_summary(SimpleNamespace(code=callee)) is summary


def test_procedure_summary_merge_preserves_effects_and_degradations():
    heap = _heap()
    left_location = HeapLocation(heap.allocation_object(None, "left", label="left"))
    right_location = HeapLocation(heap.allocation_object(None, "right", label="right"))
    left = ProcedureHeapSummary(
        effects=HeapSummaryBuilder(
            HeapEffectBuilder(heap, lambda _procedure, _expression: ())
        ).summarize(None),
        deletes=(left_location,),
        precision_degradations=frozenset({"left"}),
    )
    right = ProcedureHeapSummary(
        deletes=(right_location,),
        precision_degradations=frozenset({"right"}),
    )

    merged = left.merge(right)

    assert set(merged.deletes) == {left_location, right_location}
    assert merged.precision_degradations == frozenset({"left", "right"})
