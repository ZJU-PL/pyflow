from itertools import product

from pyflow.checker.ast_dataflow.solver import (
    ProcedureTaintSummary,
    SummaryPort,
    SummaryPortKind,
    SummaryRelation,
    SummarySinkEvent,
)

P0 = SummaryPort(SummaryPortKind.PARAMETER, name="payload", index=0)
FIELD = P0.select("command")
RETURN = SummaryPort(SummaryPortKind.RETURN)
SINK = SummaryPort(SummaryPortKind.SINK, name="eval", index=0)


def test_relational_summary_propagates_paths_and_kind_transforms():
    summary = ProcedureTaintSummary(
        "helper",
        relations=frozenset(
            {
                SummaryRelation(P0, FIELD),
                SummaryRelation(
                    FIELD,
                    RETURN,
                    mapped_kinds=(("html.raw", "html.escaped"),),
                    removed_kinds=frozenset({"shell"}),
                ),
                SummaryRelation(RETURN, SINK),
            }
        ),
    )

    values = summary.propagate({P0: {"html.raw", "shell"}})

    assert values[RETURN] == frozenset({"html.escaped"})
    assert values[SINK] == frozenset({"html.escaped"})


def test_summary_join_is_a_semilattice():
    empty = ProcedureTaintSummary("f")
    returns = ProcedureTaintSummary(
        "f", relations=frozenset({SummaryRelation(P0, RETURN)})
    )
    sinks = ProcedureTaintSummary(
        "f",
        sinks=frozenset({SummarySinkEvent("eval", 0, P0, 3)}),
    )
    states = (empty, returns, sinks, returns.join(sinks))

    for state in states:
        assert state.join(state) == state
        assert state.leq(state)
    for left, right in product(states, repeat=2):
        assert left.join(right) == right.join(left)
        assert left.leq(left.join(right))
    for first, second, third in product(states, repeat=3):
        assert first.join(second).join(third) == first.join(second.join(third))


def test_summary_seeds_represent_unconditional_source_flows():
    summary = ProcedureTaintSummary(
        "source",
        seeds=frozenset({(RETURN, "user_input")}),
    )

    assert summary.propagate({})[RETURN] == frozenset({"user_input"})


def test_summary_token_propagation_preserves_parameter_identity():
    p1 = SummaryPort(SummaryPortKind.PARAMETER, index=1)
    summary = ProcedureTaintSummary(
        "select_second",
        relations=frozenset({SummaryRelation(p1, RETURN)}),
    )
    first_origin = object()
    second_origin = object()

    values = summary.propagate_tokens(
        {
            P0: {("user_input", first_origin)},
            p1: {("user_input", second_origin)},
        }
    )

    assert values[RETURN] == frozenset({("user_input", second_origin)})
