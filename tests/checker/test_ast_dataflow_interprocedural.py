from pyflow.analysis.taint import TaintPolicy, TaintRule
from pyflow.checker.ast_dataflow.semantics import TaintSinkEvent
from pyflow.checker.ast_dataflow.solver.interprocedural import (
    ASTInterproceduralAnalyzer,
)
from pyflow.checker.ast_dataflow.solver import SummaryPort, SummaryPortKind
from pyflow.checker.ast_dataflow.semantics import UpdateDecision

POLICY = TaintPolicy(
    source_kinds_by_call={"input": frozenset({"user_input"})},
    sink_kinds_by_call={"eval": frozenset({"code_execution"})},
    sink_positions_by_call={"eval": frozenset({0})},
    rules=(
        TaintRule(
            "TEST-RCE",
            "Untrusted code execution",
            frozenset({"user_input"}),
            frozenset({"code_execution"}),
        ),
    ),
)


def test_interprocedural_relational_summaries_connect_source_and_sink():
    result = ASTInterproceduralAnalyzer(POLICY).analyze(
        {
            "source": "def source():\n    return input()\n",
            "identity": "def identity(value):\n    return value\n",
            "sink": "def sink(value):\n    eval(value)\n",
            "main": (
                "def main():\n"
                "    value = source()\n"
                "    value = identity(value)\n"
                "    sink(value)\n"
            ),
        }
    )

    events = {
        event
        for analysis in result.analyses.values()
        for event in analysis.events
        if isinstance(event, TaintSinkEvent) and "user_input" in event.source_kinds
    }
    identity_return = result.summaries["identity"].propagate(
        {
            SummaryPort(SummaryPortKind.PARAMETER, index=0): {"user_input"},
        }
    )

    assert events
    assert identity_return[SummaryPort(SummaryPortKind.RETURN)] == frozenset(
        {"user_input"}
    )
    assert result.rounds >= 2


def test_interprocedural_summary_does_not_create_flow_after_strong_kill():
    result = ASTInterproceduralAnalyzer(POLICY).analyze(
        {
            "clean_identity": (
                "def clean_identity(value):\n"
                "    value = 'safe'\n"
                "    return value\n"
            )
        }
    )
    summary = result.summaries["clean_identity"]
    values = summary.propagate(
        {SummaryPort(SummaryPortKind.PARAMETER, index=0): {"user_input"}}
    )

    assert SummaryPort(SummaryPortKind.RETURN) not in values


def test_outcome_sensitive_summaries_separate_yield_and_raise():
    result = ASTInterproceduralAnalyzer(POLICY).analyze(
        {
            "generator": "def generator(value):\n    yield value\n",
            "fail": "def fail(value):\n    raise ValueError(value)\n",
        }
    )
    parameter = SummaryPort(SummaryPortKind.PARAMETER, index=0)

    yielded = result.summaries["generator"].propagate({parameter: {"user_input"}})
    raised = result.summaries["fail"].propagate({parameter: {"user_input"}})

    assert yielded[SummaryPort(SummaryPortKind.YIELD)] == frozenset({"user_input"})
    assert raised[SummaryPort(SummaryPortKind.RAISE)] == frozenset({"user_input"})


def test_unique_method_suffix_resolves_to_relational_summary():
    result = ASTInterproceduralAnalyzer(POLICY).analyze(
        {
            "identity": "def identity(self, value):\n    return value\n",
            "main": (
                "def main(self):\n"
                "    value = input()\n"
                "    eval(self.identity(value))\n"
            ),
        }
    )

    events = [
        event
        for event in result.analyses["main"].events
        if isinstance(event, TaintSinkEvent) and "user_input" in event.source_kinds
    ]

    assert len(events) == 1


def test_parameter_path_write_effect_is_applied_in_caller():
    result = ASTInterproceduralAnalyzer(POLICY).analyze(
        {
            "fill": ("def fill(payload):\n" "    payload['command'] = input()\n"),
            "main": (
                "def main():\n"
                "    payload = {}\n"
                "    fill(payload)\n"
                "    eval(payload['command'])\n"
            ),
        }
    )

    events = [
        event
        for event in result.analyses["main"].events
        if isinstance(event, TaintSinkEvent) and "user_input" in event.source_kinds
    ]

    assert result.summaries["fill"].writes
    assert len(events) == 1


class _StrongPaths:
    def update_decision(self, location, program_point):
        return UpdateDecision(True, ("test-singleton",))


def test_must_kill_parameter_path_effect_sanitizes_caller_heap():
    result = ASTInterproceduralAnalyzer(POLICY, refinement=_StrongPaths()).analyze(
        {
            "clean": ("def clean(payload):\n" "    payload['command'] = 'safe'\n"),
            "main": (
                "def main():\n"
                "    payload = {'command': input()}\n"
                "    clean(payload)\n"
                "    eval(payload['command'])\n"
            ),
        }
    )

    events = [
        event
        for event in result.analyses["main"].events
        if isinstance(event, TaintSinkEvent) and "user_input" in event.source_kinds
    ]

    assert result.summaries["clean"].kills
    assert events == []


def test_explicit_entry_functions_define_reachability_closure():
    result = ASTInterproceduralAnalyzer(POLICY).analyze(
        {
            "helper": "def helper():\n    return input()\n",
            "main": "def main():\n    eval(helper())\n",
            "unreachable": "def unreachable():\n    eval(input())\n",
        },
        entry_functions=("main",),
    )

    assert result.reachable == frozenset({"main", "helper"})


def test_recursive_summary_converges_to_parameter_return_dependency():
    result = ASTInterproceduralAnalyzer(POLICY).analyze(
        {
            "recurse": (
                "def recurse(value, again):\n"
                "    if again:\n"
                "        return recurse(value, False)\n"
                "    return value\n"
            )
        },
        entry_functions=("recurse",),
    )
    values = result.summaries["recurse"].propagate(
        {
            SummaryPort(SummaryPortKind.PARAMETER, index=0): {"user_input"},
        }
    )

    assert values[SummaryPort(SummaryPortKind.RETURN)] == frozenset({"user_input"})
    assert result.status == "complete"
