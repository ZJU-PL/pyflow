"""Regression tests for the formal CPG taint fixed-point engine."""

from __future__ import annotations

import importlib

import pytest

from pyflow.analysis.entrypoints import EntryPointMode, EntryPointOptions
from pyflow.checker.ast_dataflow.domain import (
    TaintLocation,
    TaintOrigin,
    TaintState as FormalTaintState,
)
from pyflow.checker.ast_dataflow.semantics import UpdateDecision
from pyflow.ir.cpg import CodePropertyGraph, build_cpg
from pyflow.ir.cpg.graph import CPGEdgeKind
from pyflow.ir.cpg.taint import CPGTaintEngine
from pyflow.ir.cpg.taint.formal import CPGAbstractState, FormalCPGTaintAnalysis
from pyflow.language.python import ast as py_ast


def _engine(source: str, **kwargs) -> CPGTaintEngine:
    engine = CPGTaintEngine(build_cpg(source), **kwargs)
    engine.add_source("input")
    engine.add_sink("eval", cwe="CWE-95")
    return engine


def test_cpg_uses_shared_entrypoint_selection_modes() -> None:
    engine = CPGTaintEngine(
        build_cpg(
            "def left():\n    return right()\n"
            "def right():\n    return left()\n"
            "def root():\n    return 1\n"
        ),
        entry_point_options=EntryPointOptions(
            mode=EntryPointMode.INFERRED_ROOTS,
            include_synthetic_modules=False,
        ),
    )

    entries = FormalCPGTaintAnalysis(engine)._root_entries()

    assert tuple(engine._cpg.node_func_name(node) for node in entries) == ("root",)


def test_cpg_entry_parameter_taint_is_an_independent_option() -> None:
    source = "def handler(value):\n    eval(value)\n"
    clean = _engine(
        source,
        entry_point_options=EntryPointOptions(
            mode=EntryPointMode.ALL_PROCEDURES,
            taint_parameters=False,
        ),
    ).analyze()
    tainted = _engine(
        source,
        entry_point_options=EntryPointOptions(
            mode=EntryPointMode.ALL_PROCEDURES,
            taint_parameters=True,
        ),
    ).analyze()

    assert clean.findings == ()
    assert len(tainted.findings) == 1


def test_cpg_abstract_state_is_an_immutable_join_semilattice() -> None:
    location = TaintLocation("x")
    tainted = FormalTaintState().introduce(
        location, {"untrusted"}, TaintOrigin("untrusted", symbol="source")
    )
    clean = CPGAbstractState()
    left = CPGAbstractState(tainted)
    right = CPGAbstractState().bind_alias(TaintLocation("y"), location)

    assert clean.join(left) == left.join(clean) == left
    assert left.join(left) == left
    assert left.leq(left.join(right))
    assert right.leq(left.join(right))
    assert left.join(right) == right.join(left)


def test_inferred_supergraph_edges_are_direct_and_returns_are_matched() -> None:
    cpg = build_cpg(
        "def identity(value):\n"
        "    return value\n"
        "def recursive(value):\n"
        "    return recursive(value)\n"
        "def main():\n"
        "    return identity(recursive('safe'))\n"
    )
    call_edges = [
        edge
        for node in cpg.nodes()
        for edge in cpg._cpg_edges_out.get(node.node_id, ())
        if edge.kind is CPGEdgeKind.CALL
    ]

    assert any(cpg.node_func_name(edge.source) == "recursive" for edge in call_edges)
    assert not any(
        isinstance(edge.source.ast_node, py_ast.FunctionDef) for edge in call_edges
    )
    assert {
        cpg.node_func_name(edge.target)
        for edge in call_edges
        if cpg.node_func_name(edge.source) == "main"
    } == {"identity", "recursive"}
    for edge in call_edges:
        callee = cpg.node_func_name(edge.target)
        exits = cpg._pdgs[callee].exit_nodes
        assert all(
            any(
                returned.kind is CPGEdgeKind.RETURN_EDGE
                and returned.target is edge.source
                for returned in cpg._cpg_edges_out.get(exit_node.node_id, ())
            )
            for exit_node in exits
        )


def test_full_sanitizer_assignment_kills_flow() -> None:
    engine = _engine(
        "def main():\n"
        "    value = input()\n"
        "    cleaned = clean(value)\n"
        "    eval(cleaned)\n"
    )
    engine.add_sanitizer("clean")

    result = engine.analyze()

    assert result.status == "complete"
    assert result.findings == ()


def test_selective_sanitizer_preserves_other_kinds_and_provenance() -> None:
    engine = CPGTaintEngine(
        build_cpg(
            "def main():\n"
            "    value = input()\n"
            "    cleaned = clean_sql(value)\n"
            "    eval(cleaned)\n"
        )
    )
    # Registering a custom kind after a manual sink must extend the manual
    # rule, rather than silently limiting it to the historical default kind.
    engine.add_sink("eval")
    engine.add_source("input", "sql")
    engine.add_source("input", "shell")
    engine.add_sanitizer("clean_sql", frozenset({"sql"}))

    result = engine.analyze()

    assert len(result.findings) == 1
    assert result.findings[0].tags == frozenset({"shell"})
    assert result.findings[0].sanitizers == frozenset({"clean_sql"})


@pytest.mark.parametrize(
    "wrapper_body",
    ["    return input()\n", "    value = input()\n    return value\n"],
)
def test_precise_interprocedural_source_return_reaches_sink(wrapper_body: str) -> None:
    engine = _engine(
        "def wrapper():\n" + wrapper_body + "def main():\n"
        "    value = wrapper()\n"
        "    eval(value)\n"
    )

    result = engine.analyze()

    assert len(result.findings) == 1
    assert result.statistics["processed_states"] > 0
    assert any("input" in finding.source_label for finding in result.findings)


def test_relational_nested_call_summary_observes_strong_overwrite() -> None:
    clean = _engine(
        "def wrapper():\n"
        "    value = input()\n"
        "    value = 'safe'\n"
        "    return value\n"
        "def main():\n"
        "    eval(wrapper())\n"
    ).analyze()
    tainted_engine = _engine(
        "def wrapper():\n"
        "    value = input()\n"
        "    return value\n"
        "def main():\n"
        "    eval(wrapper())\n"
    )
    tainted = tainted_engine.analyze()

    assert clean.findings == ()
    assert len(tainted.findings) == 1
    assert "input" in tainted.findings[0].source_label
    assert all(
        any(
            edge.target is target
            for edge in tainted_engine._cpg._cpg_edges_out.get(source.node_id, ())
        )
        for source, target in zip(
            tainted.findings[0].path_nodes, tainted.findings[0].path_nodes[1:]
        )
    )


def test_matched_calls_do_not_mix_results_between_call_sites() -> None:
    result = _engine(
        "def identity(value):\n"
        "    return value\n"
        "def main():\n"
        "    safe = identity('safe')\n"
        "    dirty = identity(input())\n"
        "    eval(safe)\n"
        "    eval(dirty)\n"
    ).analyze()

    assert len(result.findings) == 1
    assert result.findings[0].sink_label == "eval"


def test_nested_relational_summary_binds_keyword_arguments_by_name() -> None:
    result = _engine(
        "def pick_first(first, second):\n"
        "    return first\n"
        "def main():\n"
        "    eval(pick_first(second=input(), first='safe'))\n"
        "    eval(pick_first(second='safe', first=input()))\n"
    ).analyze()

    assert len(result.findings) == 1


def test_recursive_call_uses_finite_relational_summary() -> None:
    result = _engine(
        "def recursive(value):\n"
        "    return recursive(value)\n"
        "def main():\n"
        "    value = recursive(input())\n"
        "    eval(value)\n"
    ).analyze()

    assert len(result.findings) == 1
    assert result.statistics["summary_applications"] >= 1
    assert "cpg-call-depth-summary" in {item.code for item in result.diagnostics}


def test_recursive_call_graph_sccs_are_analyzed_as_public_entries() -> None:
    result = _engine(
        "def first():\n"
        "    return second()\n"
        "def second():\n"
        "    value = input()\n"
        "    eval(value)\n"
        "    return first()\n"
    ).analyze()

    assert len(result.findings) == 1


def test_data_edges_are_consulted_but_cannot_bypass_a_kill() -> None:
    result = _engine(
        "def main():\n"
        "    value = input()\n"
        "    value = 'safe'\n"
        "    eval(value)\n"
    ).analyze()

    assert result.findings == ()
    assert result.statistics["data_dependencies_consulted"] > 0


def test_unknown_call_havocs_argument_conservatively_without_partial_status() -> None:
    result = _engine(
        "def main():\n"
        "    value = None\n"
        "    mutate(value)\n"
        "    eval(value.field)\n"
    ).analyze()

    assert len(result.findings) == 1
    assert result.status == "complete"
    diagnostic = next(
        item for item in result.diagnostics if item.code == "cpg-unknown-call-effect"
    )
    assert diagnostic.affects_completeness is False
    assert diagnostic.level == "conservative"


def test_pure_string_method_preserves_existing_taint_without_inventing_it() -> None:
    tainted = _engine(
        "def main():\n" "    value = input().lower()\n" "    eval(value)\n"
    ).analyze()
    clean = _engine(
        "def main():\n" "    value = 'safe'.lower()\n" "    eval(value)\n"
    ).analyze()

    assert len(tainted.findings) == 1
    assert clean.findings == ()
    assert "cpg-unknown-call-effect" not in {
        diagnostic.code for diagnostic in clean.diagnostics
    }


def test_interpreter_string_helpers_propagate_only_existing_taint() -> None:
    tainted = _engine(
        "def main():\n" "    value = input()\n" "    eval(f'prefix: {value}')\n"
    ).analyze()
    clean = _engine("def main():\n" "    eval(f'prefix: {42}')\n").analyze()

    assert len(tainted.findings) == 1
    assert clean.findings == ()
    assert not any(
        diagnostic.code == "cpg-unknown-call-effect"
        and diagnostic.operation
        and diagnostic.operation.startswith("interpreter_")
        for diagnostic in clean.diagnostics
    )


def test_nested_sink_calls_are_events_not_lost_inside_outer_expressions() -> None:
    result = _engine(
        "def main():\n" "    value = input()\n" "    consume(eval(value))\n"
    ).analyze()

    assert len(result.findings) == 1
    assert result.findings[0].sink_label == "eval"


class _SingletonRefinement:
    def __init__(self) -> None:
        self.requests = 0

    def update_decision(self, location, program_point) -> UpdateDecision:
        self.requests += 1
        return UpdateDecision(True, ("test-singleton",))


def test_heap_refinement_enables_sound_strong_field_updates() -> None:
    source = (
        "def main():\n"
        "    box = None\n"
        "    box.value = input()\n"
        "    box.value = 'safe'\n"
        "    eval(box.value)\n"
    )
    conservative = _engine(source).analyze()
    refinement = _SingletonRefinement()
    refined = _engine(source, refinement=refinement).analyze()

    assert len(conservative.findings) == 1
    assert refined.findings == ()
    assert refinement.requests >= 2


@pytest.mark.parametrize(
    ("literal", "safe_access", "tainted_access"),
    [
        ("{'bad': input(), 'good': 'safe'}", "['good']", "['bad']"),
        ("[input(), 'safe']", "[1]", "[0]"),
    ],
)
def test_collection_literals_and_getitem_are_field_sensitive(
    literal: str, safe_access: str, tainted_access: str
) -> None:
    result = _engine(
        "def main():\n"
        f"    payload = {literal}\n"
        f"    eval(payload{safe_access})\n"
        f"    eval(payload{tainted_access})\n"
    ).analyze()

    assert len(result.findings) == 1
    assert result.status == "complete"


@pytest.mark.parametrize(
    "source",
    [
        (
            "def identity(value):\n"
            "    return value\n"
            "def main():\n"
            "    box = None\n"
            "    alias = identity(box)\n"
            "    alias.value = input()\n"
            "    eval(box.value)\n"
        ),
        (
            "def make():\n"
            "    box = None\n"
            "    box.value = input()\n"
            "    return box\n"
            "def main():\n"
            "    result = make()\n"
            "    eval(result.value)\n"
        ),
    ],
)
def test_return_transfer_preserves_aliases_and_field_paths(source: str) -> None:
    result = _engine(source).analyze()

    assert len(result.findings) == 1


def test_global_storage_is_shared_across_precise_local_calls() -> None:
    result = _engine(
        "value = None\n"
        "def source():\n"
        "    global value\n"
        "    value = input()\n"
        "def sink():\n"
        "    eval(value)\n"
        "def main():\n"
        "    source()\n"
        "    sink()\n"
    ).analyze()

    assert len(result.findings) == 1


def test_import_time_global_state_seeds_public_function_entries() -> None:
    result = _engine("value = input()\n" "def sink():\n" "    eval(value)\n").analyze()

    assert len(result.findings) == 1


def test_budgets_and_loop_configuration_are_explicit() -> None:
    with pytest.raises(ValueError):
        CPGTaintEngine(build_cpg("pass"), max_loop_iterations=0)

    result = _engine(
        "def main():\n    value = input()\n    eval(value)\n", max_states=1
    ).analyze()

    assert result.status == "partial"
    assert "cpg-state-budget" in {item.code for item in result.diagnostics}
    assert "loop_threshold_crossings" in result.statistics

    loop_result = _engine(
        "def main(flag):\n"
        "    value = 'safe'\n"
        "    while flag:\n"
        "        value = input()\n"
        "    eval(value)\n",
        max_loop_iterations=1,
    ).analyze()
    assert loop_result.statistics["loop_threshold_crossings"] > 0
    assert "cpg-loop-convergence-threshold" in {
        item.code for item in loop_result.diagnostics
    }


def test_empty_graph_is_explicitly_incomplete() -> None:
    result = CPGTaintEngine(CodePropertyGraph()).analyze()

    assert result.status == "partial"
    assert "cpg-empty-graph" in {item.code for item in result.diagnostics}


def test_cpg_construction_failures_are_not_silently_dropped(monkeypatch) -> None:
    build_module = importlib.import_module("pyflow.ir.cpg.build")

    def fail_cfg(*_args, **_kwargs):
        raise RuntimeError("synthetic CFG failure")

    monkeypatch.setattr(build_module.cfg_transform, "evaluate", fail_cfg)
    result = CPGTaintEngine(
        build_module.build_cpg("def target():\n    pass\n")
    ).analyze()

    assert result.status == "partial"
    assert "cpg-cfg-build-failed" in {item.code for item in result.diagnostics}


def test_conditional_expression_in_loop_does_not_drop_the_procedure() -> None:
    engine = _engine(
        "def target(flag):\n"
        "    value = 'safe'\n"
        "    for item in ([1] if flag else []):\n"
        "        value = input()\n"
        "    eval(value)\n"
    )

    result = engine.analyze()

    assert "target" in engine._cpg.functions
    assert len(result.findings) == 1


def test_structured_try_joins_handler_effects() -> None:
    engine = _engine(
        "def target():\n"
        "    value = 'safe'\n"
        "    try:\n"
        "        value = 'still safe'\n"
        "    except Exception:\n"
        "        value = input()\n"
        "    eval(value)\n"
    )

    result = engine.analyze()

    assert len(result.findings) == 1
    assert "cpg-exception-overapproximation" in {
        item.code for item in result.diagnostics
    }


def test_structured_try_handles_bare_except_suite() -> None:
    engine = _engine(
        "def target():\n"
        "    value = 'safe'\n"
        "    try:\n"
        "        value = 'still safe'\n"
        "    except:\n"
        "        value = input()\n"
        "    eval(value)\n"
    )

    result = engine.analyze()

    assert len(result.findings) == 1
    assert "cpg-exception-overapproximation" in {
        item.code for item in result.diagnostics
    }


def test_structured_try_finally_strong_overwrite_kills_taint() -> None:
    engine = _engine(
        "def target():\n"
        "    try:\n"
        "        value = input()\n"
        "    finally:\n"
        "        value = 'safe'\n"
        "    eval(value)\n"
    )

    result = engine.analyze()

    assert result.findings == ()


def test_structured_switch_joins_tainted_branch_without_partial_status() -> None:
    result = _engine(
        "def target(flag):\n"
        "    value = 'safe'\n"
        "    if flag:\n"
        "        value = input()\n"
        "    eval(value)\n"
    ).analyze()

    assert len(result.findings) == 1
    assert result.status == "complete"


def test_structured_while_reaches_fixed_point_without_partial_status() -> None:
    result = _engine(
        "def target(flag):\n"
        "    value = 'safe'\n"
        "    while flag:\n"
        "        value = input()\n"
        "        flag = False\n"
        "    eval(value)\n"
    ).analyze()

    assert len(result.findings) == 1
    assert result.status == "complete"


def test_absent_with_finally_does_not_reenter_the_enclosing_try() -> None:
    result = _engine(
        "def main():\n"
        "    for item in items:\n"
        "        with context:\n"
        "            eval(input())\n"
    ).analyze()

    assert len(result.findings) == 1
    assert result.findings[0].sink_label == "eval"
