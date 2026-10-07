"""Independent, hand-authored MIR regression tests for the native PyCG solver."""

from __future__ import annotations

import ast

import pytest

from pyflow.analysis.callgraph.pycg_mir import (
    PyCGMIRConvergenceError,
    PyCGMIRConvergenceWarning,
    analyze_program,
)
from pyflow.ir.mir.model import (
    Alloc,
    Assume,
    Attr,
    Binary,
    Bind,
    Call,
    CFG,
    Delete,
    DictExpr,
    Env,
    Lambda,
    Length,
    ListExpr,
    Literal,
    MIRValidationError,
    NewObject,
    Node,
    Program,
    Skip,
    Var,
)


def cfg(name, *commands, synthetic=False):
    commands = (*commands, Skip())
    nodes = {
        index: Node(index, command, (index + 1,) if index + 1 < len(commands) else ())
        for index, command in enumerate(commands)
    }
    return CFG(name, nodes, 0, len(commands) - 1, is_synthetic=synthetic)


def program(*cfgs):
    return Program({item.name: item for item in cfgs}, cfgs[0].name)


def function(name):
    return Lambda("args", "kwargs", "parent", name, "return")


def leaf(name):
    return cfg(name, Alloc("return", Literal(0)))


def empty_arguments():
    return (Alloc("empty_args", ListExpr(())), Alloc("empty_kwargs", DictExpr(())))


def invoke(target, result="result"):
    return Call(result, target, Var("empty_args"), Var("empty_kwargs"))


def test_direct_calls_and_assignment_graph_do_not_require_python_ast(monkeypatch):
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        *empty_arguments(),
        Bind(Var("alias"), Var("f")),
        invoke(Var("alias")),
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("The MIR solver must not parse Python")

    monkeypatch.setattr(ast, "parse", forbidden)
    result = analyze_program(program(main, leaf("main.f")))
    assert result.converged
    assert result.call_graph.get() == {"main": {"main.f"}, "main.f": set()}
    assert "main::f" in result.assignment_graph["main::alias"]
    assert "@alloc:main:0" in result.assignment_graph["main::f"]
    assert "main.f" in result.assignment_graph["@alloc:main:0"]
    assert not result.unresolved_calls


def test_higher_order_arguments_join_across_call_sites():
    apply = cfg(
        "main.apply",
        Bind(Var("callback"), Attr(Var("args"), Literal(1))),
        *empty_arguments(),
        invoke(Var("callback"), "return"),
    )
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        Alloc("apply", function("main.apply")),
        *empty_arguments(),
        Alloc("first", ListExpr((Var("f"),))),
        Alloc("second", ListExpr((Var("g"),))),
        Call("one", Var("apply"), Var("first"), Var("empty_kwargs")),
        Call("two", Var("apply"), Var("second"), Var("empty_kwargs")),
    )
    result = analyze_program(program(main, apply, leaf("main.f"), leaf("main.g")))
    assert result.call_graph.get()["main"] == {"main.apply"}
    assert result.call_graph.get()["main.apply"] == {"main.f", "main.g"}


def test_keyword_container_and_return_alias_propagation():
    choose = cfg("main.choose", Bind(Var("return"), Attr(Var("kwargs"), Literal("callback"))))
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("choose", function("main.choose")),
        *empty_arguments(),
        Alloc("named", DictExpr((("callback", Var("f")),))),
        Call("selected", Var("choose"), Var("empty_args"), Var("named")),
        invoke(Var("selected")),
    )
    result = analyze_program(program(main, choose, leaf("main.f")))
    assert result.call_graph.get()["main"] == {"main.choose", "main.f"}
    assert "main.choose::return" in result.assignment_graph["main::selected"]


def test_returned_closure_captures_first_class_lexical_environment():
    factory = cfg(
        "main.factory",
        Bind(Var("callback"), Attr(Var("args"), Literal(1))),
        Alloc("return", function("main.factory.inner")),
    )
    inner = cfg(
        "main.factory.inner",
        Bind(Var("callback"), Attr(Var("parent"), Literal("callback"))),
        *empty_arguments(),
        invoke(Var("callback"), "return"),
    )
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("factory", function("main.factory")),
        *empty_arguments(),
        Alloc("actuals", ListExpr((Var("f"),))),
        Call("closed", Var("factory"), Var("actuals"), Var("empty_kwargs")),
        invoke(Var("closed")),
    )
    result = analyze_program(program(main, factory, inner, leaf("main.f")))
    graph = result.call_graph.get()
    assert graph["main"] == {"main.factory", "main.factory.inner"}
    assert graph["main.factory.inner"] == {"main.f"}
    assert "@env:main.factory" in result.assignment_graph["main.factory.inner::parent"]


def test_direct_recursion_and_recursive_higher_order_flow_are_retained():
    recursive = cfg(
        "main.recur",
        *empty_arguments(),
        Bind(Var("recur"), Attr(Var("parent"), Literal("recur"))),
        invoke(Var("recur"), "return"),
    )
    main = cfg(
        "main", Alloc("recur", function("main.recur")), *empty_arguments(), invoke(Var("recur"))
    )
    result = analyze_program(program(main, recursive))
    assert result.converged
    assert result.call_graph.get()["main.recur"] == {"main.recur"}
    assert ("main.recur", "main.recur") in set(result.call_graph.edges())


def test_bind_aliases_objects_but_alloc_copies_container_value():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Alloc("object", NewObject()),
        Bind(Attr(Var("object"), Literal("method")), Var("f")),
        Bind(Var("alias"), Var("object")),
        Alloc("copy", Var("object")),
        Bind(Attr(Var("copy"), Literal("method")), Var("g")),
        invoke(Attr(Var("alias"), Literal("method")), "original_call"),
        invoke(Attr(Var("copy"), Literal("method")), "copy_call"),
    )
    result = analyze_program(program(main, leaf("main.f"), leaf("main.g")))
    assert result.call_sites[("main", 9)] == {"main.f"}
    assert result.call_sites[("main", 10)] == {"main.f", "main.g"}


def test_field_sensitivity_separates_same_named_fields_on_distinct_objects():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Alloc("left", DictExpr((("method", Var("f")),))),
        Alloc("right", DictExpr((("method", Var("g")),))),
        invoke(Attr(Var("left"), Literal("method"))),
        invoke(Attr(Var("right"), Literal("method"))),
    )
    result = analyze_program(program(main, leaf("main.f"), leaf("main.g")))
    assert result.call_sites[("main", 6)] == {"main.f"}
    assert result.call_sites[("main", 7)] == {"main.g"}


def test_lists_are_one_based_and_constant_index_sensitive():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Alloc("items", ListExpr((Var("f"), Var("g")))),
        invoke(Attr(Var("items"), Literal(1))),
        invoke(Attr(Var("items"), Literal(2))),
    )
    result = analyze_program(program(main, leaf("main.f"), leaf("main.g")))
    assert result.call_sites[("main", 5)] == {"main.f"}
    assert result.call_sites[("main", 6)] == {"main.g"}


def test_unknown_string_key_reads_all_string_fields():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Alloc("items", DictExpr((("first", Var("f")), ("second", Var("g"))))),
        Alloc("unknown", Binary("+", Literal("prefix"), Literal("suffix"))),
        invoke(Attr(Var("items"), Var("unknown"))),
    )
    result = analyze_program(program(main, leaf("main.f"), leaf("main.g")))
    assert result.call_graph.get()["main"] == {"main.f", "main.g"}
    assert "@unknown:str" in result.assignment_graph["@alloc:main:5"]


def test_unknown_integer_key_reads_all_integer_fields_and_writes_summary():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Alloc("items", ListExpr((Var("f"),))),
        Alloc("unknown", Binary("+", Literal(42), Literal(42))),
        Bind(Attr(Var("items"), Var("unknown")), Var("g")),
        invoke(Attr(Var("items"), Literal(1))),
        invoke(Attr(Var("items"), Var("unknown"))),
    )
    result = analyze_program(program(main, leaf("main.f"), leaf("main.g")))
    assert result.call_sites[("main", 7)] == {"main.f", "main.g"}
    assert result.call_sites[("main", 8)] == {"main.f", "main.g"}


def test_integer_arithmetic_loop_widens_and_converges():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Alloc("items", ListExpr((Var("f"), Var("g")))),
        Alloc("index", Literal(0)),
        Alloc("index", Binary("+", Var("index"), Literal(1))),
        invoke(Attr(Var("items"), Var("index"))),
    )
    main.nodes[7].successors = (6, 8)
    result = analyze_program(program(main, leaf("main.f"), leaf("main.g")))
    assert result.converged and result.iterations < 20
    assert result.call_graph.get()["main"] == {"main.f", "main.g"}
    assert "@unknown:int" in result.assignment_graph["@alloc:main:6"]


def test_large_unrelated_literal_does_not_delay_arithmetic_widening():
    main = cfg(
        "main",
        Alloc("first", function("main.first")),
        Alloc("last", function("main.last")),
        *empty_arguments(),
        Alloc("large", ListExpr((Var("first"),) * 599 + (Var("last"),))),
        Alloc("index", Literal(0)),
        Alloc("index", Binary("+", Var("index"), Literal(1))),
        invoke(Attr(Var("large"), Var("index"))),
        invoke(Attr(Var("large"), Literal(1))),
        invoke(Attr(Var("large"), Literal(600))),
    )
    main.nodes[9].successors = (6, 10)
    result = analyze_program(
        program(main, leaf("main.first"), leaf("main.last")),
        max_iterations=64,
        raise_on_truncation=True,
    )
    assert result.converged and result.iterations <= 32
    # Top subsumes old computed integers, while literal sites stay singleton.
    assert result.assignment_graph["@alloc:main:6"] == {"@unknown:int"}
    assert result.assignment_graph["@alloc:main:5"] == {"@literal:int:0"}
    assert result.call_sites[("main", 7)] == {"main.first", "main.last"}
    # Widening an unrelated arithmetic result must not coarsen constant reads.
    assert result.call_sites[("main", 8)] == {"main.first"}
    assert result.call_sites[("main", 9)] == {"main.last"}


def test_list_concatenation_loop_has_finite_summary_indices():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Alloc("items", ListExpr((Var("f"),))),
        Alloc("items", Binary("+", Var("items"), ListExpr((Var("g"),)))),
        Alloc("index", Length(Var("items"))),
        invoke(Attr(Var("items"), Var("index"))),
    )
    main.nodes[7].successors = (5, 8)
    result = analyze_program(program(main, leaf("main.f"), leaf("main.g")))
    assert result.converged and result.iterations < 20
    assert result.call_graph.get()["main"] == {"main.f", "main.g"}


def test_list_prefix_loop_widens_even_with_large_unrelated_literal_domain():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Alloc("unrelated", ListExpr((Var("f"),) * 600)),
        Alloc("items", ListExpr((Var("f"),))),
        Alloc("items", Binary("+", ListExpr((Var("g"),)), Var("items"))),
        Alloc("index", Length(Var("items"))),
        invoke(Attr(Var("items"), Var("index"))),
    )
    main.nodes[8].successors = (6, 9)
    result = analyze_program(
        program(main, leaf("main.f"), leaf("main.g")),
        max_iterations=64,
        raise_on_truncation=True,
    )
    assert result.converged and result.iterations <= 40
    assert result.call_graph.get()["main"] == {"main.f", "main.g"}


def test_deleting_a_list_item_preserves_shifted_possible_callees():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Alloc("items", ListExpr((Var("f"), Var("g")))),
        Delete(Attr(Var("items"), Literal(1))),
        invoke(Attr(Var("items"), Literal(1))),
    )
    result = analyze_program(program(main, leaf("main.f"), leaf("main.g")))
    assert result.call_graph.get()["main"] == {"main.f", "main.g"}


def test_env_is_an_alias_to_the_actual_current_environment():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        *empty_arguments(),
        Env("environment"),
        Bind(Attr(Var("environment"), Literal("created")), Var("f")),
        invoke(Var("created")),
        Delete(Var("created")),
    )
    result = analyze_program(program(main, leaf("main.f")))
    assert result.call_graph.get()["main"] == {"main.f"}
    assert "@env:main" in result.assignment_graph["main::environment"]


def test_unknown_environment_key_flows_into_named_variable_reads():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        *empty_arguments(),
        Env("environment"),
        Alloc("key", Binary("+", Literal("dynamic"), Literal("name"))),
        Bind(Attr(Var("environment"), Var("key")), Var("f")),
        invoke(Var("dynamicname")),
    )
    result = analyze_program(program(main, leaf("main.f")))
    assert result.call_graph.get()["main"] == {"main.f"}


def test_deletion_widens_shifted_indices_outside_the_static_integer_domain():
    # A weak summary can contain an out-of-bounds field from an infeasible MIR
    # branch. Deletion must not enumerate the billion intervening indices.
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        *empty_arguments(),
        Alloc("items", ListExpr(())),
        Bind(Attr(Var("items"), Literal(1_000_000_000)), Var("f")),
        Delete(Attr(Var("items"), Literal(1))),
        invoke(Attr(Var("items"), Literal(1))),
    )
    result = analyze_program(program(main, leaf("main.f")))
    assert result.converged and result.iterations < 20
    assert result.call_graph.get()["main"] == {"main.f"}


def test_assume_does_not_prune_but_structurally_unreachable_nodes_are_ignored():
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("g", function("main.g")),
        *empty_arguments(),
        Assume(Literal(False)),
        invoke(Var("f")),
        invoke(Var("g")),
    )
    main.nodes[5].successors = (7,)
    result = analyze_program(program(main, leaf("main.f"), leaf("main.g")))
    assert result.call_graph.get()["main"] == {"main.f"}
    assert ("main", 6) not in result.call_sites


def test_synthetic_helpers_are_projected_out_and_can_be_inspected_explicitly():
    helper = cfg(
        "main.$helper",
        *empty_arguments(),
        invoke(Attr(Var("parent"), Literal("f")), "return"),
        synthetic=True,
    )
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("helper", function("main.$helper")),
        *empty_arguments(),
        invoke(Var("helper")),
    )
    mir = program(main, helper, leaf("main.f"))
    projected = analyze_program(mir)
    assert projected.call_graph.get() == {"main": {"main.f"}, "main.f": set()}
    raw = analyze_program(mir, include_synthetic=True)
    assert raw.call_graph.get()["main"] == {"main.$helper"}
    assert raw.call_graph.get()["main.$helper"] == {"main.f"}


def test_all_functions_mode_analyzes_global_calls_in_uncalled_definitions():
    uncalled = cfg(
        "main.uncalled",
        *empty_arguments(),
        invoke(Attr(Var("parent"), Literal("f")), "return"),
    )
    dormant_helper = cfg("main.$dormant", Alloc("return", Literal(0)), synthetic=True)
    main = cfg(
        "main",
        Alloc("f", function("main.f")),
        Alloc("uncalled", function("main.uncalled")),
        Alloc("helper", function("main.$dormant")),
    )
    mir = program(main, uncalled, dormant_helper, leaf("main.f"))
    whole = analyze_program(mir)
    assert whole.call_graph.get()["main.uncalled"] == {"main.f"}
    assert "main.$dormant" not in whole.reachable_cfgs
    reachable = analyze_program(mir, analyze_all_functions=False)
    assert reachable.reachable_cfgs == {"main"}
    assert reachable.call_graph.get()["main.uncalled"] == set()


def test_mutual_recursion_through_synthetic_helpers_does_not_loop_in_projection():
    main = cfg(
        "main",
        Alloc("helper", function("main.$helper")),
        *empty_arguments(),
        invoke(Var("helper")),
    )
    helper = cfg(
        "main.$helper",
        *empty_arguments(),
        invoke(Attr(Var("parent"), Literal("helper")), "return"),
        synthetic=True,
    )
    result = analyze_program(program(main, helper))
    assert result.converged
    assert result.call_graph.get() == {"main": set()}
    raw = analyze_program(program(main, helper), include_synthetic=True)
    assert raw.call_graph.get()["main.$helper"] == {"main.$helper"}


def test_unresolved_calls_are_explicit_diagnostics():
    main = cfg("main", *empty_arguments(), invoke(Var("unknown")))
    result = analyze_program(program(main))
    assert result.converged
    assert result.call_graph.get() == {"main": set()}
    assert result.unresolved_calls == (("main", 2),)
    assert "no closure target" in result.diagnostics[0]


def test_bounded_analysis_warns_and_reports_incompleteness():
    main = cfg("main", Alloc("f", function("main.f")))
    mir = program(main, leaf("main.f"))
    with pytest.warns(PyCGMIRConvergenceWarning, match="incomplete"):
        result = analyze_program(mir, max_iterations=1)
    assert result.truncated and not result.converged
    assert result.iterations == 1
    assert "incomplete" in result.diagnostics[0]
    with pytest.raises(PyCGMIRConvergenceError) as error:
        analyze_program(mir, max_iterations=1, raise_on_truncation=True)
    assert error.value.result.truncated


@pytest.mark.parametrize("budget", [0, -1, True, 1.5])
def test_invalid_iteration_budgets_are_rejected(budget):
    with pytest.raises(ValueError, match="positive integer"):
        analyze_program(program(cfg("main")), max_iterations=budget)


def test_unbounded_fixed_point_and_empty_program_body():
    result = analyze_program(program(cfg("main")), max_iterations=None)
    assert result.converged and result.iterations == 1
    assert result.call_graph.get() == {"main": set()}


def test_malformed_mir_is_rejected_before_analysis():
    main = cfg("main", Alloc("missing", function("missing")))
    with pytest.raises(MIRValidationError, match="Unknown lambda body"):
        analyze_program(program(main))
