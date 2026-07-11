"""Tests for context-sensitive IFDS solving via bounded call-strings."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.ifds import (
    CallContext,
    IFDSProblem,
    IFDSResult,
    IFDSSolver,
    PathEdge,
    Supergraph,
    ZERO,
)


Z = ZERO
TAINT = "taint"
CLEAN = "clean"


class SharedCalleeProblem(IFDSProblem[str, str, str]):
    """A shared callee called from two different calling contexts.

    main:
      x = source()        // TAINT at main.entry
      shared(x)           // call site ① — tainted argument
      y = clean_func()
      shared(y)           // call site ② — clean argument

    shared(z):
      sink(z)
    """

    def __init__(self, sg: Supergraph[str, str]) -> None:
        self._sg = sg

    @property
    def supergraph(self):
        return self._sg

    @property
    def zero_fact(self):
        return Z

    def initial_seeds(self):
        return {"main.entry": frozenset({Z})}

    def normal_flow(self, node: str, successor: str, fact: str):
        if node == "main.entry" and successor == "main.call1" and fact is Z:
            return (Z, TAINT)
        if node == "main.call1_ret" and successor == "main.body":
            return (fact,)
        if node == "main.body" and successor == "main.call2" and fact is Z:
            return (Z, CLEAN)
        if fact in {Z, TAINT, CLEAN, "tainted_arg", "clean_arg"}:
            return (fact,)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        if callee == "shared":
            if fact is Z:
                return (Z,)
            if fact == TAINT:
                return ("tainted_arg",)
            if fact == CLEAN:
                return ("clean_arg",)
        return ()

    def return_flow(
        self, call_node, callee, exit_node, return_site, call_fact, exit_fact,
    ):
        if exit_fact == "tainted_arg":
            return (TAINT,)
        if exit_fact == "clean_arg":
            return (CLEAN,)
        return ()

    def call_to_return_flow(self, call_node, return_site, fact):
        return (fact,)


class RecursiveContextProblem(IFDSProblem[str, str, str]):
    """A recursive function where context distinguishes depth.

    recurse(n):
      if n > 0: recurse(n-1)
      else: sink(x)
    """

    def __init__(self, sg: Supergraph[str, str]) -> None:
        self._sg = sg

    @property
    def supergraph(self):
        return self._sg

    @property
    def zero_fact(self):
        return Z

    def initial_seeds(self):
        return {"main.entry": frozenset({Z})}

    def normal_flow(self, node: str, successor: str, fact: str):
        if node == "main.entry" and successor == "main.call" and fact is Z:
            return (Z, "depth_0")
        if fact in {Z, "depth_0", "depth_1", "depth_2", "depth_3"}:
            return (fact,)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        if callee == "recurse" and fact is Z:
            return (Z,)
        if callee == "recurse" and fact.startswith("depth_"):
            n = int(fact.split("_")[1])
            if n < 3:
                return (f"depth_{n+1}",)
        return ()

    def return_flow(
        self, call_node, callee, exit_node, return_site, call_fact, exit_fact,
    ):
        return (exit_fact,) if exit_fact != "depth_0" else (Z,)

    def call_to_return_flow(self, call_node, return_site, fact):
        return (fact,)


def _make_shared_callee_supergraph() -> Supergraph[str, str]:
    sg = Supergraph[str, str]()

    sg.add_procedure("main", "main.entry", ["main.exit"])
    sg.add_procedure("shared", "shared.entry", ["shared.exit"])

    sg.add_node("main", "main.call1")
    sg.add_node("main", "main.call1_ret")
    sg.add_node("main", "main.body")
    sg.add_node("main", "main.call2")
    sg.add_node("main", "main.call2_ret")
    sg.add_node("main", "main.exit")

    sg.add_node("shared", "shared.body")
    sg.add_node("shared", "shared.sink")
    sg.add_node("shared", "shared.exit")

    sg.add_normal_edge("main.entry", "main.call1")
    sg.add_call_edge("main.call1", "shared", "main.call1_ret")
    sg.add_normal_edge("main.call1_ret", "main.body")
    sg.add_normal_edge("main.body", "main.call2")
    sg.add_call_edge("main.call2", "shared", "main.call2_ret")
    sg.add_normal_edge("main.call2_ret", "main.exit")

    sg.add_normal_edge("shared.entry", "shared.body")
    sg.add_normal_edge("shared.body", "shared.sink")
    sg.add_normal_edge("shared.sink", "shared.exit")

    return sg


def _make_recursive_supergraph() -> Supergraph[str, str]:
    sg = Supergraph[str, str]()

    sg.add_procedure("main", "main.entry", ["main.exit"])
    sg.add_procedure("recurse", "recurse.entry", ["recurse.exit"])

    sg.add_node("main", "main.call")
    sg.add_node("main", "main.call_ret")
    sg.add_node("main", "main.exit")

    sg.add_node("recurse", "recurse.check")
    sg.add_node("recurse", "recurse.recurse_call")
    sg.add_node("recurse", "recurse.recurse_ret")
    sg.add_node("recurse", "recurse.sink")
    sg.add_node("recurse", "recurse.exit")

    sg.add_normal_edge("main.entry", "main.call")
    sg.add_call_edge("main.call", "recurse", "main.call_ret")
    sg.add_normal_edge("main.call_ret", "main.exit")

    sg.add_normal_edge("recurse.entry", "recurse.check")
    sg.add_normal_edge("recurse.check", "recurse.recurse_call")
    sg.add_call_edge("recurse.recurse_call", "recurse", "recurse.recurse_ret")
    sg.add_normal_edge("recurse.recurse_ret", "recurse.sink")
    sg.add_normal_edge("recurse.sink", "recurse.exit")

    return sg


class TestContextInsensitive:
    def test_both_contexts_merged(self):
        sg = _make_shared_callee_supergraph()
        problem = SharedCalleeProblem(sg)
        result = IFDSSolver().solve(problem)
        assert result.is_reached("shared.sink", "tainted_arg")
        assert result.is_reached("shared.sink", "clean_arg")


class TestContextSensitive:
    def test_context_distinguishes_call_sites(self):
        sg = _make_shared_callee_supergraph()
        problem = SharedCalleeProblem(sg)

        insens = IFDSSolver().solve(problem)
        sens = IFDSSolver(max_call_string_depth=3).solve(problem)

        assert insens.is_reached("shared.sink", "tainted_arg")
        assert insens.is_reached("shared.sink", "clean_arg")
        assert insens.is_reached("main.exit", TAINT)
        assert insens.is_reached("main.exit", CLEAN)

        assert sens.is_reached("shared.sink", "tainted_arg")
        assert sens.is_reached("shared.sink", "clean_arg")

        sink_edges = [
            e for e in sens.path_edges()
            if e.node == "shared.sink" and e.fact == "tainted_arg"
        ]
        assert len(sink_edges) >= 1
        for e in sink_edges:
            assert e.context is not None
            assert isinstance(e.context, CallContext)

    def test_context_edges_have_nontrivial_context(self):
        sg = _make_shared_callee_supergraph()
        problem = SharedCalleeProblem(sg)
        result = IFDSSolver(max_call_string_depth=3).solve(problem)

        edges = list(result.path_edges())
        sink_edges = [e for e in edges if e.node == "shared.sink" and e.fact == "tainted_arg"]
        assert len(sink_edges) > 0
        for e in sink_edges:
            assert e.context is not None
            assert isinstance(e.context, CallContext)

    def test_recursive_depth_tracking(self):
        sg = _make_recursive_supergraph()
        problem = RecursiveContextProblem(sg)
        result = IFDSSolver(max_call_string_depth=5).solve(problem)
        assert result.is_reached("recurse.sink", "depth_3")


class TestCallContextOperations:
    def test_empty_context(self):
        ctx = CallContext()
        assert ctx.call_sites == ()

    def test_push_bounded(self):
        ctx = CallContext(max_depth=2)
        ctx = ctx.push("a").push("b").push("c")
        assert ctx.call_sites == ("b", "c")

    def test_pop(self):
        ctx = CallContext().push("a").push("b")
        assert ctx.pop().call_sites == ("a",)

    def test_equality(self):
        a = CallContext().push("x")
        b = CallContext().push("x")
        assert a == b
        assert hash(a) == hash(b)

    def test_different_contexts_unequal(self):
        a = CallContext().push("x")
        b = CallContext().push("y")
        assert a != b


class TestPathEdgeWithContext:
    def test_context_distinguishes_edges(self):
        ctx_a = CallContext().push("a")
        ctx_b = CallContext().push("b")
        e1 = PathEdge("n1", "f1", "n2", "f2", context=ctx_a)
        e2 = PathEdge("n1", "f1", "n2", "f2", context=ctx_b)
        assert e1 != e2
        assert hash(e1) != hash(e2)

    def test_no_context_default(self):
        e1 = PathEdge("n1", "f1", "n2", "f2")
        e2 = PathEdge("n1", "f1", "n2", "f2")
        assert e1 == e2
