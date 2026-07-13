"""Tests for context-sensitive IFDS solving via bounded call-strings."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.ifds import (
    CallContext,
    EdgeFunction,
    IDEProblem,
    IDESolver,
    IdentityEdgeFunction,
    IFDSProblem,
    IFDSResult,
    IFDSSolver,
    PathEdge,
    Supergraph,
    ValueTransition,
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


class SameFactFromTwoCallSitesProblem(IFDSProblem[str, str, str]):
    """Two call sites pass the SAME fact into a shared callee.

    Tests whether context sensitivity separates path edges that
    would otherwise be identical via the seen set.
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
        if node == "main.entry" and successor == "main.split" and fact is Z:
            return (Z,)
        if node == "main.split" and successor == "main.call1" and fact is Z:
            return (Z, "secret")
        if node == "main.split" and successor == "main.call2" and fact is Z:
            return (Z, "secret")
        if fact in {Z, "secret"}:
            return (fact,)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        return (fact,)

    def return_flow(
        self, call_node, callee, exit_node, return_site, call_fact, exit_fact,
    ):
        return (exit_fact,)

    def call_to_return_flow(self, call_node, return_site, fact):
        return (fact,)


class ThreeDeepCallChainProblem(IFDSProblem[str, str, str]):
    """A 3-level call chain: main -> mid -> inner -> sink.

    Tests context propagation and truncation through multiple call levels.
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
            return (Z, "payload")
        if fact in {Z, "payload"}:
            return (fact,)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        return (fact,)

    def return_flow(
        self, call_node, callee, exit_node, return_site, call_fact, exit_fact,
    ):
        return (exit_fact,)

    def call_to_return_flow(self, call_node, return_site, fact):
        return (fact,)


@dataclass(frozen=True)
class _AccumLabel(EdgeFunction[frozenset[str]]):
    """Accumulates labels into a frozenset via edge function composition."""

    labels: frozenset[str]

    def compute(self, value: frozenset[str]) -> frozenset[str]:
        return value | self.labels

    def is_idempotent(self) -> bool:
        return True


class SplitCallIDEProblem(IDEProblem[str, str, str, frozenset[str]]):
    """Two call sites with different edge function labels.

    IDE solver should preserve per-call-site values via
    context-sensitive jump functions.
    """

    def __init__(self, sg: Supergraph[str, str]) -> None:
        self._sg = sg

    @property
    def supergraph(self):
        return self._sg

    @property
    def zero_fact(self):
        return Z

    @property
    def bottom_value(self):
        return frozenset()

    def join_values(self, left, right):
        return left | right

    def initial_seed_values(self):
        return {("main.entry", Z): frozenset()}

    def normal_flow(self, node, successor, fact):
        if node == "main.entry" and successor in {"main.call1", "main.call2"} and fact is Z:
            return (ValueTransition("d", IdentityEdgeFunction()),)
        if node in {"main.ret1", "main.ret2"} and successor == "main.exit" and fact == "d":
            return (ValueTransition("d", IdentityEdgeFunction()),)
        if node == "callee.entry" and successor == "callee.exit" and fact == "p":
            return (ValueTransition("p", _AccumLabel(frozenset({"summary"}))),)
        return ()

    def call_flow(self, call_node, callee, fact):
        if callee != "callee" or fact != "d":
            return ()
        if call_node == "main.call1":
            return (ValueTransition("p", _AccumLabel(frozenset({"one"}))),)
        if call_node == "main.call2":
            return (ValueTransition("p", _AccumLabel(frozenset({"two"}))),)
        return ()

    def return_flow(
        self, call_node, callee, exit_node, return_site, call_fact, exit_fact,
    ):
        if (
            callee == "callee"
            and exit_node == "callee.exit"
            and call_fact == "d"
            and exit_fact == "p"
            and return_site in {"main.ret1", "main.ret2"}
        ):
            return (ValueTransition("d", IdentityEdgeFunction()),)
        return ()

    def call_to_return_flow(self, call_node, return_site, fact):
        if fact is Z:
            return (ValueTransition(Z, IdentityEdgeFunction()),)
        return ()


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


def _make_same_fact_supergraph() -> Supergraph[str, str]:
    sg = Supergraph[str, str]()
    sg.add_procedure("main", "main.entry", ["main.exit"])
    sg.add_procedure("leak", "leak.entry", ["leak.exit"])
    sg.add_node("main", "main.split")
    sg.add_node("main", "main.call1")
    sg.add_node("main", "main.call1_ret")
    sg.add_node("main", "main.call2")
    sg.add_node("main", "main.call2_ret")
    sg.add_node("main", "main.join")
    sg.add_node("main", "main.exit")
    sg.add_node("leak", "leak.sink")
    sg.add_node("leak", "leak.exit")
    sg.add_normal_edge("main.entry", "main.split")
    sg.add_normal_edge("main.split", "main.call1")
    sg.add_normal_edge("main.split", "main.call2")
    sg.add_call_edge("main.call1", "leak", "main.call1_ret")
    sg.add_call_edge("main.call2", "leak", "main.call2_ret")
    sg.add_normal_edge("main.call1_ret", "main.join")
    sg.add_normal_edge("main.call2_ret", "main.join")
    sg.add_normal_edge("main.join", "main.exit")
    sg.add_normal_edge("leak.entry", "leak.sink")
    sg.add_normal_edge("leak.sink", "leak.exit")
    return sg


def _make_three_deep_supergraph() -> Supergraph[str, str]:
    sg = Supergraph[str, str]()
    sg.add_procedure("main", "main.entry", ["main.exit"])
    sg.add_procedure("mid", "mid.entry", ["mid.exit"])
    sg.add_procedure("inner", "inner.entry", ["inner.exit"])
    sg.add_node("main", "main.call")
    sg.add_node("main", "main.call_ret")
    sg.add_node("main", "main.exit")
    sg.add_node("mid", "mid.call")
    sg.add_node("mid", "mid.call_ret")
    sg.add_node("mid", "mid.exit")
    sg.add_node("inner", "inner.sink")
    sg.add_node("inner", "inner.exit")
    sg.add_normal_edge("main.entry", "main.call")
    sg.add_call_edge("main.call", "mid", "main.call_ret")
    sg.add_normal_edge("main.call_ret", "main.exit")
    sg.add_normal_edge("mid.entry", "mid.call")
    sg.add_call_edge("mid.call", "inner", "mid.call_ret")
    sg.add_normal_edge("mid.call_ret", "mid.exit")
    sg.add_normal_edge("inner.entry", "inner.sink")
    sg.add_normal_edge("inner.sink", "inner.exit")
    return sg


def _make_split_call_supergraph() -> Supergraph[str, str]:
    sg = Supergraph[str, str]()
    sg.add_procedure("main", "main.entry", ["main.exit"])
    for node in ("main.call1", "main.call2", "main.ret1", "main.ret2"):
        sg.add_node("main", node)
    sg.add_normal_edge("main.entry", "main.call1")
    sg.add_normal_edge("main.entry", "main.call2")
    sg.add_normal_edge("main.ret1", "main.exit")
    sg.add_normal_edge("main.ret2", "main.exit")
    sg.add_procedure("callee", "callee.entry", ["callee.exit"])
    sg.add_call_edge("main.call1", "callee", "main.ret1")
    sg.add_call_edge("main.call2", "callee", "main.ret2")
    sg.add_normal_edge("callee.entry", "callee.exit")
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


    def test_same_fact_isolated_by_context(self):
        """Same fact from two call sites -> distinct path edges with context."""
        sg = _make_same_fact_supergraph()
        problem = SameFactFromTwoCallSitesProblem(sg)

        insens = IFDSSolver().solve(problem)
        sens = IFDSSolver(max_call_string_depth=3).solve(problem)

        assert insens.is_reached("leak.sink", "secret")
        assert sens.is_reached("leak.sink", "secret")

        insens_edges = [
            e
            for e in insens.path_edges()
            if e.node == "leak.sink" and e.fact == "secret"
        ]
        assert len(insens_edges) == 1, (
            "Context-insensitive should merge same (node,fact) into one path edge"
        )

        sens_edges = [
            e
            for e in sens.path_edges()
            if e.node == "leak.sink" and e.fact == "secret"
        ]
        assert len(sens_edges) == 2, (
            "Context-sensitive should have distinct path edges per call site"
        )
        contexts = {e.context for e in sens_edges}
        assert len(contexts) == 2
        for ctx in contexts:
            assert isinstance(ctx, CallContext)
            assert len(ctx.call_sites) == 1

    def test_context_truncation_deep_chain(self):
        """3-level chain with bounded context -> context is truncated."""
        sg = _make_three_deep_supergraph()
        problem = ThreeDeepCallChainProblem(sg)

        shallow = IFDSSolver(max_call_string_depth=1).solve(problem)
        deep = IFDSSolver(max_call_string_depth=3).solve(problem)

        assert shallow.is_reached("inner.sink", "payload")
        assert deep.is_reached("inner.sink", "payload")

        shallow_edges = [
            e
            for e in shallow.path_edges()
            if e.node == "inner.sink" and e.fact == "payload"
        ]
        for e in shallow_edges:
            assert isinstance(e.context, CallContext)
            assert len(e.context.call_sites) == 1, (
                f"max_depth=1 should truncate to 1 call site, got {len(e.context.call_sites)}"
            )
            assert e.context.max_depth == 1

        deep_edges = [
            e
            for e in deep.path_edges()
            if e.node == "inner.sink" and e.fact == "payload"
        ]
        for e in deep_edges:
            assert isinstance(e.context, CallContext)
            assert len(e.context.call_sites) == 2, (
                f"max_depth=3 should preserve 2 call sites, got {len(e.context.call_sites)}"
            )

    def test_context_insensitive_has_fewer_path_edges(self):
        """Context-insensitive solver should merge facts -> fewer unique path edges."""
        sg = _make_same_fact_supergraph()
        problem = SameFactFromTwoCallSitesProblem(sg)

        insens = IFDSSolver().solve(problem)
        sens = IFDSSolver(max_call_string_depth=3).solve(problem)

        assert len(sens.path_edges()) > len(insens.path_edges()), (
            "Context sensitivity should produce more unique path edges"
        )

    def test_recursive_context_merged_at_limit(self):
        """Recursive calls beyond max_depth should have bounded contexts."""
        sg = _make_recursive_supergraph()
        problem = RecursiveContextProblem(sg)

        bounded = IFDSSolver(max_call_string_depth=2).solve(problem)

        for e in bounded.path_edges():
            if e.context is not None and isinstance(e.context, CallContext):
                assert len(e.context.call_sites) <= 2, (
                    "Contexts should never exceed max_call_string_depth=2"
                )


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


class TestIDESensitivity:
    """IDE context sensitivity: per-call-site values via context-keyed jump functions."""

    def test_ide_preserves_per_context_values(self):
        sg = _make_split_call_supergraph()
        problem = SplitCallIDEProblem(sg)
        result = IDESolver(max_call_string_depth=3).solve(problem)

        call1_ctx = CallContext(max_depth=3).push("main.call1")
        call2_ctx = CallContext(max_depth=3).push("main.call2")

        assert result.value_at("callee.entry", "p") == frozenset({"one", "two"})
        assert result.value_at_context("callee.entry", "p", call1_ctx) == frozenset({"one"})
        assert result.value_at_context("callee.entry", "p", call2_ctx) == frozenset({"two"})

    def test_ide_contextual_value_at_return_site(self):
        sg = _make_split_call_supergraph()
        problem = SplitCallIDEProblem(sg)
        result = IDESolver(max_call_string_depth=3).solve(problem)

        call1_ctx = CallContext(max_depth=3).push("main.call1")
        call2_ctx = CallContext(max_depth=3).push("main.call2")
        root_ctx = CallContext(max_depth=3)

        assert result.value_at_context("main.ret1", "d", root_ctx) == frozenset({"one", "summary"})
        assert result.value_at_context("main.ret2", "d", root_ctx) == frozenset({"two", "summary"})


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
