"""Tests for ZeroFact, flow combinators, CallContext, and taint categories."""

from __future__ import annotations

from pyflow.analysis.ifds import (
    CATEGORY_DATABASE,
    CATEGORY_ENVIRONMENT,
    CATEGORY_FILE,
    CATEGORY_NETWORK,
    CATEGORY_USER_INPUT,
    CallContext,
    GenFlow,
    IdentityFlow,
    KillFlow,
    PathEdge,
    Supergraph,
    ZERO,
    ZeroFact,
)
from pyflow.analysis.ifds.problem import IFDSProblem
from pyflow.analysis.ifds.solver import IDESolver, IFDSSolver


class TestZeroFact:
    def test_singleton(self):
        a = ZeroFact()
        b = ZeroFact()
        assert a is b
        assert a is ZERO
        assert ZERO is ZeroFact()

    def test_hash_equality(self):
        a = ZeroFact()
        b = ZeroFact()
        assert hash(a) == hash(b)
        assert a == b
        assert not (a != b)

    def test_repr(self):
        assert repr(ZeroFact()) == "⊥"
        assert repr(ZERO) == "⊥"

    def test_not_equal_to_string(self):
        assert ZeroFact() != "ZERO"
        assert ZERO != "⊥"

    def test_hashable(self):
        s = {ZeroFact(), ZERO}
        assert len(s) == 1
        d = {ZeroFact(): "value"}
        assert d[ZERO] == "value"


class TestFlowCombinators:
    def test_identity_passes_fact_through(self):
        fn = IdentityFlow(zero=ZERO)
        assert fn("x") == ("x",)
        assert fn(42) == (42,)

    def test_identity_preserves_zero(self):
        fn = IdentityFlow(zero=ZERO)
        assert fn(ZERO) == (ZERO,)

    def test_kill_drops_everything(self):
        fn = KillFlow()
        assert fn("x") == ()
        assert fn(ZERO) == ()
        assert fn(42) == ()

    def test_gen_from_zero(self):
        fn = GenFlow(generated="tainted", zero=ZERO)
        assert fn(ZERO) == ("tainted",)

    def test_gen_preserves_existing(self):
        fn = GenFlow(generated="tainted", zero=ZERO)
        assert fn("x") == ("x", "tainted")

    def test_gen_with_zero_fact(self):
        fn = GenFlow(generated=ZERO, zero=ZERO)
        assert fn(ZERO) == (ZERO,)
        assert fn("x") == ("x", ZERO)


class TestCallContext:
    def test_empty_context(self):
        ctx = CallContext()
        assert ctx.call_sites == ()
        assert ctx.max_depth == 3

    def test_push_single(self):
        ctx = CallContext().push("site_a")
        assert ctx.call_sites == ("site_a",)

    def test_push_chain(self):
        ctx = CallContext()
        ctx = ctx.push("a")
        ctx = ctx.push("b")
        ctx = ctx.push("c")
        assert ctx.call_sites == ("a", "b", "c")

    def test_depth_bounding(self):
        ctx = CallContext()
        for i in range(5):
            ctx = ctx.push(f"s{i}")
        assert len(ctx.call_sites) == 3
        assert ctx.call_sites == ("s2", "s3", "s4")

    def test_custom_max_depth(self):
        ctx = CallContext(max_depth=1)
        ctx = ctx.push("a")
        ctx = ctx.push("b")
        assert len(ctx.call_sites) == 1
        assert ctx.call_sites == ("b",)

    def test_rejects_zero_max_depth(self):
        try:
            CallContext(max_depth=0)
        except ValueError as exc:
            assert "max_depth must be >= 1" in str(exc)
        else:
            raise AssertionError("Expected ValueError")

    def test_pop(self):
        ctx = CallContext()
        ctx = ctx.push("a")
        ctx = ctx.push("b")
        popped = ctx.pop()
        assert popped.call_sites == ("a",)

    def test_pop_empty(self):
        ctx = CallContext()
        popped = ctx.pop()
        assert popped.call_sites == ()

    def test_hashable(self):
        ctx1 = CallContext().push("a")
        ctx2 = CallContext().push("a")
        assert hash(ctx1) == hash(ctx2)
        assert ctx1 == ctx2

    def test_frozen(self):
        ctx = CallContext()
        ctx2 = ctx.push("a")
        assert ctx.call_sites == ()
        assert ctx2.call_sites == ("a",)


class TestPathEdgeContext:
    def test_no_context_default(self):
        pe = PathEdge("n1", "f1", "n2", "f2")
        assert pe.context is None

    def test_with_context(self):
        ctx = CallContext().push("site_a")
        pe = PathEdge("n1", "f1", "n2", "f2", context=ctx)
        assert pe.context is ctx

    def test_hash_distinguishes_context(self):
        ctx = CallContext().push("a")
        pe1 = PathEdge("n1", "f1", "n2", "f2", context=ctx)
        pe2 = PathEdge("n1", "f1", "n2", "f2")
        pe3 = PathEdge("n1", "f1", "n2", "f2", context=CallContext().push("b"))
        assert pe1 != pe2
        assert pe1 != pe3
        s = {pe1, pe2, pe3}
        assert len(s) == 3


class TestTaintCategories:
    def test_constants_defined(self):
        assert isinstance(CATEGORY_USER_INPUT, str)
        assert isinstance(CATEGORY_ENVIRONMENT, str)
        assert isinstance(CATEGORY_FILE, str)
        assert isinstance(CATEGORY_NETWORK, str)
        assert isinstance(CATEGORY_DATABASE, str)

    def test_constants_distinct(self):
        categories = {
            CATEGORY_USER_INPUT,
            CATEGORY_ENVIRONMENT,
            CATEGORY_FILE,
            CATEGORY_NETWORK,
            CATEGORY_DATABASE,
        }
        assert len(categories) == 5

    def test_constants_meanings(self):
        assert CATEGORY_USER_INPUT == "user_input"
        assert CATEGORY_ENVIRONMENT == "env"
        assert CATEGORY_FILE == "file"
        assert CATEGORY_NETWORK == "network"
        assert CATEGORY_DATABASE == "database"


class TestContextInsensitiveSolver:
    """Verify the solver still works correctly with its new context internals."""

    def test_linear_problem(self):
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_node("main", "main.body")
        sg.add_node("main", "main.exit")
        sg.add_normal_edge("main.entry", "main.body")
        sg.add_normal_edge("main.body", "main.exit")

        class Linear(IFDSProblem[str, str, str]):
            @property
            def supergraph(self):
                return sg

            @property
            def zero_fact(self):
                return ZERO

            def initial_seeds(self):
                return {"main.entry": frozenset({ZERO})}

            def normal_flow(self, node, successor, fact):
                if node == "main.entry" and fact is ZERO:
                    return (ZERO, "x")
                return (fact,)

        result = IFDSSolver().solve(Linear())
        assert result.is_reached("main.body", "x")
        assert result.is_reached("main.body", ZERO)
        assert result.is_reached("main.exit", "x")

    def test_context_enabled_runs(self):
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_node("main", "main.body")
        sg.add_node("main", "main.exit")
        sg.add_normal_edge("main.entry", "main.body")
        sg.add_normal_edge("main.body", "main.exit")

        class Linear(IFDSProblem[str, str, str]):
            @property
            def supergraph(self):
                return sg

            @property
            def zero_fact(self):
                return ZERO

            def initial_seeds(self):
                return {"main.entry": frozenset({ZERO})}

            def normal_flow(self, node, successor, fact):
                if node == "main.entry" and fact is ZERO:
                    return (ZERO, "x")
                return (fact,)

        solver = IFDSSolver(max_call_string_depth=3)
        result = solver.solve(Linear())
        assert result.is_reached("main.body", "x")
        assert result.is_reached("main.exit", "x")


def test_ifds_solver_rejects_invalid_call_string_depth():
    try:
        IFDSSolver(max_call_string_depth=0)
    except ValueError as exc:
        assert "max_call_string_depth must be >= 1" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_ide_solver_rejects_invalid_call_string_depth():
    try:
        IDESolver(max_call_string_depth=False)
    except TypeError as exc:
        assert "max_call_string_depth must be an integer or None" in str(exc)
    else:
        raise AssertionError("Expected TypeError")
