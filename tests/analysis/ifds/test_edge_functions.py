from __future__ import annotations

from pyflow.analysis.ifds import (
    ComposedEdgeFunction,
    ConstantEdgeFunction,
    EdgeFunction,
    IdentityEdgeFunction,
    JoinedEdgeFunction,
)


def test_identity_edge_function_computes_identity():
    identity = IdentityEdgeFunction[int]()
    assert identity.compute(42) == 42
    assert identity.compute("hello") == "hello"


def test_identity_edge_function_call():
    identity = IdentityEdgeFunction[int]()
    assert identity(99) == 99


def test_identity_edge_function_is_idempotent():
    identity = IdentityEdgeFunction[int]()
    assert identity.is_idempotent() is True


def test_identity_compose_with_self_returns_self():
    identity = IdentityEdgeFunction[int]()
    result = identity.compose(identity)
    assert result == identity


def test_constant_edge_function_computes_constant():
    constant = ConstantEdgeFunction[int](constant=7)
    assert constant.compute(0) == 7
    assert constant.compute(42) == 7


def test_constant_edge_function_compose_returns_self():
    constant = ConstantEdgeFunction[int](constant=7)
    identity = IdentityEdgeFunction[int]()
    result = constant.compose(identity)
    assert result == constant
    result2 = constant.compose(IdentityEdgeFunction[int]())
    assert result2 == constant


def test_constant_edge_function_is_idempotent():
    constant = ConstantEdgeFunction[int](constant=7)
    assert constant.is_idempotent() is True


def test_composed_edge_function_computes_outer_inner():
    add_1 = lambda x: x + 1
    add_2 = lambda x: x + 2

    class AddEdge(EdgeFunction[int]):
        def __init__(self, delta: int):
            self.delta = delta

        def compute(self, value: int) -> int:
            return value + self.delta

        def __eq__(self, other):
            if isinstance(other, AddEdge):
                return self.delta == other.delta
            return False

        def __hash__(self):
            return hash(self.delta)

    outer = AddEdge(2)
    inner = AddEdge(1)
    composed = ComposedEdgeFunction.from_functions(outer, inner)
    assert composed.compute(0) == 3


def test_composed_edge_function_normalizes_nested():
    identity = IdentityEdgeFunction[int]()

    class AddEdge(EdgeFunction[int]):
        def __init__(self, delta: int):
            self.delta = delta

        def compute(self, value: int) -> int:
            return value + self.delta

        def __eq__(self, other):
            if isinstance(other, AddEdge):
                return self.delta == other.delta
            return False

        def __hash__(self):
            return hash(self.delta)

    add1 = AddEdge(1)
    add2 = AddEdge(2)
    composed = ComposedEdgeFunction.from_functions(
        ComposedEdgeFunction.from_functions(add2, add1),
        identity,
    )
    assert composed.compute(0) == 3


def test_composed_edge_function_normalizes_consecutive_idempotent():
    class IdempotentEdge(EdgeFunction[int]):
        def compute(self, value: int) -> int:
            return value

        def is_idempotent(self) -> bool:
            return True

        def __eq__(self, other):
            return isinstance(other, IdempotentEdge)

        def __hash__(self):
            return 0

    edge = IdempotentEdge()
    composed = ComposedEdgeFunction.from_functions(edge, edge)
    assert composed.compute(5) == 5


def test_joined_edge_function_joins_values():
    identity = IdentityEdgeFunction[int]()
    constant_3 = ConstantEdgeFunction[int](constant=3)
    constant_7 = ConstantEdgeFunction[int](constant=7)

    joined = JoinedEdgeFunction.from_functions(
        constant_3, constant_7, join_values=lambda a, b: max(a, b)
    )
    assert joined.compute(0) == 7


def test_joined_edge_function_deduplicates_identical():
    identity = IdentityEdgeFunction[int]()
    joined = JoinedEdgeFunction.from_functions(
        identity, identity, join_values=lambda a, b: a
    )
    assert joined == identity


def test_joined_edge_function_compose_distributes():
    identity = IdentityEdgeFunction[int]()

    class MulEdge(EdgeFunction[int]):
        def __init__(self, factor: int):
            self.factor = factor

        def compute(self, value: int) -> int:
            return value * self.factor

        def __eq__(self, other):
            if isinstance(other, MulEdge):
                return self.factor == other.factor
            return False

        def __hash__(self):
            return hash(self.factor)

    mul2 = MulEdge(2)
    const3 = ConstantEdgeFunction[int](constant=3)
    const5 = ConstantEdgeFunction[int](constant=5)

    joined = JoinedEdgeFunction.from_functions(
        const3, const5, join_values=lambda a, b: a + b
    )
    composed = joined.compose(mul2)
    assert composed.compute(1) == 8


def test_edge_function_compose_identity_is_symmetric():
    identity = IdentityEdgeFunction[int]()
    constant = ConstantEdgeFunction[int](constant=42)
    assert constant.compose(identity) == constant
    assert identity.compose(constant) == constant


def test_joined_compose_with_identity():
    identity = IdentityEdgeFunction[int]()
    const3 = ConstantEdgeFunction[int](constant=3)
    const5 = ConstantEdgeFunction[int](constant=5)

    joined = JoinedEdgeFunction.from_functions(
        const3, const5, join_values=lambda a, b: a + b
    )
    composed = joined.compose(identity)
    assert composed.compute(0) == 8


def test_no_self_join_when_different_identity_subclasses():
    identity_a = IdentityEdgeFunction[int]()
    identity_b = IdentityEdgeFunction[int]()
    joined = identity_a.join(identity_b, join_values=lambda a, b: a)
    assert isinstance(joined, IdentityEdgeFunction)
