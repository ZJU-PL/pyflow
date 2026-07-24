"""Unit tests for the lattice package."""

from __future__ import annotations

import pytest

from pyflow.analysis.lattice import (
    AbstractDomain,
    SetDomain,
    ElementSetDomain,
    InvertedSetDomain,
    OverUnderSetDomain,
    Approximation,
    ToppedSetDomain,
    BucketedElementSetDomain,
    MapDomain,
    ProductDomain,
    FlatDomain,
    TreeDomain,
    RootedTreeDomain,
    SimpleDomain,
    WrapperDomain,
    OP_MAP,
    OP_ADD,
    OP_FILTER,
    OP_FILTER_MAP,
    OP_EXPAND,
    OP_ACC,
    OP_EXISTS,
    OP_BY,
    OP_BY_FILTER,
    check_lattice_properties,
)


class TestSetDomain:
    def test_bottom(self):
        d = SetDomain.bottom()
        assert d.is_bottom()
        assert len(d.elements()) == 0

    def test_singleton(self):
        d = SetDomain.singleton(1)
        assert 1 in d.elements()
        assert len(d.elements()) == 1

    def test_of(self):
        d = SetDomain.of(1, 2, 3)
        assert d.elements() == frozenset({1, 2, 3})

    def test_join(self):
        a = SetDomain.of(1, 2)
        b = SetDomain.of(2, 3)
        c = a.join(b)
        assert c.elements() == frozenset({1, 2, 3})

    def test_meet(self):
        a = SetDomain.of(1, 2, 3)
        b = SetDomain.of(2, 3, 4)
        c = a.meet(b)
        assert c.elements() == frozenset({2, 3})

    def test_leq(self):
        a = SetDomain.of(1, 2)
        b = SetDomain.of(1, 2, 3)
        assert a.leq(b)
        assert not b.leq(a)

    def test_widen(self):
        a = SetDomain.of(1)
        b = SetDomain.of(1, 2)
        c = a.widen(b)
        assert c.elements() == frozenset({1, 2})

    def test_subtract(self):
        a = SetDomain.of(1, 2, 3)
        b = SetDomain.of(2)
        c = a.subtract(b)
        assert c.elements() == frozenset({1, 3})

    def test_transform_map(self):
        d = SetDomain.of(1, 2, 3)
        result = d.transform("Element", OP_MAP, lambda x: x * 2)
        assert result.elements() == frozenset({2, 4, 6})

    def test_transform_add(self):
        d = SetDomain.of(1, 2)
        result = d.transform("Element", OP_ADD, 3)
        assert result.elements() == frozenset({1, 2, 3})

    def test_transform_filter(self):
        d = SetDomain.of(1, 2, 3, 4)
        result = d.transform("Element", OP_FILTER, lambda x: x % 2 == 0)
        assert result.elements() == frozenset({2, 4})

    def test_reduce_acc(self):
        d = SetDomain.of(1, 2, 3)
        total = d.reduce("Element", OP_ACC, lambda e, acc: acc + e, 0)
        assert total == 6

    def test_reduce_exists(self):
        d = SetDomain.of(1, 2, 3)
        assert d.reduce("Element", OP_EXISTS, lambda e: e > 2, False)
        assert not d.reduce("Element", OP_EXISTS, lambda e: e > 5, False)


class TestElementSetDomain:
    class OrderedElement:
        """Element with partial order for testing."""

        def __init__(self, val):
            self.val = val

        def leq(self, other):
            return self.val <= other.val

        def __hash__(self):
            return hash(self.val)

        def __eq__(self, other):
            return isinstance(other, self.__class__) and self.val == other.val

        def __repr__(self):
            return f"E({self.val})"

    def test_bottom(self):
        d = ElementSetDomain.bottom()
        assert d.is_bottom()

    def test_add_and_subsumption(self):
        d = ElementSetDomain.bottom()
        d = d.add(self.OrderedElement(5))
        assert not d.is_bottom()
        # Adding with leq(5) should be subsumed
        d2 = d.add(self.OrderedElement(3))
        assert len(d2.elements()) == 1  # 3 is subsumed by 5

    def test_join(self):
        a = ElementSetDomain.empty()
        a = a.add(self.OrderedElement(5))
        a = a.add(self.OrderedElement(10))
        b = ElementSetDomain.empty()
        b = b.add(self.OrderedElement(7))
        b = b.add(self.OrderedElement(12))
        c = a.join(b)
        assert len(c.elements()) >= 2

    def test_leq_no_ordering(self):
        d = ElementSetDomain.empty()
        d = d.add(1)
        d = d.add(2)
        assert d.leq(d)


class TestInvertedSetDomain:
    def test_bottom(self):
        d = InvertedSetDomain.bottom()
        assert d.is_bottom()

    def test_singleton(self):
        d = InvertedSetDomain.singleton(1)
        assert d.contains(1)
        assert not d.contains(2)

    def test_join_is_intersection(self):
        a = InvertedSetDomain.singleton(1)
        a = a.add(2)
        b = InvertedSetDomain.singleton(2)
        b = b.add(3)
        c = a.join(b)
        assert c.contains(2)
        assert not c.contains(1)
        assert not c.contains(3)

    def test_meet_is_union(self):
        a = InvertedSetDomain.singleton(1)
        b = InvertedSetDomain.singleton(2)
        c = a.meet(b)
        assert c.contains(1)
        assert c.contains(2)

    def test_leq_inverted(self):
        a = InvertedSetDomain.singleton(1)
        a = a.add(2)
        b = InvertedSetDomain.singleton(1)
        # a = {1,2}, b = {1} => a has more restrictions => a ≤ b
        assert a.leq(b)
        assert not b.leq(a)


class TestOverUnderSetDomain:
    def test_bottom(self):
        d = OverUnderSetDomain.bottom()
        assert d.is_bottom()

    def test_inject(self):
        d = OverUnderSetDomain.inject(1)
        assert d.contains(1)
        assert not d.contains(2)

    def test_join_unions_over_intersects_under(self):
        a = OverUnderSetDomain.of(1, 2)
        b = OverUnderSetDomain.of(2, 3)
        c = a.join(b)
        assert c.contains(1)
        assert c.contains(2)
        assert c.contains(3)

    def test_meet(self):
        a = OverUnderSetDomain.of(1, 2)
        b = OverUnderSetDomain.of(2, 3)
        c = a.meet(b)
        assert not c.contains(1)
        assert c.contains(2)
        assert not c.contains(3)

    def test_to_approximations(self):
        d = OverUnderSetDomain.of(1, 2)
        apprs = d.to_approximations()
        assert len(apprs) == 2
        assert all(a.in_under for a in apprs)

    def test_sequence_join(self):
        a = OverUnderSetDomain.of(1)
        b = OverUnderSetDomain.of(2)
        c = a.sequence_join(b)
        assert c.contains(1)
        assert c.contains(2)


class TestToppedSetDomain:
    def test_bottom(self):
        d = ToppedSetDomain.bottom()
        assert d.is_bottom()

    def test_top(self):
        d = ToppedSetDomain.top()
        assert d.is_top()

    def test_singleton(self):
        d = ToppedSetDomain.singleton(1)
        assert d.contains(1)
        assert not d.contains(2)

    def test_join_with_top(self):
        d = ToppedSetDomain.singleton(1)
        t = ToppedSetDomain.top()
        assert d.join(t).is_top()
        assert t.join(d).is_top()

    def test_meet_with_top(self):
        d = ToppedSetDomain.singleton(1)
        t = ToppedSetDomain.top()
        m = d.meet(t)
        assert m.contains(1)
        assert len(m.elements()) == 1

    def test_add(self):
        d = ToppedSetDomain.bottom()
        d = d.add(1)
        assert d.contains(1)

    def test_leq(self):
        a = ToppedSetDomain.singleton(1)
        b = ToppedSetDomain.singleton(1)
        b = b.add(2)
        assert a.leq(b)


class TestBucketedElementSetDomain:
    def test_bottom(self):
        d = BucketedElementSetDomain.bottom()
        assert d.is_bottom()

    def test_add(self):
        d = BucketedElementSetDomain.bottom()
        d = d.add(1, "bucket_a")
        assert not d.is_bottom()
        assert len(d.get("bucket_a").elements()) == 1

    def test_join(self):
        a = BucketedElementSetDomain.bottom()
        a = a.add(1, "x")
        b = BucketedElementSetDomain.bottom()
        b = b.add(2, "x")
        c = a.join(b)
        assert len(c.get("x").elements()) == 2

    def test_keys(self):
        d = BucketedElementSetDomain.bottom()
        d = d.add(1, "a")
        d = d.add(2, "b")
        assert set(d.keys()) == {"a", "b"}


class TestMapDomain:
    def test_bottom(self):
        d = MapDomain.bottom()
        assert d.is_bottom()

    def test_of(self):
        d = MapDomain.of("k", FlatDomain.of(1))
        assert d.get("k") == FlatDomain.of(1)

    def test_set(self):
        d = MapDomain.bottom()
        d = d.set("k", FlatDomain.of(42))
        assert d.get("k") == FlatDomain.of(42)

    def test_join(self):
        a = MapDomain.of("x", FlatDomain.of(1))
        b = MapDomain.of("x", FlatDomain.of(2))
        c = a.join(b)
        assert c.get("x") == FlatDomain.of(1).join(FlatDomain.of(2))

    def test_remove(self):
        d = MapDomain.bottom()
        d = d.set("a", FlatDomain.of(1)).set("b", FlatDomain.of(2))
        d = d.remove("a")
        assert "a" not in d


class TestProductDomain:
    def test_bottom(self):
        d = ProductDomain.bottom()
        assert d.is_bottom()

    def test_properties(self):
        d = ProductDomain(FlatDomain.of(1), FlatDomain.of(2))
        assert d.left == FlatDomain.of(1)
        assert d.right == FlatDomain.of(2)

    def test_join(self):
        a = ProductDomain(FlatDomain.of(1), FlatDomain.of(2))
        b = ProductDomain(FlatDomain.of(1), FlatDomain.of(3))
        c = a.join(b)
        # FlatDomain(1) ⊔ FlatDomain(1) = FlatDomain(1)
        # FlatDomain(2) ⊔ FlatDomain(3) = Top (different values)
        assert c.left == FlatDomain.of(1)

    def test_leq(self):
        a = ProductDomain(FlatDomain.bottom(), FlatDomain.bottom())
        b = ProductDomain(FlatDomain.of(1), FlatDomain.of(2))
        assert a.leq(b)

    def test_parts(self):
        a = ProductDomain(FlatDomain.of(1), FlatDomain.of(2))
        result = a.transform("Left", OP_MAP, lambda x: FlatDomain.of(x.value() * 2))
        assert result.left == FlatDomain.of(2)


class TestFlatDomain:
    def test_bottom(self):
        d = FlatDomain.bottom()
        assert d.is_bottom()

    def test_top(self):
        d = FlatDomain.top()
        assert d.is_top()

    def test_of(self):
        d = FlatDomain.of(42)
        assert d.value() == 42
        assert not d.is_bottom()
        assert not d.is_top()

    def test_join_same(self):
        a = FlatDomain.of(1)
        b = FlatDomain.of(1)
        assert a.join(b) == a

    def test_join_different(self):
        a = FlatDomain.of(1)
        b = FlatDomain.of(2)
        assert a.join(b).is_top()

    def test_meet_same(self):
        a = FlatDomain.of(1)
        b = FlatDomain.of(1)
        assert a.meet(b) == a

    def test_meet_different(self):
        a = FlatDomain.of(1)
        b = FlatDomain.of(2)
        assert a.meet(b).is_bottom()

    def test_leq(self):
        assert FlatDomain.bottom().leq(FlatDomain.of(1))
        assert FlatDomain.of(1).leq(FlatDomain.top())
        assert FlatDomain.of(1).leq(FlatDomain.of(1))
        assert not FlatDomain.of(1).leq(FlatDomain.of(2))


class TestTreeDomain:
    def test_bottom(self):
        d = TreeDomain.bottom()
        assert d.is_bottom()

    def test_leaf(self):
        d = TreeDomain.leaf(FlatDomain.of(1))
        assert d.get("") == FlatDomain.of(1)

    def test_set(self):
        d = TreeDomain.bottom()
        d = d.set("a", FlatDomain.of(1))
        assert d.get("a") == FlatDomain.of(1)

    def test_join(self):
        a = TreeDomain.bottom().set("x", FlatDomain.of(1))
        b = TreeDomain.bottom().set("x", FlatDomain.of(2))
        c = a.join(b)
        assert c.get("x") == FlatDomain.of(1).join(FlatDomain.of(2))

    def test_keys(self):
        d = TreeDomain.bottom().set("a", FlatDomain.of(1)).set("b", FlatDomain.of(2))
        assert set(d.keys()) == {"a", "b"}


class TestRootedTreeDomain:
    def test_bottom(self):
        d = RootedTreeDomain.bottom()
        assert d.is_bottom()

    def test_of(self):
        d = RootedTreeDomain.of(FlatDomain.of(1))
        assert d.root == FlatDomain.of(1)
        assert not d.is_bottom()

    def test_join(self):
        a = RootedTreeDomain.of(FlatDomain.of(1))
        b = RootedTreeDomain.of(FlatDomain.of(2))
        c = a.join(b)
        assert c.root == FlatDomain.of(1).join(FlatDomain.of(2))

    def test_set_child(self):
        d = RootedTreeDomain.of(FlatDomain.of(0))
        child = RootedTreeDomain.of(FlatDomain.of(1))
        d = d.set("a", child)
        assert d.get("a") == child


class TestSimpleDomain:
    def test_bottom(self):
        d = SimpleDomain.bottom()
        assert d.is_bottom()

    def test_of(self):
        d = SimpleDomain.of(42)
        assert d.value() == 42

    def test_join_same(self):
        a = SimpleDomain.of(1)
        b = SimpleDomain.of(1)
        assert a.join(b) == a

    def test_join_different(self):
        a = SimpleDomain.of(1)
        b = SimpleDomain.of(2)
        assert a.join(b).is_bottom()

    def test_meet_same(self):
        a = SimpleDomain.of(1)
        b = SimpleDomain.of(1)
        assert a.meet(b) == a

    def test_meet_different(self):
        a = SimpleDomain.of(1)
        b = SimpleDomain.of(2)
        assert a.meet(b).is_bottom()


class TestWrapperDomain:
    def test_wrap(self):
        inner = SetDomain.of(1, 2, 3)
        w = WrapperDomain(inner)
        assert w.inner == inner

    def test_join(self):
        a = WrapperDomain(SetDomain.of(1))
        b = WrapperDomain(SetDomain.of(2))
        c = a.join(b)
        assert c.inner == SetDomain.of(1, 2)

    def test_leq(self):
        a = WrapperDomain(SetDomain.of(1))
        b = WrapperDomain(SetDomain.of(1, 2))
        assert a.leq(b)
        assert not b.leq(a)

    def test_transform(self):
        w = WrapperDomain(SetDomain.of(1, 2))
        # Inner transform uses _transform_self which calls f(self)
        result = w.transform("Inner", OP_MAP, lambda d: SetDomain.of(3, 4))
        assert result.inner == SetDomain.of(3, 4)

    def test_bottom(self):
        w = WrapperDomain.bottom()
        assert w.is_bottom()


class TestLatticeProperties:
    """Sanity-check lattice laws for basic domains."""

    def test_set_domain_laws(self):
        d = SetDomain.of(1, 2, 3)
        check_lattice_properties(d)

    def test_flat_domain_laws(self):
        d = FlatDomain.of(42)
        check_lattice_properties(d)

    def test_topped_set_laws(self):
        d = ToppedSetDomain.singleton(1)
        check_lattice_properties(d)

    def test_simple_domain_laws(self):
        d = SimpleDomain.of("test")
        check_lattice_properties(d)

    def test_product_laws(self):
        # ProductDomain needs same component types for bottom() to work
        d = ProductDomain(SetDomain.of(1), SetDomain.of(2))
        check_lattice_properties(d)

    def test_wrapper_laws(self):
        d = WrapperDomain(SetDomain.of(1, 2))
        check_lattice_properties(d)

    def test_map_domain_laws(self):
        d = MapDomain.of("k", FlatDomain.of(1))
        check_lattice_properties(d)
