"""Executable coverage for dynamic Python features handled by KCFA."""

import random

from pyflow.analysis.alias.kcfa import PointerAnalysis
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.state import Worklist


class TestDynamicFeatureSupport:
    def test_semantic_results_are_stable_under_random_worklist_orders(
        self, monkeypatch
    ):
        source = """
class Left:
    value = object()

class Right:
    value = []

Base = Left
Base = Right

class C(Base):
    pass

sentinel = object()

class M1(type):
    def __call__(cls):
        return sentinel

class M2(M1):
    pass

class Product(metaclass=M2):
    pass

base_value = C.value
product = Product()
"""
        rng = random.Random(20260816)

        def pop_random(worklist):
            if not worklist.items_list:
                raise IndexError("pop from empty worklist")
            index = rng.randrange(len(worklist.items_list))
            worklist.items_list.rotate(-index)
            scope, node, pts = worklist.items_list.popleft()
            worklist.items_list.rotate(index)
            del worklist.items_dict[node]
            return scope, node, pts.val

        monkeypatch.setattr(Worklist, "pop", pop_random)
        for _ in range(10):
            result = PointerAnalysis(source, k=1).run()
            base_pts = result.points_to("base_value")
            assert any("AllocKind.OBJECT" in obj for obj in base_pts)
            assert any("AllocKind.LIST" in obj for obj in base_pts)
            assert result.points_to("product") == result.points_to("sentinel")

    def test_closure_return_flows_from_inner_function(self):
        source = """
def outer():
    x = object()
    def inner():
        return x
    return inner

f = outer()
y = f()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y")
        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("y"))

    def test_identity_decorator_preserves_function_return(self):
        source = """
def deco(fn):
    return fn

@deco
def f():
    return object()

y = f()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y")
        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("y"))

    def test_descriptor_getter_contributes_attribute_value(self):
        source = """
class D:
    def __get__(self, obj, typ):
        return object()

class A:
    d = D()

a = A()
y = a.d
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y")
        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("y"))

    def test_inherited_descriptor_getter_contributes_attribute_value(self):
        source = """
class DescriptorBase:
    def __get__(self, obj, typ):
        return object()

class Descriptor(DescriptorBase):
    pass

class A:
    d = Descriptor()

y = A().d
"""
        result = PointerAnalysis(source, k=1).run()

        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("y"))

    def test_inherited_descriptor_setter_receives_written_value(self):
        source = """
sentinel = object()
seen = None

class DescriptorBase:
    def __set__(self, obj, value):
        global seen
        seen = value

class Descriptor(DescriptorBase):
    pass

class A:
    d = Descriptor()

a = A()
a.d = sentinel
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("sentinel") <= result.points_to("seen")

    def test_metaclass_class_instantiation_remains_an_instance(self):
        source = """
class M(type):
    pass

class A(metaclass=M):
    pass

y = A()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y")
        assert any("AllocKind.INSTANCE" in obj for obj in result.points_to("y"))

    def test_overridden_metaclass_call_controls_class_call_result(self):
        source = """
sentinel = object()

class M(type):
    def __call__(cls):
        return sentinel

class A(metaclass=M):
    pass

x = A()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")
        assert all("AllocKind.INSTANCE" not in obj for obj in result.points_to("x"))

    def test_metaclass_call_is_inherited_by_subclasses(self):
        source = """
sentinel = object()

class M(type):
    def __call__(cls):
        return sentinel

class Base(metaclass=M):
    pass

class Child(Base):
    pass

x = Child()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")

    def test_metaclass_call_is_inherited_by_metaclass_subclasses(self):
        source = """
sentinel = object()

class M1(type):
    def __call__(cls):
        return sentinel

class M2(M1):
    pass

class A(metaclass=M2):
    pass

x = A()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")
        assert all("AllocKind.INSTANCE" not in obj for obj in result.points_to("x"))

    def test_generator_next_reads_yielded_value(self):
        source = """
def gen():
    x = object()
    yield x

g = gen()
y = next(g)
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("g")
        assert any("AllocKind.GENERATOR" in obj for obj in result.points_to("g"))
        assert result.points_to("y")
        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("y"))

    def test_async_call_allocates_coroutine_object(self):
        source = """
async def f():
    return object()

c = f()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("c")
        assert any("AllocKind.COROUTINE" in obj for obj in result.points_to("c"))

    def test_super_method_return_flows_to_override(self):
        source = """
class A:
    def m(self):
        return object()

class B(A):
    def m(self):
        return super().m()

b = B()
y = b.m()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y")
        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("y"))

    def test_exec_eval_remain_conservative_static_limitations(self):
        result = PointerAnalysis('exec("x = object()")\ny = x\n', k=1).run()

        assert result.points_to("y") == set()

    def test_dynamic_import_produces_conservative_result_object(self):
        source = """
name = "math"
m = __import__(name)
y = m
"""
        result = PointerAnalysis(source, k=1).run()

        # Dynamic import is a security-sensitive operation. Retaining an
        # abstract result is safer than silently dropping the return flow.
        assert result.points_to("y")
