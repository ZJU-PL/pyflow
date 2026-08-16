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

    def test_callable_instance_uses_shared_call_binding_service(self):
        source = """
class Callable:
    def __call__(self, value, *, marker):
        return marker

value = object()
sentinel = []
callable_object = Callable()
result = callable_object(value, marker=sentinel)
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to("result") == analysis.points_to("sentinel")

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

    def test_descriptor_delete_receives_instance(self):
        source = """
seen = None

class Descriptor:
    def __delete__(self, obj):
        global seen
        seen = obj

class A:
    field = Descriptor()

a = A()
del a.field
x = a
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") <= result.points_to("seen")

    def test_builtin_delattr_uses_descriptor_delete_protocol(self):
        source = """
seen = None

class Descriptor:
    def __delete__(self, obj):
        global seen
        seen = obj

class A:
    field = Descriptor()

a = A()
delattr(a, "field")
x = a
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") <= result.points_to("seen")

    def test_slots_create_descriptor_and_preserve_slot_value(self):
        source = """
sentinel = object()

class A:
    __slots__ = ("field",)

a = A()
a.field = sentinel
x = a.field
descriptor = A.field
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")
        assert any(
            "<slot:__main__.A.field>" in value
            for value in result.points_to("descriptor")
        )

    def test_slots_reject_ordinary_undeclared_instance_cell(self):
        source = """
sentinel = object()

class A:
    __slots__ = ()

a = A()
a.missing = sentinel
x = a.missing
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("sentinel").isdisjoint(result.points_to("x"))

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

    def test_function_metaclass_controls_class_definition_result(self):
        source = """
sentinel = object()

def make_class(name, bases, namespace):
    return sentinel

class A(metaclass=make_class):
    pass

x = A
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")
        assert all("AllocKind.CLASS" not in obj for obj in result.points_to("x"))

    def test_function_metaclass_receives_class_namespace(self):
        source = """
sentinel = object()

def make_class(name, bases, namespace):
    return namespace["marker"]

class A(metaclass=make_class):
    marker = sentinel

x = A
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")

    def test_class_decorator_controls_final_binding(self):
        source = """
sentinel = object()

def decorate(cls):
    return sentinel

@decorate
class A:
    pass

x = A
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")
        assert all("AllocKind.CLASS" not in obj for obj in result.points_to("x"))

    def test_metaclass_new_controls_class_definition_result(self):
        source = """
sentinel = object()

class M(type):
    def __new__(mcls, name, bases, namespace):
        return sentinel

class A(metaclass=M):
    pass

x = A
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")
        assert all("AllocKind.CLASS" not in obj for obj in result.points_to("x"))

    def test_metaclass_prepare_hook_is_analyzed(self):
        source = """
sentinel = object()
seen = None

class M(type):
    @classmethod
    def __prepare__(mcls, name, bases):
        global seen
        seen = sentinel
        return {}

class A(metaclass=M):
    pass
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("sentinel") <= result.points_to("seen")

    def test_metaclass_new_receives_the_prepared_namespace(self):
        source = """
sentinel = object()

class Namespace:
    marker = sentinel

class M(type):
    @classmethod
    def __prepare__(mcls, name, bases):
        return Namespace()

    def __new__(mcls, name, bases, namespace):
        return namespace.marker

class A(metaclass=M):
    body_value = object()

x = A
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")

    def test_class_body_populates_the_prepared_mapping(self):
        source = """
sentinel = object()

class M(type):
    @classmethod
    def __prepare__(mcls, name, bases):
        return {}

    def __new__(mcls, name, bases, namespace):
        return namespace["body_value"]

class A(metaclass=M):
    body_value = sentinel

x = A
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") == result.points_to("sentinel")

    def test_descriptor_set_name_hook_receives_new_class(self):
        source = """
seen = None

class Descriptor:
    def __set_name__(self, owner, name):
        global seen
        seen = owner

class A:
    field = Descriptor()

x = A
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") <= result.points_to("seen")

    def test_init_subclass_hook_receives_new_subclass(self):
        source = """
seen = None

class Base:
    def __init_subclass__(cls):
        global seen
        seen = cls

class Child(Base):
    pass

x = Child
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x") <= result.points_to("seen")

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

    def test_explicit_super_slices_the_receiver_mro(self):
        source = """
a = object()
b = []

class A:
    x = a

class B(A):
    x = b

class C(A):
    pass

class D(C, B):
    pass

d = D()
y = super(C, d).x
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y") == result.points_to("b")

    def test_super_tracks_all_late_argument_alternatives(self):
        source = """
a = object()
b = []

class A:
    x = a

class B(A):
    x = b

class C(A):
    pass

class D(C, B):
    pass

class E(B, C):
    pass

Start = C
Start = B
receiver = D()
receiver = E()
y = super(Start, receiver).x
"""
        for policy, seed in (
            ("fifo", 0),
            ("lifo", 0),
            *[("random", seed) for seed in range(10)],
        ):
            result = PointerAnalysis(
                source,
                k=1,
                worklist_policy=policy,
                worklist_seed=seed,
            ).run()

            assert result.points_to("a") <= result.points_to("y")
            assert result.points_to("b") <= result.points_to("y")

    def test_constant_exec_is_lowered_into_the_current_scope(self):
        result = PointerAnalysis('exec("x = object()")\ny = x\n', k=1).run()

        assert result.points_to("y")
        assert result.points_to_query("y").complete is True

    def test_constant_eval_flows_to_call_result(self):
        result = PointerAnalysis(
            'sentinel = object()\ny = eval("sentinel")\n', k=1
        ).run()

        assert result.points_to("y") == result.points_to("sentinel")

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
