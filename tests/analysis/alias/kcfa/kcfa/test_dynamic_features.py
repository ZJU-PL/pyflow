"""Executable coverage for dynamic Python features handled by KCFA."""

from pyflow.analysis.alias.kcfa import PointerAnalysis


class TestDynamicFeatureSupport:
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
