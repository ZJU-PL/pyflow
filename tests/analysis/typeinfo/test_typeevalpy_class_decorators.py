"""Class decorators must rebind the class name to the decorator result."""

from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine


def infer(source):
    return StaticTypeInferenceEngine().infer_source("sample", source)


def test_local_class_decorator_replaces_method_and_records_class_argument():
    result = infer("""
def decorate(cls):
    class Replacement(cls):
        def method(self): return "a"
    return Replacement
@decorate
class Original:
    def method(self): return 1
instance = Original()
answer = instance.method()
""")
    assert str(result.type_of("answer")) == "str"
    assert str(result.type_of("instance")) == "sample.decorate.Replacement"
    parameter = result.functions["sample.decorate"].parameters["cls"]
    assert str(parameter.runtime_type()) == "type[sample.Original]"
    assert not parameter.unknown
    assert result.converged


def test_decorator_returning_unrelated_class_replaces_constructor():
    result = infer("""
class Replacement:
    def method(self): return "a"
def decorate(cls): return Replacement
@decorate
class Original:
    def method(self): return 1
answer = Original().method()
""")
    assert str(result.type_of("answer")) == "str"


def test_identity_class_decorator_preserves_original_class():
    result = infer("""
def identity(cls): return cls
@identity
class Original:
    def method(self): return 1
answer = Original().method()
""")
    assert str(result.type_of("answer")) == "int"


def test_stacked_class_decorators_apply_bottom_up():
    result = infer("""
class First:
    def method(self): return 1
class Second:
    def method(self): return "a"
def first(cls): return First
def second(cls): return Second
@second
@first
class Original:
    pass
answer = Original().method()
""")
    assert str(result.type_of("answer")) == "str"
    assert (
        str(result.functions["sample.second"].parameters["cls"].runtime_type())
        == "type[sample.First]"
    )


def test_class_decorator_factory_receives_config_and_class_evidence():
    result = infer("""
class Replacement:
    def method(self): return "a"
def configure(flag):
    def decorate(cls): return Replacement
    return decorate
@configure(True)
class Original:
    def method(self): return 1
answer = Original().method()
""")
    assert str(result.type_of("answer")) == "str"
    assert str(result.functions["sample.configure"].parameters["flag"].public_type()) == "bool"
    assert (
        str(result.functions["sample.configure.decorate"].parameters["cls"].runtime_type())
        == "type[sample.Original]"
    )


def test_decorator_can_replace_class_with_a_function_value():
    result = infer("""
def decorate(cls):
    def factory(): return "a"
    return factory
@decorate
class Original:
    pass
answer = Original()
""")
    assert str(result.type_of("answer")) == "str"


def test_unknown_decorator_does_not_leave_original_as_a_definite_class():
    result = infer("""
@missing
class Original:
    def method(self): return 1
answer = Original().method()
""")
    assert result.value_of("Original").unknown
    assert result.type_of("answer") is None


def test_dataclass_and_final_transforms_keep_existing_constructor_models():
    result = infer("""
from dataclasses import dataclass
from typing import final
@final
@dataclass
class Record:
    value: int
answer = Record(1).value
""")
    assert str(result.type_of("answer")) == "int"
    assert not result.diagnostics


def test_callable_instance_can_decorate_a_class():
    result = infer("""
class Replacement:
    def method(self): return "a"
class Decorator:
    def __call__(self, cls): return Replacement
decorate = Decorator()
@decorate
class Original:
    def method(self): return 1
answer = Original().method()
""")
    assert str(result.type_of("answer")) == "str"


def test_annotated_decorator_returned_class_remains_constructible():
    result = infer("""
class Replacement:
    def method(self): return "a"
def decorate(cls) -> type[Replacement]: return Replacement
@decorate
class Original:
    def method(self): return 1
answer = Original().method()
""")
    assert str(result.type_of("answer")) == "str"


def test_annotated_class_factory_return_is_constructible():
    result = infer("""
class Product:
    def method(self): return "a"
def factory() -> type[Product]: return Product
cls = factory()
answer = cls().method()
""")
    assert str(result.type_of("answer")) == "str"


def test_partly_unknown_decorator_keeps_uncertainty_through_member_call():
    result = infer("""
class Replacement:
    def method(self): return "a"
def decorate(cls): return Replacement
maybe = decorate if unknown_flag else missing
@maybe
class Original:
    pass
answer = Original().method()
""")
    assert result.value_of("Original").unknown
    assert result.value_of("answer").unknown
