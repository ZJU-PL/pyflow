"""Regression tests for typeinfo issues found on real-world projects."""

from __future__ import annotations

from pyflow.analysis.typeinfo import StaticTypeInferenceEngine
from pyflow.analysis.typeinfo.core.typesystem import TypeSystem
from pyflow.analysis.typeinfo.inference.validation import (
    ObservedType,
    validate_observed_types,
)


def _infer(source: str) -> object:
    return StaticTypeInferenceEngine().infer_source("sample", source)


def _mismatches(result) -> list[str]:
    return [
        diagnostic.message
        for diagnostic in result.diagnostics
        if diagnostic.code == "annotation-mismatch"
    ]


def test_asyncio_union_argument_does_not_recurse() -> None:
    result = _infer(
        "import asyncio\n"
        "async def f(x: int | str):\n"
        "    return await asyncio.to_thread(str, x)\n"
    )
    assert result.status == "complete"


def test_call_site_starred_arguments_expand_fixed_tuples() -> None:
    result = _infer(
        "def f(x: int, y: str) -> str: ...\n"
        "f(*(1, 'a'))\n"
        "f(*[1, 'a'])\n"
        "args = (1, 'a')\n"
        "f(*args)\n"
    )
    assert _mismatches(result) == []
    assert [
        diagnostic.message
        for diagnostic in result.diagnostics
        if diagnostic.code == "call-arity-mismatch"
    ] == []


def test_call_site_double_star_expands_mapping_shape() -> None:
    result = _infer(
        "def f(x: int, y: str) -> str: ...\n"
        "kwargs = {'x': 1, 'y': 'a'}\n"
        "result = f(**kwargs)\n"
    )
    assert _mismatches(result) == []
    assert str(result.type_of("result")) == "str"


def test_unknown_star_arguments_do_not_produce_false_arity_errors() -> None:
    result = _infer(
        "def f(x: int, y: str) -> str: ...\n"
        "def forward(*args, **kwargs):\n"
        "    return f(*args, **kwargs)\n"
        "result = forward(1, 'a')\n"
    )
    assert _mismatches(result) == []
    assert str(result.type_of("result")) == "str"


def test_empty_list_literals_are_not_aliases() -> None:
    result = _infer(
        "def f(xs: list[int]) -> None: ...\n" "a = []\n" "b = []\n" "b.append('s')\n" "f(a)\n"
    )
    assert _mismatches(result) == []
    assert str(result.type_of("a")) == "list[Never]"
    assert str(result.type_of("b")) == "list[str]"


def test_mutating_union_receiver_keeps_the_applicable_alternative() -> None:
    result = _infer(
        "a = [1]\n" "b = {1}\n" "value = a if a else b\n" "value.append(2)\n" "result = value\n"
    )
    assert str(result.type_of("result")) == "list[int]"


def test_float_multiplication_over_union_keeps_float() -> None:
    result = _infer(
        "def f(flag):\n"
        "    value = 1 if flag else 's'\n"
        "    return 3.5 * value\n"
        "result = f(True)\n"
    )
    assert str(result.type_of("result")) == "float"
    assert validate_observed_types(result, [ObservedType(float, symbol="result")]) == []


def test_class_decorator_uses_call_return_type() -> None:
    result = _infer(
        "class Deco:\n"
        "    def __init__(self, f): self.f = f\n"
        "    def __call__(self, *args, **kwargs): return 's'\n"
        "@Deco\n"
        "def g() -> int:\n"
        "    return 1\n"
        "result = g()\n"
    )
    assert str(result.type_of("result")) == "str"
    assert validate_observed_types(result, [ObservedType(str, symbol="result")]) == []


def test_qualified_and_aliased_cached_property() -> None:
    for source in (
        "import functools\n"
        "class C:\n"
        "    @functools.cached_property\n"
        "    def x(self) -> int: return 1\n"
        "value = C().x\n",
        "from functools import cached_property as cp\n"
        "class C:\n"
        "    @cp\n"
        "    def x(self) -> int: return 1\n"
        "value = C().x\n",
    ):
        result = _infer(source)
        assert str(result.type_of("value")) == "int"


def test_mapping_proxy_type_is_a_class_object() -> None:
    result = _infer(
        "from types import MappingProxyType\n"
        "mapping: dict[type, int] = {MappingProxyType: 1}\n"
        "alias = MappingProxyType\n"
    )
    assert _mismatches(result) == []
    assert str(result.type_of("alias")) == "type[mappingproxy]"


def test_enum_subclass_members_keep_enum_type() -> None:
    result = _infer(
        "import enum\n"
        "class Base(str, enum.Enum):\n"
        "    A = 'a'\n"
        "class Sub(Base):\n"
        "    B = 'b'\n"
        "member: Sub = Sub.B\n"
        "value = Sub.B.value\n"
    )
    assert _mismatches(result) == []
    assert str(result.type_of("member")) == "sample.Sub"
    assert str(result.type_of("value")) == "str"


def test_os_getenv_and_environ_get_honor_non_none_default() -> None:
    result = _infer(
        "import os\n"
        "def f(value: str) -> None: ...\n"
        "f(os.getenv('X', ''))\n"
        "f(os.environ.get('X', ''))\n"
        "without_default = os.getenv('X')\n"
    )
    assert _mismatches(result) == []
    assert str(result.type_of("without_default")) == "None | str"


def test_unannotated_generator_is_a_generator() -> None:
    result = _infer(
        "from typing import Generator\n"
        "def use(value: Generator[int, None, None]) -> None: ...\n"
        "def values():\n"
        "    yield 1\n"
        "use(values())\n"
        "generator = values()\n"
    )
    assert _mismatches(result) == []
    assert str(result.type_of("generator")) == "collections.abc.Generator[int, Any, None]"


def test_generic_varargs_bind_element_type() -> None:
    result = _infer(
        "from typing import Generic, TypeVar\n"
        "T = TypeVar('T')\n"
        "class M:\n"
        "    def __add__(self, other: 'M') -> 'M':\n"
        "        return Group(self, other)\n"
        "class Group(M, Generic[T]):\n"
        "    def __init__(self, *mobjects: T) -> None: ...\n"
    )
    assert _mismatches(result) == []
    assert str(result.functions["sample.M.__add__"].return_type) == "sample.M"


def test_empty_dict_setitem_refines_key_and_value_types() -> None:
    result = _infer(
        "def build():\n"
        "    values = {}\n"
        "    values['a'] = 1\n"
        "    return values\n"
        "result = build()\n"
        "value = result['a']\n"
    )
    assert str(result.functions["sample.build"].return_type) == "dict[str, int]"
    assert str(result.type_of("value")) == "int"


def test_closure_container_mutation_reaches_enclosing_scope() -> None:
    result = _infer(
        "def collect():\n"
        "    values = []\n"
        "    def add(value: int) -> None:\n"
        "        values.append(value)\n"
        "    add(1)\n"
        "    return values[0]\n"
        "result = collect()\n"
    )
    assert str(result.functions["sample.collect"].return_type) == "int"
    assert str(result.type_of("result")) == "int"


def test_walrus_in_comprehension_condition_is_bound() -> None:
    result = _infer("result = [value for item in range(3) if (value := item + 1)]\n")
    assert str(result.type_of("result")) == "list[int]"


def test_reanalysis_does_not_reuse_stale_class_structure() -> None:
    type_system = TypeSystem()
    type_system.enable_numeric_tower()
    StaticTypeInferenceEngine(type_system=type_system).infer_source(
        "sample",
        "from typing import NamedTuple\n" "P = NamedTuple('P', [('x', int), ('y', str)])\n",
    )
    result = StaticTypeInferenceEngine(type_system=type_system).infer_source(
        "sample",
        "from typing import Protocol\n"
        "class P(Protocol):\n"
        "    x: int\n"
        "def use(value: P) -> int: return value.x\n"
        "class C:\n"
        "    x = 1\n"
        "use(C())\n",
    )
    assert _mismatches(result) == []
    descriptor = type_system._types["sample.P"]
    assert descriptor.tuple_fields is None
    assert set(descriptor.members) == {"x"}


def test_user_defined_iterables_and_enums_yield_element_types() -> None:
    result = _infer(
        "class It:\n"
        "    def __iter__(self): return iter([1])\n"
        "class Container:\n"
        "    def __iter__(self): return It()\n"
        "for item in Container():\n"
        "    loop_value = item\n"
        "import enum\n"
        "class Color(enum.Enum):\n"
        "    RED = 1\n"
        "for member in Color:\n"
        "    enum_value = member\n"
    )
    assert str(result.type_of("loop_value")) == "int"
    assert str(result.type_of("enum_value")) == "sample.Color"


def test_generator_send_returns_yield_type() -> None:
    result = _infer(
        "from typing import Generator\n"
        "def values() -> Generator[int, str, None]:\n"
        "    x = yield 1\n"
        "    yield 2\n"
        "generator = values()\n"
        "sent = generator.send('a')\n"
    )
    assert str(result.type_of("sent")) == "int"


def test_generic_dataclass_and_namedtuple_constructor_inference() -> None:
    result = _infer(
        "from dataclasses import dataclass\n"
        "from typing import Generic, NamedTuple, TypeVar\n"
        "T = TypeVar('T')\n"
        "@dataclass\n"
        "class Box(Generic[T]):\n"
        "    value: T\n"
        "class Pair(NamedTuple, Generic[T]):\n"
        "    item: T\n"
        "box = Box(1)\n"
        "pair = Pair('a')\n"
        "box_value = box.value\n"
        "pair_value = pair.item\n"
    )
    assert str(result.type_of("box_value")) == "int"
    assert str(result.type_of("pair_value")) == "str"


def test_typevar_class_constructor_binding() -> None:
    result = _infer(
        "from typing import TypeVar\n"
        "T = TypeVar('T')\n"
        "def make(cls: type[T]) -> T:\n"
        "    return cls()\n"
        "class C: pass\n"
        "value = make(C)\n"
    )
    assert str(result.type_of("value")) == "sample.C"


def test_property_setter_does_not_change_getter_type() -> None:
    result = _infer(
        "class C:\n"
        "    @property\n"
        "    def x(self) -> int: return 1\n"
        "    @x.setter\n"
        "    def x(self, value: str): ...\n"
        "c = C()\n"
        "c.x = 's'\n"
        "value = c.x\n"
    )
    assert str(result.type_of("value")) == "int"


def test_enum_inheritance_through_imported_base(tmp_path) -> None:
    from pyflow.analysis.typeinfo import ProjectTypeInferenceEngine
    from pyflow.language.modules.project_resolution import ProjectContext

    (tmp_path / "dep.py").write_text(
        "import enum\n" "class Base(str, enum.Enum):\n" "    A = 'a'\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from dep import Base\n"
        "class Sub(Base):\n"
        "    B = 'b'\n"
        "member: Sub = Sub.B\n"
        "value = Sub.B.value\n",
        encoding="utf-8",
    )
    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["app"])
    assert _mismatches(result.modules["app"]) == []
    assert str(result.modules["app"].type_of("member")) == "app.Sub"
    assert str(result.modules["app"].type_of("value")) == "str"


def test_bool_arithmetic_with_non_numeric_union_member_returns_int() -> None:
    result = _infer(
        "def f(value: bool | None):\n"
        "    value += True\n"
        "    return value\n"
        "result = f(True)\n"
    )
    assert str(result.functions["sample.f"].return_type) == "int"
    assert str(result.type_of("result")) == "int"


def test_union_bitwise_and_set_operations() -> None:
    result = _infer(
        "def f(a: set[int], b: set[int] | int):\n"
        "    union = a | b\n"
        "    intersection = a & b\n"
        "    difference = a - b\n"
        "    symmetric = a ^ b\n"
        "    return union, intersection, difference, symmetric\n"
        "result = f({1}, {2})\n"
    )
    assert str(result.functions["sample.f"].return_type) == (
        "tuple[set[int], set[int], set[int], set[int]]"
    )
    assert str(result.type_of("result")).startswith("tuple[set[int]")


def test_union_mapping_or_and_mutated_parameter_return() -> None:
    result = _infer(
        "def merge(a: dict[str, int], b: dict[str, int] | int):\n"
        "    return a | b\n"
        "merged = merge({'a': 1}, {'b': 2})\n"
        "def keep(value: int | str):\n"
        "    return value\n"
        "def bump(value: bool | None):\n"
        "    return value + 1\n"
        "kept = keep(1)\n"
        "bumped = bump(True)\n"
    )
    assert str(result.functions["sample.merge"].return_type) == "dict[str, int]"
    assert str(result.type_of("merged")) == "dict[str, int]"
    assert str(result.type_of("kept")) == "int"
    assert str(result.type_of("bumped")) == "int"


def test_union_receiver_methods_join_alternatives() -> None:
    result = _infer(
        "def copy_value(value: list[str] | set[int]):\n"
        "    return value.copy()\n"
        "def lookup(value: dict[str, int] | dict[str, None]):\n"
        "    return value.get('a')\n"
        "copied = copy_value(['a'])\n"
        "found = lookup({'a': 1})\n"
    )
    assert str(result.type_of("copied")) == "list[str] | set[int]"
    assert str(result.type_of("found")) == "None | int"


def test_return_dependency_ignores_reassigned_parameter() -> None:
    result = _infer(
        "def identity(value):\n"
        "    return value\n"
        "def reassigned(value):\n"
        "    value = 1\n"
        "    return value\n"
        "same = identity(True)\n"
        "changed = reassigned(True)\n"
    )
    assert str(result.type_of("same")) == "bool"
    assert str(result.type_of("changed")) == "int"


def test_zip_keeps_concrete_zip_type_and_iterates() -> None:
    result = _infer(
        "from typing import Iterator\n"
        "def use(value: Iterator[tuple[int, str]]) -> None: ...\n"
        "zipped = zip([1], ['a'])\n"
        "use(zipped)\n"
        "items = list(zipped)\n"
        "for number, text in zip([1], ['a']):\n"
        "    first = number\n"
        "    second = text\n"
    )
    assert str(result.type_of("zipped")) == "zip[tuple[int, str]]"
    assert str(result.type_of("items")) == "list[tuple[int, str]]"
    assert str(result.type_of("first")) == "int"
    assert str(result.type_of("second")) == "str"
    assert _mismatches(result) == []


def test_decorator_added_keyword_only_parameter_is_accepted() -> None:
    result = _infer(
        "from functools import wraps\n"
        "class C:\n"
        "    def triggers_refresh(func):\n"
        "        @wraps(func)\n"
        "        def wrapper(self, *args, refresh=True, **kwargs):\n"
        "            return func(self, *args, **kwargs)\n"
        "        return wrapper\n"
        "    @triggers_refresh\n"
        "    def set_points(self, points):\n"
        "        return self\n"
        "c = C()\n"
        "c.set_points([1], refresh=False)\n"
        "c.set_points([1])\n"
    )
    assert [
        diagnostic.message
        for diagnostic in result.diagnostics
        if diagnostic.code == "call-arity-mismatch"
    ] == []


def test_omitted_default_parameters_keep_default_types() -> None:
    result = _infer(
        "def f(x=1):\n"
        "    return x\n"
        "def g(*, x=1):\n"
        "    return x\n"
        "def h(x, /, y=2):\n"
        "    return x + y\n"
        "a = f()\n"
        "b = f('s')\n"
        "c = g()\n"
        "d = h(1)\n"
    )
    assert str(result.type_of("a")) == "int"
    assert str(result.type_of("b")) == "str"
    assert str(result.type_of("c")) == "int"
    assert str(result.type_of("d")) == "int"


def test_lambda_default_parameter_type() -> None:
    result = _infer("f = lambda x=1: x\n" "without_argument = f()\n" "with_argument = f('s')\n")
    assert str(result.type_of("without_argument")) == "int"
    assert str(result.type_of("with_argument")) == "str"


def test_fallback_analysis_uses_existing_classmethod_specializations() -> None:
    result = _infer(
        "from enum import Enum\n"
        "class Convertible(Enum):\n"
        "    @classmethod\n"
        "    def convert(cls, value):\n"
        "        if isinstance(value, cls): return value\n"
        "        for member in cls:\n"
        "            if member.value == value: return member\n"
        "        return None\n"
        "class First(Convertible):\n"
        "    A = 'a'\n"
        "class Second(Convertible):\n"
        "    B = 'b'\n"
        "def convert_both(first, second):\n"
        "    return First.convert(first), Second.convert(second)\n"
        "result = convert_both('a', 'b')\n"
    )
    assert str(result.functions["sample.convert_both"].return_type) == (
        "tuple[None | sample.First, None | sample.Second]"
    )


def test_empty_dict_builders_refine_and_propagate_mutation() -> None:
    result = _infer(
        "def add(values):\n"
        "    values['k'] = 1\n"
        "values = {}\n"
        "add(values)\n"
        "value = values['k']\n"
        "other = {}\n"
        "set_value = other.setdefault('a', 1)\n"
    )
    assert str(result.type_of("values")) == "dict[str, int]"
    assert str(result.type_of("value")) == "int"
    assert str(result.type_of("set_value")) == "int"


def test_user_defined_async_iterables_yield_element_types() -> None:
    result = _infer(
        "class Iterator:\n"
        "    def __aiter__(self): return self\n"
        "    async def __anext__(self) -> int: ...\n"
        "class Container:\n"
        "    def __aiter__(self): return Iterator()\n"
        "async def first():\n"
        "    async for value in Container():\n"
        "        return value\n"
    )
    assert str(result.functions["sample.first"].return_type) == "None | int"


def test_explicit_staticmethod_assignment_is_callable() -> None:
    result = _infer(
        "from typing import Any, Callable\n"
        "def _default(value): return value\n"
        "class Provider:\n"
        "    default: Callable[[Any], Any] = staticmethod(_default)\n"
    )
    assert _mismatches(result) == []


def test_overload_selection_respects_keyword_parameters() -> None:
    result = _infer(
        "from typing import Literal, overload\n"
        "@overload\n"
        "def convert(value: int) -> int: ...\n"
        "@overload\n"
        "def convert(value: int, *, unicode: Literal[True]) -> str: ...\n"
        "def convert(value, unicode=True): return value\n"
        "text = convert(1, unicode=True)\n"
    )
    assert str(result.type_of("text")) == "str"
    assert [
        diagnostic.message
        for diagnostic in result.diagnostics
        if diagnostic.code == "call-arity-mismatch"
    ] == []


def test_empty_dict_is_compatible_with_total_false_typeddict() -> None:
    result = _infer(
        "from typing import TypedDict\n"
        "class Options(TypedDict, total=False):\n"
        "    enabled: bool\n"
        "options: Options = {}\n"
        "class Required(TypedDict):\n"
        "    value: int\n"
        "missing: Required = {}\n"
    )
    assert str(result.type_of("options")) == "sample.Options"
    assert any("missing keys ['value']" in diagnostic.message for diagnostic in result.diagnostics)


def test_empty_dict_is_compatible_with_mapping_annotations() -> None:
    result = _infer(
        "from typing import Any, Mapping\n"
        "def consume(value: Mapping[str, int]) -> None: ...\n"
        "def build() -> Mapping[str, Any]:\n"
        "    return {}\n"
        "consume({})\n"
    )
    assert _mismatches(result) == []


def test_variadic_unresolved_annotation_converges() -> None:
    result = _infer(
        "def variadic[*Ts](*args: *Ts) -> tuple[*Ts]:\n"
        "    return args\n"
        'x = variadic(1, "a")\n'
    )
    assert not any(d.code == "inference-did-not-converge" for d in result.diagnostics)
    assert "tuple[tuple[tuple" not in str(result.diagnostics)


def test_walrus_bindings_in_boolean_conditions_and_comprehensions() -> None:
    result = _infer('if (a := 1) and (b := "hello"):\n' "    x = a\n" "    y = b\n")
    assert str(result.type_of("b")) == "str"
    assert str(result.type_of("y")) == "str"

    result_comp = _infer(
        'words = ["hello", "world", "abc"]\n'
        "long_words = [w for word in words if (n := len(word)) > 3 and (w := word.upper())]\n"
    )
    assert str(result_comp.type_of("w")) == "str"
    assert str(result_comp.type_of("long_words")) == "list[str]"


def test_protocol_satisfaction_with_init_instance_attributes() -> None:
    result = _infer(
        "from typing import Protocol\n"
        "class HasName(Protocol):\n"
        "    name: str\n"
        "class Person:\n"
        "    def __init__(self, name: str):\n"
        "        self.name = name\n"
        "def get_name(item: HasName) -> str:\n"
        "    return item.name\n"
        'x = get_name(Person("Alice"))\n'
    )
    assert not any(d.code == "annotation-mismatch" for d in result.diagnostics)
    assert str(result.type_of("x")) == "str"


def test_stub_docstring_only_and_pyi_not_implicit_none() -> None:
    engine = StaticTypeInferenceEngine()
    result_pyi = engine.infer_source(
        "sample",
        'def is_valid(obj: object) -> bool:\n    """Doc"""\n',
        filename="sample.pyi",
    )
    assert not any(d.code == "annotation-mismatch" for d in result_pyi.diagnostics)

    result_py = engine.infer_source(
        "sample",
        'def is_valid(obj: object) -> bool:\n    """Doc"""\n',
    )
    assert not any(d.code == "annotation-mismatch" for d in result_py.diagnostics)


def test_bare_tuple_in_generic_list_accepts_tuples() -> None:
    result = _infer(
        "from typing import List\n"
        "def run_rep(boxes: List[tuple]) -> bool:\n"
        "    return True\n"
        "run_rep([(1, 2, 3, 4)])\n"
    )
    assert not any(d.code == "annotation-mismatch" for d in result.diagnostics)


def test_generic_subclass_constructor_typevar_binding_and_method_chaining() -> None:
    result = _infer(
        "from typing import Generic, TypeVar\n"
        'K = TypeVar("K")\n'
        'V = TypeVar("V")\n'
        "class Pair(Generic[K, V]):\n"
        "    def __init__(self, first: K, second: V):\n"
        "        self.first = first\n"
        "        self.second = second\n"
        "    def get_first(self) -> K:\n"
        "        return self.first\n"
        "    def get_second(self) -> V:\n"
        "        return self.second\n"
        'A = TypeVar("A")\n'
        'B = TypeVar("B")\n'
        "class Swapped(Pair[B, A]):\n"
        "    def __init__(self, first: B, second: A):\n"
        "        super().__init__(second, first)\n"
        'p = Swapped("hello", 123)\n'
        "f = p.get_first()\n"
        "s = p.get_second()\n"
    )
    assert str(result.type_of("p")) == "sample.Swapped[str, int]"
    assert str(result.type_of("f")) == "str"
    assert str(result.type_of("s")) == "int"


def test_inherited_generic_method_call_substitutes_subclass_args() -> None:
    result = _infer(
        "from typing import Generic, TypeVar\n"
        'T = TypeVar("T")\n'
        "class Buffer(Generic[T]):\n"
        "    def __init__(self, item: T):\n"
        "        self.item = item\n"
        "    def read(self) -> T:\n"
        "        return self.item\n"
        "class SpecialBuffer(Buffer[T]):\n"
        "    pass\n"
        'sbuf = SpecialBuffer("hello")\n'
        "res = sbuf.read()\n"
    )
    assert str(result.type_of("res")) == "str"


def test_type_ignore_suppresses_call_arity_mismatch() -> None:
    result = _infer("def f(x: int): pass\n" "f(1, 2)  # type: ignore[call-arg]\n")
    assert not any(d.code == "call-arity-mismatch" for d in result.diagnostics)


def test_typeddict_variable_literal_subscript() -> None:
    result = _infer(
        "from typing import TypedDict\n"
        "class Movie(TypedDict):\n"
        "    title: str\n"
        "    year: int\n"
        'm: Movie = {"title": "Inception", "year": 2010}\n'
        'k = "title"\n'
        "val = m[k]\n"
    )
    assert str(result.type_of("val")) == "str"


def test_fstring_formatted_values_are_indexed() -> None:
    result = _infer("def compute() -> int: return 42\n" 'msg = f"Value: {compute()}"\n')
    found = any(
        v.public_type() and str(v.public_type()) == "int" for v in result.expressions.values()
    )
    assert found


def test_validate_observed_types_rejects_non_callable_classes_for_callable() -> None:
    result = _infer("def f(): pass\n")
    violations = validate_observed_types(result, [ObservedType(int, symbol="f")])
    assert len(violations) == 1
    assert violations[0].observation.raw_type is int


def test_subtype_distance_for_virtual_abc() -> None:
    from pyflow.analysis.typeinfo.resolution.annotations import (
        BuiltinTypeLookup,
        resolve_annotation,
    )

    ts = TypeSystem()
    lookup = BuiltinTypeLookup()
    t_seq = resolve_annotation("typing.Sequence[int]", lookup)
    t_list = resolve_annotation("list[int]", lookup)
    assert ts.subtype_distance(t_seq, t_list) == 1


def test_tuple_covariance_in_generic_list_argument() -> None:
    result = _infer(
        "from typing import List, Tuple\n"
        "def divide_all(divides: List[Tuple[float, float]]) -> None: pass\n"
        "DIVIDES = [(1000, 200), (3.1427, 2)]\n"
        "divide_all(DIVIDES)\n"
    )
    assert not any(d.code == "annotation-mismatch" for d in result.diagnostics)


def test_common_stdlib_modules_and_types_resolve_in_annotations() -> None:
    from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup

    lookup = BuiltinTypeLookup()
    for t in [
        "argparse.Namespace",
        "decimal.Decimal",
        "enum.Enum",
        "urllib.parse.ParseResult",
        "ssl.SSLContext",
        "socket.socket",
        "Namespace",
        "Decimal",
        "Enum",
        "ParseResult",
    ]:
        assert lookup(t) is not None, f"Failed for {t}"


def test_nested_typeddict_literal_compatibility() -> None:
    result = _infer(
        "from typing import TypedDict, Literal\n"
        "Role = Literal['system', 'user', 'assistant']\n"
        "class Message(TypedDict):\n"
        "    role: Role\n"
        "    content: str\n"
        "class ChatPrediction(TypedDict):\n"
        "    generation: Message\n"
        "pred: ChatPrediction = {\n"
        '    "generation": {\n'
        '        "role": "assistant",\n'
        '        "content": "hello"\n'
        "    }\n"
        "}\n"
    )
    assert not any(d.code == "annotation-mismatch" for d in result.diagnostics)


def test_context_manager_without_as_target_does_not_warn() -> None:
    result = _infer("class Ctx:\n" "    pass\n" "with Ctx():\n" "    pass\n")
    assert not any(d.code == "unmodeled-context-manager" for d in result.diagnostics)


def test_click_command_without_arguments_does_not_warn_call_arity() -> None:
    result = _infer(
        "import click\n"
        "@click.command()\n"
        "@click.argument('foo')\n"
        "def main(foo): pass\n"
        "main()\n"
    )
    assert not any(d.code == "call-arity-mismatch" for d in result.diagnostics)
