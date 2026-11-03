"""Regression tests for k-CFA soundness and termination gaps."""

import builtins
import ast

import pytest

from pyflow.analysis.alias.kcfa import AliasStatus, PointerAnalysis


def _points(result, name: str) -> set[str]:
    return result.points_to_name_union(name)


def test_positional_only_parameter_is_bound_in_return_flow():
    result = PointerAnalysis("""
class A: pass
a = A()

def f(x, /):
    return x

y = f(a)
""").run()

    assert result.complete
    assert _points(result, "y") == _points(result, "a")


def test_name_default_resolves_in_definition_scope():
    result = PointerAnalysis("""
class A: pass
a = A()

def f(x=a):
    return x

y = f()
""").run()

    assert result.complete
    assert _points(result, "y") == _points(result, "a")


@pytest.mark.skipif(
    not hasattr(builtins, "ExceptionGroup"), reason="ExceptionGroup requires Python 3.11+"
)
def test_exception_group_members_flow_through_exceptions_attribute():
    result = PointerAnalysis("""
member = ValueError()
group = ExceptionGroup("request failed", [member])
direct = group.exceptions[0]
try:
    raise group
except* ValueError as caught:
    handled = caught.exceptions[0]
""").run()

    assert _points(result, "member") <= _points(result, "direct")
    assert _points(result, "member") <= _points(result, "handled")
    assert result.points_to_query("direct").complete


def test_match_sequence_captures_point_to_items_and_starred_remainder():
    result = PointerAnalysis("""
class Marker: pass
marker = Marker()
other = object()
items = [marker, other]
match items:
    case [head, *tail]:
        first = head
tail_item = tail[0]
""").run()

    assert _points(result, "marker") <= _points(result, "first")
    assert _points(result, "marker") <= _points(result, "head")
    assert _points(result, "head").isdisjoint(_points(result, "items"))
    assert _points(result, "tail").isdisjoint(_points(result, "items"))
    assert _points(result, "other") <= _points(result, "tail_item")


def test_match_mapping_capture_reads_the_matched_value():
    result = PointerAnalysis("""
class Marker: pass
marker = Marker()
record = {"item": marker}
match record:
    case {"item": captured}:
        result = captured
""").run()

    assert _points(result, "marker") <= _points(result, "result")


def test_match_or_capture_unions_values_from_all_alternatives():
    result = PointerAnalysis("""
class A: pass
class B: pass
a = A()
b = B()
record = {"left": a, "right": b}
match record:
    case {"left": captured} | {"right": captured}:
        result = captured
""").run()

    assert _points(result, "a") <= _points(result, "result")
    assert _points(result, "b") <= _points(result, "result")


def test_match_class_positional_capture_uses_match_args():
    result = PointerAnalysis("""
class Marker: pass
marker = Marker()
class Record:
    __match_args__ = ("payload",)
    def __init__(self, payload):
        self.payload = payload
record = Record(marker)
match record:
    case Record(captured):
        result = captured
""").run()

    assert _points(result, "marker") <= _points(result, "result")
    assert result.points_to_query("result").complete


def test_match_builtin_class_capture_preserves_subject_value():
    result = PointerAnalysis("""
value = "connected"
match value:
    case str(captured):
        result = captured
""").run()

    assert _points(result, "value") <= _points(result, "result")
    assert result.points_to_query("result").complete


def test_match_dataclass_positional_capture_uses_field_order():
    result = PointerAnalysis("""
from dataclasses import dataclass
class Marker: pass
marker = Marker()
@dataclass
class Record:
    payload: object
record = Record(marker)
match record:
    case Record(captured):
        result = captured
""").run()

    assert _points(result, "marker") <= _points(result, "result")
    assert result.points_to_query("result").complete


@pytest.mark.skipif(not hasattr(ast, "TypeAlias"), reason="type statements require Python 3.12+")
def test_type_alias_binds_runtime_alias_object_and_value():
    result = PointerAnalysis("""
class Marker: pass
type Alias = Marker
alias_object = Alias
alias_value = Alias.__value__
""").run()

    assert _points(result, "Alias")
    assert _points(result, "Alias") <= _points(result, "alias_object")
    assert _points(result, "Marker") <= _points(result, "alias_value")
    assert result.points_to_query("Alias").complete


@pytest.mark.skipif(not hasattr(ast, "TypeAlias"), reason="type statements require Python 3.12+")
def test_generic_type_alias_preserves_type_parameters_and_arguments():
    result = PointerAnalysis("""
class Bound: pass
type Alias[T: Bound] = list[T]
alias_value = Alias.__value__
type_param = Alias.__type_params__[0]
bound = type_param.__bound__
argument = alias_value.__args__[0]
""").run()

    assert _points(result, "Alias")
    assert _points(result, "Bound") <= _points(result, "bound")
    assert _points(result, "type_param") <= _points(result, "argument")
    assert result.points_to_query("argument").complete


@pytest.mark.skipif(not hasattr(ast, "TypeAlias"), reason="type statements require Python 3.12+")
def test_constrained_type_alias_preserves_type_parameter_constraints():
    result = PointerAnalysis("""
class A: pass
class B: pass
type Alias[T: (A, B)] = list[T]
constraints = Alias.__type_params__[0].__constraints__
first_constraint = constraints[0]
""").run()

    assert _points(result, "A") <= _points(result, "first_constraint")
    assert result.points_to_query("first_constraint").complete


@pytest.mark.skipif(not hasattr(ast, "TypeAlias"), reason="type parameters require Python 3.12+")
def test_generic_class_preserves_runtime_type_parameters():
    result = PointerAnalysis("""
class Bound: pass
class Container[T: Bound]:
    pass
parameter = Container.__type_params__[0]
bound = parameter.__bound__
def identity[T: Bound](value):
    return value
function_parameter = identity.__type_params__[0]
function_bound = function_parameter.__bound__
def constrained[T: (Bound, str)](value):
    return value
function_constraints = constrained.__type_params__[0].__constraints__
first_function_constraint = function_constraints[0]
""").run()

    assert _points(result, "Container")
    assert _points(result, "Bound") <= _points(result, "bound")
    assert _points(result, "identity")
    assert _points(result, "Bound") <= _points(result, "function_bound")
    assert _points(result, "Bound") <= _points(result, "first_function_constraint")
    assert result.points_to_query("parameter").complete
    assert result.points_to_query("function_parameter").complete


@pytest.mark.skipif(
    "default_value" not in getattr(getattr(ast, "TypeVar", ast.AST), "_fields", ()),
    reason="type parameter defaults require Python 3.13+",
)
def test_generic_function_preserves_type_parameter_default():
    result = PointerAnalysis("""
class Default: pass
def identity[T = Default](value):
    return value
default = identity.__type_params__[0].__default__
""").run()

    assert _points(result, "Default") <= _points(result, "default")
    assert result.points_to_query("default").complete


def test_depth_limited_same_name_import_terminates(tmp_path):
    entry = tmp_path / "main.py"
    entry.write_text("from datetime import datetime\nx = datetime.now()\n", encoding="utf-8")

    result = PointerAnalysis.from_project(
        entry,
        project_path=tmp_path,
        max_import_depth=0,
        max_iterations=5_000,
    ).run()

    # Before the import-base fix this created ``datetime.datetime.datetime...``
    # native paths until the iteration budget was exhausted.
    assert result.fixpoint_complete
    assert _points(result, "x")


def test_slice_is_a_distinct_container_that_preserves_elements():
    result = PointerAnalysis("""
class A: pass
class B: pass
a = A()
b = B()
xs = [a, b]
ys = xs[1:]
y0 = ys[0]
""").run()

    assert result.complete
    assert _points(result, "ys")
    assert _points(result, "ys") != _points(result, "xs")
    assert _points(result, "y0") == _points(result, "a") | _points(result, "b")


def test_starred_literal_and_rest_target_keep_element_flow():
    result = PointerAnalysis("""
class A: pass
class B: pass
a = A()
b = B()
src = [a, b]
items = [*src]
first, *rest = src
item0 = items[0]
rest0 = rest[0]
""").run()

    assert result.complete
    assert _points(result, "a") <= _points(result, "item0")
    assert _points(result, "b") <= _points(result, "item0")
    assert _points(result, "a") <= _points(result, "rest0")
    assert _points(result, "b") <= _points(result, "rest0")


def test_sequence_concat_repeat_and_mapping_union_keep_element_flow():
    result = PointerAnalysis("""
class A: pass
class B: pass
a = A()
b = B()
xs = [a]
xs = xs + [b]
repeated = xs * 2
mapping = {"x": a}
merged = {**mapping}
union = {"x": a} | {"y": b}
merged_x = merged["x"]
union_y = union["y"]
xs0 = xs[0]
repeated0 = repeated[0]
""").run()

    assert result.complete
    assert _points(result, "a") <= _points(result, "xs0")
    assert _points(result, "b") <= _points(result, "xs0")
    assert _points(result, "a") <= _points(result, "repeated0")
    assert _points(result, "b") <= _points(result, "repeated0")
    assert _points(result, "merged_x") == _points(result, "a")
    assert _points(result, "b") <= _points(result, "union_y")


def test_builtin_container_subclasses_use_user_defined_subscript_methods():
    result = PointerAnalysis("""
list_marker = object()
add_marker = object()
dict_marker = object()
stored = object()

class CustomList(list):
    def __getitem__(self, index):
        return list_marker
    def __add__(self, other):
        return add_marker

class CustomDict(dict):
    def __getitem__(self, key):
        return dict_marker
    def __setitem__(self, key, value):
        self.saved = value

items = CustomList()
mapping = CustomDict()
list_value = items[0]
combined = items + []
dict_value = mapping["key"]
mapping["key"] = stored
saved_value = mapping.saved
""").run()

    assert _points(result, "list_marker") <= _points(result, "list_value")
    assert _points(result, "add_marker") <= _points(result, "combined")
    assert _points(result, "dict_marker") <= _points(result, "dict_value")
    assert _points(result, "stored") <= _points(result, "saved_value")


def test_rich_comparison_can_return_user_pointer_values():
    result = PointerAnalysis("""
marker = object()
class Equality(list):
    def __eq__(self, other):
        return marker
left = Equality()
right = Equality()
comparison = left == right
""").run()

    assert _points(result, "marker") <= _points(result, "comparison")


def test_contains_dispatches_to_the_container_operand():
    result = PointerAnalysis("""
sentinel = object()
seen = None
class Container:
    def __contains__(self, value):
        global seen
        seen = sentinel
        return True
item = object()
container = Container()
result = item in container
""").run()

    assert _points(result, "sentinel") <= _points(result, "seen")


def test_len_and_bool_execute_user_defined_special_methods():
    length = PointerAnalysis("""
sentinel = object()
seen = None
class Length(list):
    def __len__(self):
        global seen
        seen = sentinel
        return 1
value = len(Length())
""").run()
    truth = PointerAnalysis("""
sentinel = object()
seen = None
class Truth(list):
    def __bool__(self):
        global seen
        seen = sentinel
        return True
value = bool(Truth())
""").run()

    assert _points(length, "sentinel") <= _points(length, "seen")
    assert _points(truth, "sentinel") <= _points(truth, "seen")


def test_if_condition_invokes_user_truth_protocol():
    source = """
sentinel = object()
seen = None
class Condition(list):
    def __bool__(self):
        global seen
        seen = sentinel
        return True
if Condition():
    pass
"""
    result = PointerAnalysis(source).run()
    negated = PointerAnalysis(source.replace("if Condition():", "if not Condition():")).run()

    assert result.points_to("sentinel") <= result.points_to("seen")
    assert negated.points_to("sentinel") <= negated.points_to("seen")
    assert result.complete


def test_not_preserves_the_possible_boolean_values():
    result = PointerAnalysis("""
known = not False
unknown = not object()
""").run()

    assert any("True" in value for value in _points(result, "known"))
    assert any("False" in value for value in _points(result, "unknown"))
    assert any("True" in value for value in _points(result, "unknown"))


def test_alias_query_for_unbound_name_is_unknown():
    result = PointerAnalysis("""
class A: pass
a = A()
""").run()

    assert result.alias_status("does_not_exist", "a") is AliasStatus.UNKNOWN
    query = result.points_to_query("does_not_exist")
    assert query.complete is False
    assert query.reasons[0]["kind"] == "unbound_name"


def test_native_access_paths_are_bounded_and_idempotent():
    from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import (
        MAX_NATIVE_ACCESS_PATH_DEPTH,
        canonicalize_native_access_path,
    )

    deep = ".".join(["step"] * (MAX_NATIVE_ACCESS_PATH_DEPTH * 4))
    bounded = canonicalize_native_access_path(deep)

    assert bounded.count(".") <= MAX_NATIVE_ACCESS_PATH_DEPTH
    assert canonicalize_native_access_path(bounded + ".next") == bounded


def test_typing_cast_and_overload_are_transparent_by_default():
    cast_result = PointerAnalysis("""
class A: pass
a = A()
from typing import cast
x = cast(A, a)
""").run()
    assert cast_result.complete
    assert _points(cast_result, "x") == _points(cast_result, "a")

    overload_result = PointerAnalysis("""
from typing import overload

@overload
def f(x):
    ...

g = f
""").run()
    assert overload_result.complete
    assert _points(overload_result, "g")
    assert any("fn [overload] f(" in callee for callee in _points(overload_result, "g"))


def test_min_and_max_return_elements_not_opaque_objects():
    result = PointerAnalysis("""
class A: pass
class B: pass
a = A()
b = B()
values = [a, b]
low = min(values)
high = max(a, b)
""").run()

    assert result.complete
    assert _points(result, "a") <= _points(result, "low")
    assert _points(result, "b") <= _points(result, "low")
    assert _points(result, "a") <= _points(result, "high")
    assert _points(result, "b") <= _points(result, "high")


def test_container_copy_union_and_frozenset_preserve_elements():
    result = PointerAnalysis("""
class A: pass
class B: pass
a = A()
b = B()
values = [a, b]
copied = values.copy()
copied0 = copied[0]
mapping = {"x": a}
mapping_copy = mapping.copy()
mapping_x = mapping_copy["x"]
frozen = frozenset([a, b])
frozen0 = next(iter(frozen))
""").run()

    assert result.complete
    assert _points(result, "a") <= _points(result, "copied0")
    assert _points(result, "b") <= _points(result, "copied0")
    assert _points(result, "mapping_x") == _points(result, "a")
    assert _points(result, "a") <= _points(result, "frozen0")
    assert _points(result, "b") <= _points(result, "frozen0")


def test_from_project_infers_package_root_for_relative_imports(tmp_path):
    package = tmp_path / "pkg"
    subpackage = package / "sub"
    subpackage.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (subpackage / "__init__.py").write_text("", encoding="utf-8")
    (package / "model.py").write_text(
        "class A: pass\n\ndef make():\n    return A()\n",
        encoding="utf-8",
    )
    entry = subpackage / "use.py"
    entry.write_text(
        "from ..model import A, make\nc = A()\nd = make()\n",
        encoding="utf-8",
    )

    result = PointerAnalysis.from_project(entry).run()

    assert result.complete
    assert _points(result, "c")
    assert _points(result, "d")


def test_dataclass_fields_defaults_and_inheritance():
    result = PointerAnalysis("""
from dataclasses import dataclass, field
class A: pass
class B: pass
a = A()
b = B()

@dataclass
class Base:
    x: object

@dataclass
class Child(Base):
    y: object = None
    items: list = field(default_factory=list)

c = Child(a, b)
cx = c.x
cy = c.y
items = c.items
""").run()

    assert result.complete
    assert _points(result, "cx") == _points(result, "a")
    assert _points(result, "cy") == _points(result, "b")
    assert any("AllocKind.LIST" in obj for obj in _points(result, "items"))
    assert all("AllocKind.INSTANCE" not in obj or "Child" in obj for obj in _points(result, "c"))


def test_namedtuple_and_enum_members_resolve():
    named = PointerAnalysis("""
from typing import NamedTuple
class A: pass
class Pair(NamedTuple):
    left: object
    right: object
a = A()
p = Pair(a, a)
value = p.left
""").run()
    assert named.complete
    assert _points(named, "value") == _points(named, "a")

    enum = PointerAnalysis("""
import enum
class Color(enum.Enum):
    RED = 1
    BLUE = 2
selected = Color.RED
number = selected.value
""").run()
    assert enum.complete
    assert any("enum-member" in obj for obj in _points(enum, "selected"))
    assert any("AllocKind.CONSTANT" in obj for obj in _points(enum, "number"))


def test_property_getter_survives_setter_decorator():
    result = PointerAnalysis("""
class A: pass
class B: pass
class Box:
    def __init__(self):
        self._value = A()
    @property
    def value(self):
        return self._value
    @value.setter
    def value(self, new):
        self._value = new
box = Box()
read = box.value
""").run()

    assert result.complete
    assert _points(result, "a").issubset(_points(result, "read")) if _points(result, "a") else True
    # The getter must contribute the initial A value.
    assert any("A()" in obj for obj in _points(result, "read"))


def test_constant_index_loads_are_precise_and_mutations_stay_sound():
    result = PointerAnalysis("""
class A: pass
class B: pass
a = A()
b = B()
items = [a, b]
first = items[0]
second = items[1]
mutated = [a]
mutated.append(B())
after_append = mutated[0]
""").run()

    assert result.complete
    assert _points(result, "first") == _points(result, "a")
    assert _points(result, "second") == _points(result, "b")
    assert _points(result, "a") <= _points(result, "after_append")
    assert any("B()" in obj for obj in _points(result, "after_append"))


def test_augmented_assignment_uses_inplace_dunder():
    result = PointerAnalysis("""
class A: pass
class Box:
    def __iadd__(self, other):
        return A()
box = Box()
box += 1
result = box
""").run()

    assert result.complete
    assert any("A()" in obj for obj in _points(result, "result"))


def test_star_import_copy_chain_and_scope_dicts():
    result = PointerAnalysis.from_project if False else PointerAnalysis("""
import copy
import itertools
from math import *
class A: pass
a = A()
items = [a]
copied = copy.copy(items)
chained = list(itertools.chain(items, [a]))[0]
scope = globals()
from_scope = scope["a"]
local_scope = locals()
from_local = local_scope["a"]
""").run()

    assert result.complete
    assert _points(result, "a") <= _points(result, "chained")
    assert _points(result, "from_scope") == _points(result, "a")
    assert _points(result, "from_local") == _points(result, "a")


def test_starred_class_bases_do_not_crash():
    result = PointerAnalysis("""
class MyTimeout(Exception):
    pass

Bases = (ValueError, LookupError)

class Combined(*Bases):
    pass

instance = Combined()
""").run()

    assert _points(result, "instance")
    assert result.complete is False
    assert any(reason["kind"] == "starred_class_base" for reason in result.incomplete_reasons())


def test_yield_from_yields_inner_elements():
    result = PointerAnalysis("""
class A: pass
class B: pass

def inner():
    yield A()
    returned = B()
    return returned

def outer():
    value = yield from inner()
    yield value

it = outer()
first = next(it)
second = next(it)
""").run()

    assert any("A()" in obj for obj in _points(result, "first"))
    assert any("A()" in obj for obj in _points(result, "second"))
    assert _points(result, "returned") <= _points(result, "second")


def test_next_with_default_includes_default_for_empty_iterator():
    result = PointerAnalysis("""
class Fallback: pass
fallback = Fallback()
value = next(iter(()), fallback)
""").run()

    assert _points(result, "fallback") <= _points(result, "value")


def test_advanced_dataclass_fields_post_init_and_asdict():
    result = PointerAnalysis("""
from dataclasses import dataclass, field, InitVar, asdict, astuple
from typing import ClassVar
class A: pass
class B: pass
a = A()
b = B()

@dataclass
class D:
    cv: ClassVar[object] = None
    iv: InitVar[object] = None
    x: object = field(init=False)
    y: object = field(default=b)

    def __post_init__(self, iv):
        self.x = a

d = D()
dx = d.x
dy = d.y
mapping = asdict(d)
mapping_x = mapping["x"]
values = astuple(d)
value_x = values[0]
""").run()

    assert result.complete
    assert _points(result, "dx") == _points(result, "a")
    assert _points(result, "dy") == _points(result, "b")
    assert _points(result, "mapping_x") == _points(result, "a")
    assert _points(result, "value_x") == _points(result, "a")


def test_type_and_class_attributes_resolve_class_objects():
    result = PointerAnalysis("""
class A: pass
a = A()
class_of_a = a.__class__
via_type = type(a)
first = class_of_a()
second = via_type()
""").run()

    assert result.complete
    assert any("class A" in obj for obj in _points(result, "class_of_a"))
    assert any("class A" in obj for obj in _points(result, "via_type"))
    assert _points(result, "first")
    assert _points(result, "second")


def test_typing_newtype_is_identity():
    result = PointerAnalysis("""
from typing import NewType
class A: pass
a = A()
UserId = NewType("UserId", int)
value = UserId(a)
""").run()

    assert result.complete
    assert _points(result, "value") == _points(result, "a")


def test_boolean_and_integer_constants_do_not_alias():
    result = PointerAnalysis("""
class A: pass
class B: pass
a = A()
b = B()
values = [a, b]
zero = values[False]
one = values[True]
mapping = {False: a, True: b}
mapping_zero = mapping[0]
mapping_one = mapping[1]
""").run()

    assert result.complete
    assert _points(result, "zero") == _points(result, "a")
    assert _points(result, "one") == _points(result, "b")
    assert _points(result, "mapping_zero") == _points(result, "a")
    assert _points(result, "mapping_one") == _points(result, "b")


def test_singledispatch_registered_implementation_flows():
    result = PointerAnalysis("""
import functools
class A: pass
class B: pass

@functools.singledispatch
def convert(value):
    return A()

@convert.register
def _(value: int):
    return B()

value = convert(1)
""").run()

    assert result.complete
    assert any("A()" in obj for obj in _points(result, "value"))
    assert any("B()" in obj for obj in _points(result, "value"))
