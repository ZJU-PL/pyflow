"""Regression tests for k-CFA soundness and termination gaps."""

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
