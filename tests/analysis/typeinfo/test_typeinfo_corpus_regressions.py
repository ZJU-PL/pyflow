"""Regressions for issues found while running typeinfo on the top-100 corpus."""

from __future__ import annotations

from pathlib import Path

from pyflow.analysis.typeinfo import (
    InferenceOptions,
    ObservedType,
    ProjectTypeInferenceEngine,
    StaticTypeInferenceEngine,
    TypeInfoService,
    validate_observed_types,
)
from pyflow.analysis.typeinfo.core.typesystem import (
    CallableType,
    Instance,
    TupleType,
    TypeType,
)
from pyflow.language.modules.project_resolution import ProjectContext


def infer(source: str, *, strict: bool = False):
    return StaticTypeInferenceEngine(
        options=InferenceOptions(strict_annotations=strict)
    ).infer_source("m", source)


def raw_types(typ) -> set[type]:
    if isinstance(typ, Instance):
        return {typ.type.raw_type}
    items = getattr(typ, "items", ())
    return {item.type.raw_type for item in items if isinstance(item, Instance)}


def test_unknown_operand_does_not_produce_complete_numeric_type() -> None:
    result = infer(
        "import sys\nu = sys.argv[0]\nx = u * 2\n"
    )
    value = result.value_of("x")
    assert value is not None
    assert value.public_type() is None or value.unknown
    assert not value.is_complete or value.public_type() is None


def test_generator_expression_is_a_generator_not_a_list() -> None:
    result = infer("g = (i for i in range(3))\n")
    typ = result.type_of("g")
    assert isinstance(typ, Instance)
    assert typ.type.full_name == "collections.abc.Generator"


def test_tuple_repetition_stays_a_tuple() -> None:
    result = infer("x = (1, 2) * 3\n")
    typ = result.type_of("x")
    assert typ is not None
    assert typ.__class__.__name__ == "TupleType"


def test_dict_unpack_merges_mapping_key_value_types() -> None:
    result = infer("x = {**{'a': 1}}\ny = x['a']\n")
    assert raw_types(result.type_of("x")) == {dict}
    assert raw_types(result.type_of("y")) == {int}
    typ = result.type_of("x")
    assert isinstance(typ, Instance)
    assert [str(arg) for arg in typ.args] == ["str", "int"]


def test_extend_and_update_widen_collection_elements() -> None:
    source = """
xs = [1]
xs.extend(['s'])
a = xs[-1]
ys = {1}
ys.update({'s'})
b = list(ys)[-1]
d = {'a': 1}
d.update({'b': 's'})
c = d['b']
"""
    result = infer(source)
    assert raw_types(result.type_of("a")) == {int, str}
    assert raw_types(result.type_of("b")) == {int, str}
    assert raw_types(result.type_of("c")) == {int, str}


def test_alias_mutation_widens_all_equal_bindings() -> None:
    result = infer("a = [1]\nb = a\nb.append('s')\ny = a[-1]\n")
    a_type = result.type_of("a")
    assert isinstance(a_type, Instance)
    assert [str(arg) for arg in a_type.args] == ["int | str"]
    assert raw_types(result.type_of("y")) == {int, str}


def test_none_sentinel_is_not_a_type_alias() -> None:
    result = infer("CACHE = None\nCACHE = 1\nVALUE = CACHE\n")
    assert raw_types(result.type_of("VALUE")) == {int}


def test_builtin_shadowing_and_chained_builtin_named_methods() -> None:
    source = """
def id(x: int) -> str:
    return str(x)
a = id(1)
def dict() -> int:
    return 1
b = dict()
str = 5
c = str
class N:
    def set(self, v: int) -> int:
        return v
d = N().set(1)
"""
    result = infer(source)
    assert raw_types(result.type_of("a")) == {str}
    assert raw_types(result.type_of("b")) == {int}
    assert raw_types(result.type_of("c")) == {int}
    assert raw_types(result.type_of("d")) == {int}


def test_module_global_reads_are_visible_inside_functions() -> None:
    source = """
X = 1
NAMES: list[str] = ['a']
CONFIG = {'x': 1}
def a(): return X
def b(): return NAMES[0]
def c(): return CONFIG['x']
"""
    result = infer(source)
    assert raw_types(result.functions["m.a"].return_type) == {int}
    assert raw_types(result.functions["m.b"].return_type) == {str}
    assert raw_types(result.functions["m.c"].return_type) == {int}


def test_varargs_and_kwargs_bodies_see_containers() -> None:
    result = infer(
        "def f(*xs: int):\n    return xs[0]\n"
        "def g(**kw: int):\n    return kw['a']\n"
    )
    assert raw_types(result.functions["m.f"].return_type) == {int}
    assert raw_types(result.functions["m.g"].return_type) == {int}
    assert isinstance(result.functions["m.f"].parameters["xs"].public_type(), TupleType)
    assert raw_types(result.functions["m.g"].parameters["kw"].public_type()) == {dict}


def test_protocol_annotation_with_type_does_not_crash() -> None:
    source = (
        "from typing import Protocol\n"
        "class P(Protocol):\n    x: int\n"
        "def f(t: type):\n    y: P = t\n"
        "def g(x: P):\n    if not isinstance(x, type):\n        pass\n"
    )
    result = infer(source)
    assert result.converged


def test_in_narrowing_removes_none() -> None:
    source = """
def g(x: str) -> str: return x
def f(x: str | None):
    if x in {'a', 'b'}:
        return g(x)
    return ''
"""
    result = infer(source, strict=True)
    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]


def test_enum_name_and_value_attributes() -> None:
    result = infer(
        "from enum import Enum, IntEnum, StrEnum\n"
        "class C(Enum): A = 1\n"
        "class I(IntEnum): A = 1\n"
        "class S(StrEnum): A = 'a'\n"
        "n = C.A.name\nv = C.A.value\n"
        "ni = I.A.name\nvi = I.A.value\n"
        "ns = S.A.name\nvs = S.A.value\n"
    )
    for name in ("n", "ni", "ns"):
        assert raw_types(result.type_of(name)) == {str}
    assert raw_types(result.type_of("v")) == {int}
    assert raw_types(result.type_of("vi")) == {int}
    assert raw_types(result.type_of("vs")) == {str}


def test_match_class_pattern_binds_field_types() -> None:
    source = """
from dataclasses import dataclass
@dataclass
class P:
    x: int
    y: str
p = P(1, 's')
match p:
    case P(a, b):
        pass
match p:
    case P(x=c, y=d):
        pass
"""
    result = infer(source)
    assert raw_types(result.type_of("a")) == {int}
    assert raw_types(result.type_of("b")) == {str}
    assert raw_types(result.type_of("c")) == {int}
    assert raw_types(result.type_of("d")) == {str}


def test_generic_constructor_and_generic_base_substitution() -> None:
    source = """
from typing import Generic, TypeVar
T = TypeVar('T')
class Box(Generic[T]):
    def __init__(self, v: T): self.v = v
    def get(self) -> T: return self.v
class IntBox(Box[int]):
    pass
b = Box(1)
x = b.get()
i = IntBox(1)
y = i.get()
z = i.v
"""
    result = infer(source)
    assert raw_types(result.type_of("x")) == {int}
    assert raw_types(result.type_of("y")) == {int}
    assert raw_types(result.type_of("z")) == {int}


def test_super_method_and_attribute_lookup() -> None:
    source = """
class A:
    value: int = 1
    def m(self) -> int: return 1
class B(A):
    def attr(self): return super().value
    def meth(self): return super().m()
b = B()
a = b.attr()
m = b.meth()
class C(A):
    def m(self) -> str: return 'c'
class D(C, B):
    pass
diamond = D().m()
"""
    result = infer(source)
    assert raw_types(result.type_of("a")) == {int}
    assert raw_types(result.type_of("m")) == {int}
    assert raw_types(result.type_of("diamond")) == {str}


def test_empty_list_append_keeps_the_first_element_type() -> None:
    result = infer("out = []\nout.append(1)\ny = out[0]\n")
    assert raw_types(result.type_of("out")) == {list}
    assert raw_types(result.type_of("y")) == {int}


def test_late_closure_assignment_is_sound() -> None:
    result = infer(
        "def f():\n"
        "    v = 1\n"
        "    def g(): return v\n"
        "    v = 's'\n"
        "    return g()\n"
        "x = f()\n"
    )
    assert raw_types(result.type_of("x")) == {int, str}


def test_open_read_types_without_stubs() -> None:
    result = infer(
        'with open("x") as f:\n    text = f.read()\n'
        'with open("x", "rb") as g:\n    data = g.read()\n'
    )
    assert raw_types(result.type_of("text")) == {str}
    assert raw_types(result.type_of("data")) == {bytes}


def test_validator_accepts_local_classes_type_objects_and_numeric_tower() -> None:
    source = "class A:\n    pass\na = A()\n"
    result = infer(source)
    namespace: dict[str, object] = {"__name__": "m"}
    exec(source, namespace)
    assert not validate_observed_types(
        result, [ObservedType(namespace["a"].__class__, "a")]
    )

    result = infer("x = type(1)\n")
    assert not validate_observed_types(result, [ObservedType(type, "x")])

    result = infer("y = 1 + 1.5\n")
    assert not validate_observed_types(result, [ObservedType(int, "y")])


def _write_order_project(root: Path, *, dependency_first: bool) -> tuple[str, str]:
    dependency = "a_dep" if dependency_first else "z_dep"
    app = "z_app" if dependency_first else "a_app"
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{dependency}.py").write_text(
        "class A:\n"
        "    value: int = 1\n"
        "    def m(self) -> int:\n"
        "        return 1\n"
    )
    (root / f"{app}.py").write_text(
        f"from {dependency} import A\n"
        "def f(x: A):\n"
        "    return x.m()\n"
        "def g(x: A):\n"
        "    return x.value\n"
        "y = A()\n"
        "z = y.m()\n"
    )
    return dependency, app


def test_project_inference_is_order_independent(tmp_path: Path) -> None:
    results = []
    for dependency_first in (True, False):
        _, app = _write_order_project(
            tmp_path / ("good" if dependency_first else "bad"),
            dependency_first=dependency_first,
        )
        root = tmp_path / ("good" if dependency_first else "bad")
        inferred = ProjectTypeInferenceEngine(ProjectContext(root)).infer_project([app])
        module = inferred.modules[app]
        results.append(
            (
                raw_types(module.functions[f"{app}.f"].return_type),
                raw_types(module.functions[f"{app}.g"].return_type),
            )
        )
    assert results == [({int}, {int}), ({int}, {int})]


def test_project_module_qualified_access_and_reexports(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("from .core import A, VALUE, helper\n")
    (package / "core.py").write_text(
        "VALUE: int = 1\n"
        "def helper(x: int) -> str:\n    return str(x)\n"
        "class A:\n    def m(self) -> int:\n        return 1\n"
    )
    (tmp_path / "app.py").write_text(
        "import pkg\nimport pkg.core\n"
        "from pkg import A, VALUE, helper\n"
        "a = pkg.VALUE\n"
        "b = pkg.core.helper(1)\n"
        "c = helper(1)\n"
        "d = A().m()\n"
    )
    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(
        ["app"]
    )
    module = result.modules["app"]
    assert raw_types(module.type_of("a")) == {int}
    assert raw_types(module.type_of("b")) == {str}
    assert raw_types(module.type_of("c")) == {str}
    assert raw_types(module.type_of("d")) == {int}


def test_typeinfo_service_resolves_cross_module_members(tmp_path: Path) -> None:
    dependency, app = _write_order_project(tmp_path, dependency_first=False)
    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module(app)
    result = service.inference_result(app)
    assert result is not None
    assert raw_types(result.functions[f"{app}.f"].return_type) == {int}
    assert raw_types(result.functions[f"{app}.g"].return_type) == {int}
    method = service.type_of(dependency, "A.m")
    assert isinstance(method, CallableType)
    assert raw_types(method.return_type) == {int}
    assert raw_types(service.type_of(dependency, "A.value")) == {int}


def test_local_stub_class_members_feed_inference(tmp_path: Path) -> None:
    package = tmp_path / "lib"
    package.mkdir()
    (package / "__init__.pyi").write_text(
        "class Widget:\n"
        "    name: str\n"
        "    def render(self, width: int) -> bytes: ...\n"
        "def make(name: str) -> Widget: ...\n"
    )
    (tmp_path / "app.py").write_text(
        "from lib import Widget, make\n"
        "w = Widget()\n"
        "name = w.name\n"
        "rendered = w.render(1)\n"
        "made = make('x')\n"
    )
    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("app")
    result = service.inference_result("app")
    assert result is not None
    assert raw_types(result.type_of("name")) == {str}
    assert raw_types(result.type_of("rendered")) == {bytes}
    assert isinstance(result.type_of("made"), Instance)
    assert result.type_of("made").type.full_name == "lib.Widget"


def test_stub_version_conditional_members_are_collected(tmp_path: Path) -> None:
    package = tmp_path / "lib"
    package.mkdir()
    (package / "__init__.pyi").write_text(
        "import sys\n"
        "class C:\n"
        "    if sys.version_info >= (3, 0):\n"
        "        def m(self) -> int: ...\n"
        "    else:\n"
        "        def m(self) -> str: ...\n"
    )
    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("lib")
    member = service.type_of("lib", "C.m")
    assert member is not None
