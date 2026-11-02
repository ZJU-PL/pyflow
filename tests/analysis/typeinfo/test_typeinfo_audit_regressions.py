"""Regression tests for issues found while exercising typeinfo on real projects."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pyflow.analysis.typeinfo import (
    ProjectTypeInferenceEngine,
    StaticTypeInferenceEngine,
    TypeInfoService,
)
from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    CallableType,
    Instance,
    TupleType,
    TypeSystem,
    TypeType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference.engine import InferenceOptions
from pyflow.language.modules.project_resolution import ProjectContext


def _infer(source: str, *, strict: bool = False):
    return StaticTypeInferenceEngine(
        options=InferenceOptions(strict_annotations=strict)
    ).infer_source("sample", source)


def _raw_types(typ) -> set[type]:
    if isinstance(typ, Instance):
        return {typ.type.raw_type}
    if isinstance(typ, TypeType):
        return _raw_types(typ.item)
    if isinstance(typ, UnionType):
        result: set[type] = set()
        for item in typ.items:
            result.update(_raw_types(item))
        return result
    return set()


def _instance_name(typ) -> str:
    if isinstance(typ, TypeType):
        typ = typ.item
    assert isinstance(typ, Instance)
    return typ.type.full_name


def test_dict_shape_specializations_are_sortable() -> None:
    result = _infer("""
def f(d):
    return d

f({"a": 1})
d: dict[str, int] = {}
f(d)
""")

    assert result.converged
    assert _raw_types(result.functions["sample.f"].return_type) == {dict}


def test_division_does_not_coerce_non_numeric_receivers_to_float() -> None:
    result = _infer("""
from pathlib import Path
from decimal import Decimal

path = Path("a") / "b"
amount = Decimal("1.0") / 2
integer = 1 / 2
floating = 1.5 / 2
""")

    assert result.type_of("sample.path") is None
    assert result.type_of("sample.amount") is None
    assert _raw_types(result.type_of("sample.integer")) == {float}
    assert _raw_types(result.type_of("sample.floating")) == {float}


def test_service_does_not_fabricate_nominal_classes_for_calls() -> None:
    service = TypeInfoService()
    service.collect_module(
        "sample",
        source="""
import json
import os
import re
import time

loaded = json.loads("{}")
cwd = os.getcwd()
pattern = re.compile("x")
timestamp = time.time()
""",
    )

    for name in ("loaded", "cwd", "pattern", "timestamp"):
        assert service.fact_of("sample", name) is None
    assert service.inference_result("sample").status == "complete"


def test_class_objects_project_to_type_types_in_values_and_containers() -> None:
    result = _infer("""
class A:
    pass

class B:
    pass

alias = A
mapping = {A: 1, B: 2}
pair = (A, B)
annotated: type[A] = A
""")

    alias = result.type_of("sample.alias")
    assert isinstance(alias, TypeType)
    assert _instance_name(alias) == "sample.A"

    mapping = result.type_of("sample.mapping")
    assert isinstance(mapping, Instance) and mapping.type.raw_type is dict
    assert isinstance(mapping.args[0], UnionType)
    assert {_instance_name(item) for item in mapping.args[0].items} == {
        "sample.A",
        "sample.B",
    }

    pair = result.type_of("sample.pair")
    assert isinstance(pair, TupleType)
    assert [_instance_name(item) for item in pair.args] == ["sample.A", "sample.B"]
    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]


def test_bound_method_lookup_drops_receiver_but_class_lookup_does_not() -> None:
    result = _infer("""
class A:
    def m(self, x: int) -> str:
        return ""

    @classmethod
    def c(cls, x: int) -> str:
        return ""

    @staticmethod
    def s(x: int) -> str:
        return ""

a = A()
bound = a.m
unbound = A.m
class_bound = A.c
static = A.s
""")

    assert str(result.type_of("sample.bound")) == "Callable[[int], str]"
    assert str(result.type_of("sample.unbound")) == "Callable[[Any, int], str]"
    assert str(result.type_of("sample.class_bound")) == "Callable[[int], str]"
    assert str(result.type_of("sample.static")) == "Callable[[int], str]"


def test_fresh_collection_literals_widen_in_call_arguments() -> None:
    result = _infer(
        """
class A:
    pass

class B:
    pass

def take_list(items: list[A | B]) -> None: ...
def take_set(items: set[A | B]) -> None: ...
def take_dict(items: dict[str, A | B]) -> None: ...

take_list([A()])
take_set({A()})
take_dict({"a": A()})
""",
        strict=True,
    )

    assert [d for d in result.diagnostics if d.code == "annotation-mismatch"] == []


def test_callable_ellipsis_and_type_type_are_assignable() -> None:
    type_system = TypeSystem()
    string = Instance(type_system.to_class_descriptor(str))
    boolean = Instance(type_system.to_class_descriptor(bool))
    assert type_system.is_subtype(
        CallableType(None, ANY),
        CallableType((string,), boolean),
    )
    assert type_system.is_subtype(
        type_system.convert_type_hint(type[int]),
        type_system.convert_type_hint(type),
    )


def test_engine_reuse_recomputes_protocol_compatibility() -> None:
    engine = StaticTypeInferenceEngine(options=InferenceOptions(strict_annotations=True))
    matching = """
from typing import Protocol
class P(Protocol):
    def m(self, x: int) -> str: ...
class A:
    def m(self, x: int) -> str:
        return ""
def take(p: P) -> None: ...
take(A())
"""
    mismatch = """
from typing import Protocol
class P(Protocol):
    def m(self, x: int) -> str: ...
class A:
    def m(self, x: str) -> int:
        return 1
def take(p: P) -> None: ...
take(A())
"""

    assert not engine.infer_source("sample", matching).diagnostics
    result = engine.infer_source("sample", mismatch)
    assert any(d.code == "annotation-mismatch" for d in result.diagnostics)


def test_type_checking_import_resolves_in_annotations() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("models.py").write_text(
            "class Client:\n    value: int\n",
            encoding="utf-8",
        )
        package.joinpath("service.py").write_text(
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from .models import Client\n\n"
            "def fetch(client: Client) -> Client:\n"
            "    return client\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))
        service.collect_module("pkg.service")

        signature = service.signature_of("pkg.service", "fetch")
        assert signature is not None
        assert _instance_name(signature.params["client"]) == "pkg.models.Client"
        assert _instance_name(signature.returns) == "pkg.models.Client"


def test_project_inference_uses_imported_class_members() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("models.py").write_text(
            "class Model:\n"
            "    def __init__(self, value: int) -> None:\n"
            "        self.value = value\n"
            "    def get(self) -> int:\n"
            "        return self.value\n",
            encoding="utf-8",
        )
        package.joinpath("use.py").write_text(
            "from .models import Model\n\n"
            "def use() -> tuple[int, int]:\n"
            "    model = Model(3)\n"
            "    return model.value, model.get()\n",
            encoding="utf-8",
        )

        result = ProjectTypeInferenceEngine(ProjectContext(root)).infer_project(["pkg.use"])
        summary = result.modules["pkg.use"].functions["pkg.use.use"]
        assert isinstance(summary.return_type, TupleType)
        assert all(_raw_types(item) == {int} for item in summary.return_type.args)


def test_members_of_loads_the_defining_module() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("models.py").write_text(
            "class Client:\n    value: int = 1\n",
            encoding="utf-8",
        )

        service = TypeInfoService(ProjectContext(root))
        members = service.members_of("pkg.models.Client")
        assert "value" in members


def test_ellipsis_body_is_a_stub_not_an_implicit_none_return() -> None:
    result = _infer(
        """
from typing import Generic, TypeVar
T = TypeVar("T")
class Box(Generic[T]):
    def get(self) -> T: ...
""",
        strict=True,
    )

    assert [d for d in result.diagnostics if d.code == "annotation-mismatch"] == []


def test_unresolved_annotation_keeps_inferred_value_type() -> None:
    service = TypeInfoService()
    service.collect_module(
        "sample",
        source="from missing import T\nvalue: T = 1\n",
    )

    fact = service.fact_of("sample", "value")
    assert fact is not None
    assert _raw_types(fact.typ) == {int}


def test_common_builtins_and_instance_call() -> None:
    result = _infer("""
class A:
    x: int = 1
    def __call__(self, value: int) -> str:
        return ""

a = A()
attribute = getattr(a, "x")
absolute = abs(-1)
rounded = round(1.5)
quotient, remainder = divmod(3, 2)
power = pow(2, 3)
called = a(1)
""")

    assert _raw_types(result.type_of("sample.attribute")) == {int}
    assert _raw_types(result.type_of("sample.absolute")) == {int}
    assert _raw_types(result.type_of("sample.rounded")) == {int}
    assert _raw_types(result.type_of("sample.power")) == {int}
    assert _raw_types(result.type_of("sample.called")) == {str}
    assert _raw_types(result.type_of("sample.quotient")) == {int}
    assert _raw_types(result.type_of("sample.remainder")) == {int}


def test_service_collects_project_modules_from_src_layout(tmp_path: Path) -> None:
    package = tmp_path / "src" / "pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "impl.py").write_text("class Client:\n    value: int = 1\n", encoding="utf-8")
    (package / "use.py").write_text(
        "from .impl import Client\nclient = Client()\nvalue = client.value\n",
        encoding="utf-8",
    )

    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("pkg.use")

    assert _instance_name(service.type_of("pkg.use", "client")) == "pkg.impl.Client"
    assert _raw_types(service.type_of("pkg.use", "value")) == {int}
    assert service.inference_result("pkg.use").status == "complete"


def test_empty_accumulator_mutations_survive_branches_and_loops() -> None:
    branch = _infer(
        "def f(flag: bool):\n"
        "    xs = []\n"
        "    if flag:\n"
        "        xs.append(1)\n"
        "    return xs\n"
    )
    loop = _infer(
        "def f():\n"
        "    xs = []\n"
        "    for item in [1, 2]:\n"
        "        xs.append(item)\n"
        "    return xs\n"
    )
    ternary = _infer("def f(flag: bool):\n    return [] if flag else [1]\n")

    assert _raw_types(branch.functions["sample.f"].return_type) == {list}
    assert _raw_types(loop.functions["sample.f"].return_type) == {list}
    assert _raw_types(ternary.functions["sample.f"].return_type) == {list}
    assert str(branch.functions["sample.f"].return_type) == "list[int]"
    assert str(loop.functions["sample.f"].return_type) == "list[int]"
    assert str(ternary.functions["sample.f"].return_type) == "list[int]"


def test_union_members_and_subscripts_are_projected_per_alternative() -> None:
    result = _infer(
        "class A:\n"
        "    value: int = 1\n"
        "class B:\n"
        "    value: int = 2\n"
        "def attr(item: A | B) -> int:\n"
        "    return item.value\n"
        "def index(item: list[int] | dict[str, int]) -> int:\n"
        "    return item[0]\n"
        "def iterate(item: list[str] | set[str]) -> str:\n"
        "    for value in item:\n"
        "        result = value\n"
        "    return result\n"
    )

    assert _raw_types(result.functions["sample.attr"].return_type) == {int}
    assert _raw_types(result.functions["sample.index"].return_type) == {int}
    assert _raw_types(result.functions["sample.iterate"].return_type) == {str}


def test_typevar_projection_through_abstract_containers_and_callables() -> None:
    result = _infer(
        "from typing import Callable, Iterable, Mapping, Sequence, TypeVar\n"
        "T = TypeVar('T')\n"
        "K = TypeVar('K')\n"
        "V = TypeVar('V')\n"
        "def first(values: Sequence[T]) -> T: ...\n"
        "def flatten(values: Iterable[T]) -> T: ...\n"
        "def lookup(mapping: Mapping[K, V], key: K) -> V: ...\n"
        "def apply(func: Callable[[T], V], value: T) -> V: ...\n"
        "a = first([1])\n"
        "b = flatten([1])\n"
        "c = lookup({'a': 1}, 'a')\n"
        "d = apply(lambda value: str(value), 1)\n"
    )

    assert _raw_types(result.type_of("sample.a")) == {int}
    assert _raw_types(result.type_of("sample.b")) == {int}
    assert _raw_types(result.type_of("sample.c")) == {int}
    assert _raw_types(result.type_of("sample.d")) == {str}


def test_generic_base_arguments_are_available_without_constructor_evidence() -> None:
    result = _infer(
        "from typing import Generic, TypeVar\n"
        "T = TypeVar('T')\n"
        "class Box(Generic[T]):\n"
        "    def get(self) -> T: ...\n"
        "    def put(self, value: T) -> None: ...\n"
        "class IntBox(Box[int]):\n"
        "    pass\n"
        "box = IntBox()\n"
        "value = box.get()\n"
        "box.put('bad')\n"
    )

    assert _raw_types(result.type_of("sample.value")) == {int}
    assert any(diagnostic.code == "annotation-mismatch" for diagnostic in result.diagnostics)


def test_default_parameter_values_seed_body_inference() -> None:
    result = _infer(
        "def number(value=1):\n"
        "    return value\n"
        "def words(value='text'):\n"
        "    return value\n"
        "def values(items=[]):\n"
        "    items.append(1)\n"
        "    return items\n"
    )

    assert _raw_types(result.functions["sample.number"].return_type) == {int}
    assert _raw_types(result.functions["sample.words"].return_type) == {str}
    assert _raw_types(result.functions["sample.values"].return_type) == {list}
    assert str(result.functions["sample.values"].return_type) == "list[int]"


def test_generator_call_preserves_send_and_return_parameters() -> None:
    result = _infer(
        "from typing import Generator\n"
        "def gen() -> Generator[int, str, bool]:\n"
        "    yield 1\n"
        "    return True\n"
        "generator = gen()\n"
        "sent = generator.send('value')\n"
    )

    assert str(result.type_of("sample.generator")).startswith("collections.abc.Generator")
    assert _raw_types(result.type_of("sample.sent")) == {bool}


def test_signature_and_members_follow_dotted_and_inherited_classes() -> None:
    service = TypeInfoService()
    service.collect_module(
        "m",
        source=(
            "class Base:\n"
            "    x: int = 1\n"
            "    def ping(self, value: str) -> int: return 1\n"
            "class Child(Base):\n"
            "    y: float = 1.0\n"
        ),
    )

    signature = service.signature_of("m", "Child.ping")
    assert signature is not None
    assert _instance_name(signature.returns) == "builtins.int"
    members = service.members_of("m.Child")
    assert {"x", "ping", "y"} <= members.keys()


def test_source_overloads_select_return_types_by_argument() -> None:
    result = _infer(
        "from typing import overload\n"
        "@overload\n"
        "def convert(value: int) -> str: ...\n"
        "@overload\n"
        "def convert(value: str) -> int: ...\n"
        "def convert(value):\n"
        "    return 1.0\n"
        "text = convert(1)\n"
        "number = convert('value')\n"
    )

    assert _raw_types(result.type_of("sample.text")) == {str}
    assert _raw_types(result.type_of("sample.number")) == {int}


def test_stub_overloads_do_not_collapse_to_the_last_declaration(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "stubmod.pyi").write_text(
        "from typing import overload\n"
        "@overload\n"
        "def convert(value: str) -> int: ...\n"
        "@overload\n"
        "def convert(value: bytes) -> bytes: ...\n",
        encoding="utf-8",
    )
    (package / "use.py").write_text(
        "from .stubmod import convert\nresult = convert('value')\n",
        encoding="utf-8",
    )

    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("pkg.use")

    assert _raw_types(service.type_of("pkg.use", "result")) == {int, bytes}


def test_builtin_generic_subclasses_keep_container_element_types() -> None:
    result = _infer(
        "class IntList(list[int]):\n"
        "    pass\n"
        "class StringDict(dict[str, int]):\n"
        "    pass\n"
        "items = IntList()\n"
        "items.append(1)\n"
        "first = items[0]\n"
        "for item in items:\n"
        "    looped = item\n"
        "mapping = StringDict()\n"
        "mapping['key'] = 1\n"
        "value = mapping['key']\n"
        "keys = mapping.keys()\n"
    )

    assert _raw_types(result.type_of("sample.first")) == {int}
    assert _raw_types(result.type_of("sample.looped")) == {int}
    assert _raw_types(result.type_of("sample.value")) == {int}
    assert "KeysView" in str(result.type_of("sample.keys"))


def test_common_stdlib_containers_and_functional_helpers_are_modelled() -> None:
    result = _infer(
        "from collections import ChainMap, Counter, OrderedDict, defaultdict, deque\n"
        "from functools import partial, reduce\n"
        "import itertools as it\n"
        "queue = deque([1])\n"
        "popped = queue.popleft()\n"
        "mapping = defaultdict(int)\n"
        "defaulted = mapping['missing']\n"
        "counter = Counter('aab')\n"
        "common = counter.most_common(1)\n"
        "ordered = OrderedDict(a=1)\n"
        "item = ordered.popitem()\n"
        "chain = ChainMap({'a': 1})\n"
        "chained = chain['a']\n"
        "def add(x: int, y: str) -> float: return 1.0\n"
        "partial_add = partial(add, 1)\n"
        "partial_result = partial_add('value')\n"
        "reduced = reduce(lambda x, y: x + y, [1, 2], 0)\n"
        "chained_iter = list(it.chain([1], [2]))\n"
        "product_iter = list(it.product([1], ['a']))\n"
        "texts = list(map(str, [1]))\n"
        "incremented = list(map(lambda x: x + 1, [1]))\n"
        "filtered = list(filter(None, [1, None]))\n"
        "mapping_literal = dict(a=1)\n"
        "from pathlib import Path\n"
        "path = Path('x')\n"
        "path_text = path.read_text()\n"
        "path_exists = path.exists()\n"
        "path_entries = list(path.iterdir())\n"
        "path_binary = path.open('wb')\n"
    )

    assert _raw_types(result.type_of("sample.popped")) == {int}
    assert _raw_types(result.type_of("sample.defaulted")) == {int}
    assert str(result.type_of("sample.common")) == "list[tuple[str, int]]"
    assert str(result.type_of("sample.item")) == "tuple[str, int]"
    assert _raw_types(result.type_of("sample.chained")) == {int}
    assert _raw_types(result.type_of("sample.partial_result")) == {float}
    assert _raw_types(result.type_of("sample.reduced")) == {int}
    assert str(result.type_of("sample.chained_iter")) == "list[int]"
    assert str(result.type_of("sample.product_iter")) == "list[tuple[int, str]]"
    assert str(result.type_of("sample.texts")) == "list[str]"
    assert str(result.type_of("sample.incremented")) == "list[int]"
    assert str(result.type_of("sample.filtered")) == "list[int]"
    assert str(result.type_of("sample.mapping_literal")) == "dict[str, int]"
    assert _raw_types(result.type_of("sample.path_text")) == {str}
    assert _raw_types(result.type_of("sample.path_exists")) == {bool}
    assert "pathlib" in str(result.type_of("sample.path_entries"))
    assert "BufferedIOBase" in str(result.type_of("sample.path_binary"))


def test_class_getattr_and_custom_descriptors_are_resolved() -> None:
    result = _infer(
        "class Descriptor:\n"
        "    def __get__(self, instance, owner=None) -> int: return 1\n"
        "class Model:\n"
        "    value = Descriptor()\n"
        "    def __getattr__(self, name: str) -> str: return name\n"
        "model = Model()\n"
        "descriptor_value = model.value\n"
        "dynamic_value = model.missing\n"
    )

    assert _raw_types(result.type_of("sample.descriptor_value")) == {int}
    assert _raw_types(result.type_of("sample.dynamic_value")) == {str}


def test_module_getattr_and_star_imports_resolve_exports(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .impl import *\n" "def __getattr__(name: str) -> int:\n" "    return 1\n",
        encoding="utf-8",
    )
    (package / "impl.py").write_text(
        "__all__ = ['Client']\nclass Client:\n    value: int = 1\nclass Hidden:\n    pass\n",
        encoding="utf-8",
    )
    (package / "use.py").write_text(
        "import pkg\n"
        "from pkg import Client\n"
        "client = Client()\n"
        "client_value = client.value\n"
        "hidden = Hidden()\n"
        "dynamic = pkg.anything\n",
        encoding="utf-8",
    )

    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("pkg.use")

    assert _instance_name(service.type_of("pkg.use", "client")) == "pkg.impl.Client"
    assert _raw_types(service.type_of("pkg.use", "client_value")) == {int}
    assert service.type_of("pkg.use", "hidden") is None
    assert _raw_types(service.type_of("pkg.use", "dynamic")) == {int}


def test_generic_protocol_members_are_checked_with_concrete_arguments() -> None:
    result = _infer(
        "from typing import Protocol, TypeVar\n"
        "T = TypeVar('T')\n"
        "class Provider(Protocol[T]):\n"
        "    def get(self) -> T: ...\n"
        "class IntegerProvider:\n"
        "    def get(self) -> int: return 1\n"
        "def consume(provider: Provider[int]) -> None: ...\n"
        "consume(IntegerProvider())\n"
    )

    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_conditional_attribute_write_does_not_replace_the_other_branch() -> None:
    result = _infer(
        "class Config:\n"
        "    value = 0\n"
        "config = Config()\n"
        "def read(flag: bool):\n"
        "    if flag:\n"
        "        config.value = 'changed'\n"
        "    return config.value\n"
    )

    assert _raw_types(result.functions["sample.read"].return_type) == {int, str}


def test_hasattr_and_type_guards_narrow_union_alternatives() -> None:
    result = _infer(
        "class HasValue:\n"
        "    value: int = 1\n"
        "class MissingValue:\n"
        "    pass\n"
        "def by_hasattr(item: HasValue | MissingValue):\n"
        "    if hasattr(item, 'value'):\n"
        "        return item.value\n"
        "    return 0\n"
        "def by_type(item: int | str):\n"
        "    if type(item) is int:\n"
        "        return item + 1\n"
        "    return item.upper()\n"
    )

    assert _raw_types(result.functions["sample.by_hasattr"].return_type) == {int}
    assert _raw_types(result.functions["sample.by_type"].return_type) == {int, str}


def test_lazy_collection_depth_limit_stops_runaway_recursion(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    for index in range(5):
        next_import = f"from .m{index + 1} import value{index + 1}\n" if index < 4 else ""
        (package / f"m{index}.py").write_text(
            next_import + f"value{index} = {index}\n", encoding="utf-8"
        )

    service = TypeInfoService(ProjectContext(tmp_path))
    service._max_collection_depth = 2
    service.collect_module("pkg.m0")

    assert any(
        diagnostic.code == "type_collection_depth_exceeded" for diagnostic in service.diagnostics()
    )


def test_singledispatch_registered_overloads_are_used_for_calls() -> None:
    result = _infer(
        "from functools import singledispatch\n"
        "@singledispatch\n"
        "def convert(value) -> str: return 'default'\n"
        "@convert.register\n"
        "def _(value: int) -> int: return 1\n"
        "integer = convert(1)\n"
        "text = convert('value')\n"
    )

    assert _raw_types(result.type_of("sample.integer")) == {int}
    assert _raw_types(result.type_of("sample.text")) == {str}


def test_functional_namedtuple_creates_a_nominal_class() -> None:
    result = _infer(
        "from collections import namedtuple\n"
        "Point = namedtuple('Point', ('x', 'y'))\n"
        "point = Point(1, 2)\n"
        "fields = Point._fields\n"
    )

    assert _instance_name(result.type_of("sample.point")) == "sample.Point"
    assert str(result.type_of("sample.fields")) == "tuple[str, ...]"


def test_functional_typeddict_creates_field_information() -> None:
    result = _infer(
        "from typing import TypedDict\n"
        "Record = TypedDict('Record', {'name': str, 'count': int})\n"
        "record: Record = {'name': 'value', 'count': 1}\n"
        "name = record['name']\n"
        "count = record['count']\n"
    )

    assert _instance_name(result.type_of("sample.record")) == "sample.Record"
    assert _raw_types(result.type_of("sample.name")) == {str}
    assert _raw_types(result.type_of("sample.count")) == {int}


def test_project_engine_resolves_inherited_members_across_modules(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "base.py").write_text(
        "class Base:\n    value: int = 1\n    def get(self) -> str: return 'x'\n",
        encoding="utf-8",
    )
    (package / "derived.py").write_text(
        "from .base import Base\nclass Derived(Base): pass\n", encoding="utf-8"
    )
    (package / "use.py").write_text(
        "from .derived import Derived\n"
        "obj = Derived()\n"
        "value = obj.value\n"
        "text = obj.get()\n",
        encoding="utf-8",
    )

    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["pkg.use"])
    module = result.module("pkg.use")
    assert module is not None
    assert _raw_types(module.type_of("value")) == {int}
    assert _raw_types(module.type_of("text")) == {str}


def test_project_engine_resolves_super_calls_across_modules(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "base.py").write_text(
        "class Base:\n    def value(self): return 1\n", encoding="utf-8"
    )
    (package / "derived.py").write_text(
        "from .base import Base\n"
        "class Derived(Base):\n"
        "    def value(self): return super().value() + 1\n",
        encoding="utf-8",
    )
    (package / "use.py").write_text(
        "from .derived import Derived\nresult = Derived().value()\n", encoding="utf-8"
    )

    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["pkg.use"])
    module = result.module("pkg.use")
    assert module is not None
    assert _raw_types(module.type_of("result")) == {int}


def test_paramspec_decorator_preserves_the_wrapped_return_type() -> None:
    result = _infer(
        "from typing import Callable, ParamSpec, TypeVar\n"
        "P = ParamSpec('P')\n"
        "R = TypeVar('R')\n"
        "def deco(func: Callable[P, R]) -> Callable[P, R]: return func\n"
        "@deco\n"
        "def identity(value: int) -> str: return str(value)\n"
        "result = identity(1)\n"
    )

    assert _raw_types(result.type_of("sample.result")) == {str}


def test_functional_enum_creates_nominal_members() -> None:
    result = _infer(
        "import enum\n"
        "Color = enum.Enum('Color', 'RED BLUE')\n"
        "member = Color.RED\n"
        "name = member.name\n"
        "value = member.value\n"
    )

    assert _instance_name(result.type_of("sample.member")) == "sample.Color"
    assert _raw_types(result.type_of("sample.name")) == {str}
    assert _raw_types(result.type_of("sample.value")) == {int}


def test_synthetic_builtin_tuple_does_not_hit_the_nominal_tuple_assertion() -> None:
    engine = StaticTypeInferenceEngine()
    value = engine._synthetic_instance("builtins.tuple", unresolved=True)
    assert isinstance(value, TupleType)
