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
