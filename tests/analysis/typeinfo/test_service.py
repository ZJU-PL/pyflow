from __future__ import annotations

import tempfile
from pathlib import Path

from pyflow.analysis import typeinfo
from pyflow.analysis.typeinfo import (
    ClassTypeInfo,
    FunctionTypeInfo,
    TypeFact,
    TypeInfoService,
)
from pyflow.analysis.typeinfo.core.typesystem import (
    CallableType,
    Instance,
    NoneType,
    UnionType,
)
from pyflow.language.modules.project_resolution import ProjectContext


def _instance_name(value) -> str:
    assert isinstance(value, Instance)
    return value.type.full_name


def _builtin_instance(value, raw_type: type) -> bool:
    return isinstance(value, Instance) and value.type.raw_type is raw_type


def test_service_collects_source_annotations_and_literals() -> None:
    source = """
x: int
y = "value"
z = None

def make(name: str) -> int:
    return 1
"""
    service = TypeInfoService(ProjectContext(None))
    service.collect_module("pkg.mod", source=source)

    assert _builtin_instance(service.type_of("pkg.mod", "x"), int)
    assert _builtin_instance(service.type_of("pkg.mod", "y"), str)
    assert isinstance(service.type_of("pkg.mod", "z"), NoneType)
    fact = service.fact_of("pkg.mod", "x")
    assert fact is not None
    assert fact.raw_annotation == "int"

    signature = service.signature_of("pkg.mod", "make")
    assert signature is not None
    function_type = service.type_of("pkg.mod", "make")
    assert isinstance(function_type, CallableType)
    assert function_type.arg_types is not None
    assert _builtin_instance(function_type.arg_types[0], str)
    assert _builtin_instance(function_type.return_type, int)
    assert _builtin_instance(signature.params["name"], str)
    assert _builtin_instance(signature.returns, int)
    assert signature.raw_params == {"name": "str"}
    assert signature.raw_returns == "int"
    assert signature.source == "annotation"


def test_service_infers_local_constructor_assignment() -> None:
    source = """
class Client:
    attr: int

def make() -> Client:
    return Client()

client = Client()
"""
    service = TypeInfoService(ProjectContext(None))
    service.collect_module("pkg.mod", source=source)

    assert _instance_name(service.type_of("pkg.mod", "client")) == (
        "pkg.mod.Client"
    )
    members = service.members_of("pkg.mod.Client")
    assert members["attr"] == TypeFact(
        name="attr",
        typ=members["attr"].typ,
        raw_annotation="int",
        source="annotation",
        kind="class_var",
    )
    assert _builtin_instance(members["attr"].typ, int)
    assert "make" not in members


def test_service_collects_source_class_methods_as_members() -> None:
    source = """
class Client:
    value: str

    def ping(self, timeout: int) -> bool:
        return True
"""
    service = TypeInfoService(ProjectContext(None))
    service.collect_module("pkg.mod", source=source)

    members = service.members_of("pkg.mod.Client")
    assert _builtin_instance(members["value"].typ, str)
    assert members["ping"] == TypeFact(
        name="ping",
        typ=members["ping"].typ,
        raw_annotation="bool",
        source="annotation",
        kind="method",
    )
    assert _builtin_instance(members["ping"].typ, bool)


def test_service_resolves_composite_types() -> None:
    source = """
from typing import Callable

class Client:
    pass

items: list[int]
maybe: Client | None
callback: Callable[[int], str]
"""
    service = TypeInfoService(ProjectContext(None))
    service.collect_module("pkg.mod", source=source)

    items = service.type_of("pkg.mod", "items")
    assert isinstance(items, Instance)
    assert items.type.raw_type is list
    assert _builtin_instance(items.args[0], int)

    maybe = service.type_of("pkg.mod", "maybe")
    assert isinstance(maybe, UnionType)
    assert {str(item) for item in maybe.items} == {"None", "pkg.mod.Client"}

    callback = service.type_of("pkg.mod", "callback")
    assert isinstance(callback, CallableType)
    assert callback.arg_types is not None
    assert _builtin_instance(callback.arg_types[0], int)
    assert _builtin_instance(callback.return_type, str)


def test_service_resolves_project_imported_annotations() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("models.py").write_text(
            "class Client:\n"
            "    value: int\n",
            encoding="utf-8",
        )
        package.joinpath("service.py").write_text(
            "from pkg.models import Client\n\n"
            "client: Client\n"
            "made = Client()\n\n"
            "def make(item: Client) -> Client:\n"
            "    return item\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.service")

        assert _instance_name(service.type_of("pkg.service", "client")) == (
            "pkg.models.Client"
        )
        assert _instance_name(service.type_of("pkg.service", "made")) == (
            "pkg.models.Client"
        )
        signature = service.signature_of("pkg.service", "make")
        assert signature is not None
        assert _instance_name(signature.params["item"]) == "pkg.models.Client"
        assert _instance_name(signature.returns) == "pkg.models.Client"
        assert _builtin_instance(
            service.members_of("pkg.models.Client")["value"].typ,
            int,
        )


def test_service_resolves_imported_module_alias_annotations() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("models.py").write_text(
            "class Client: ...\n",
            encoding="utf-8",
        )
        package.joinpath("service.py").write_text(
            "import pkg.models as models\n\n"
            "client: models.Client\n"
            "made = models.Client()\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.service")

        assert _instance_name(service.type_of("pkg.service", "client")) == (
            "pkg.models.Client"
        )
        assert _instance_name(service.type_of("pkg.service", "made")) == (
            "pkg.models.Client"
        )


def test_service_resolves_relative_imports_and_package_exports() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text(
            "from .models import Client\n"
            "exported: Client\n",
            encoding="utf-8",
        )
        package.joinpath("models.py").write_text(
            "class Client: ...\n",
            encoding="utf-8",
        )
        package.joinpath("service.py").write_text(
            "from .models import Client\n\n"
            "client: Client\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.service")
        service.collect_module("pkg")

        assert _instance_name(service.type_of("pkg.service", "client")) == (
            "pkg.models.Client"
        )
        assert _instance_name(service.type_of("pkg", "exported")) == (
            "pkg.models.Client"
        )


def test_service_resolves_namespace_package_imports() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        namespace = root / "ns_pkg"
        namespace.mkdir()
        namespace.joinpath("models.py").write_text(
            "class Client: ...\n",
            encoding="utf-8",
        )
        namespace.joinpath("service.py").write_text(
            "from ns_pkg.models import Client\n\n"
            "client: Client\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("ns_pkg.service")

        assert _instance_name(service.type_of("ns_pkg.service", "client")) == (
            "ns_pkg.models.Client"
        )


def test_service_resolves_imported_stub_annotations() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("models.py").write_text(
            "class Client: ...\n",
            encoding="utf-8",
        )
        package.joinpath("service.py").write_text(
            "def make(item):\n"
            "    return item\n",
            encoding="utf-8",
        )
        package.joinpath("service.pyi").write_text(
            "from .models import Client\n\n"
            "client: Client\n"
            "def make(item: Client) -> Client: ...\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.service")

        assert _instance_name(service.type_of("pkg.service", "client")) == (
            "pkg.models.Client"
        )
        signature = service.signature_of("pkg.service", "make")
        assert signature is not None
        assert _instance_name(signature.params["item"]) == "pkg.models.Client"
        assert _instance_name(signature.returns) == "pkg.models.Client"
        function_type = service.type_of("pkg.service", "make")
        assert isinstance(function_type, CallableType)
        assert function_type.arg_types is not None
        assert _instance_name(function_type.arg_types[0]) == (
            "pkg.models.Client"
        )
        assert _instance_name(function_type.return_type) == (
            "pkg.models.Client"
        )


def test_service_prefers_module_local_class_names() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("a.py").write_text(
            "class Client: ...\n"
            "value: Client\n",
            encoding="utf-8",
        )
        package.joinpath("b.py").write_text(
            "class Client: ...\n"
            "value: Client\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.a")
        service.collect_module("pkg.b")

        assert _instance_name(service.type_of("pkg.a", "value")) == (
            "pkg.a.Client"
        )
        assert _instance_name(service.type_of("pkg.b", "value")) == (
            "pkg.b.Client"
        )


def test_service_resolves_reexported_import_alias_assignment() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text(
            "from pkg.impl import Client\n\n"
            "PublicClient = Client\n",
            encoding="utf-8",
        )
        package.joinpath("impl.py").write_text(
            "class Client: ...\n",
            encoding="utf-8",
        )
        package.joinpath("service.py").write_text(
            "import pkg\n\n"
            "client: pkg.PublicClient\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.service")

        assert _instance_name(service.type_of("pkg", "PublicClient")) == (
            "pkg.impl.Client"
        )
        assert _instance_name(service.type_of("pkg.service", "client")) == (
            "pkg.impl.Client"
        )


def test_service_stub_overrides_source_signature() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.joinpath("lib.py").write_text(
            "def make(name):\n    return name\n",
            encoding="utf-8",
        )
        root.joinpath("lib.pyi").write_text(
            "def make(name: str, *, retries: int) -> Client: ...\n"
            "class Client:\n"
            "    def ping(self) -> str: ...\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("lib")

        signature = service.signature_of("lib", "make")
        assert signature is not None
        assert signature.source == "stub"
        assert _builtin_instance(signature.params["name"], str)
        assert _builtin_instance(signature.params["retries"], int)
        assert _instance_name(signature.returns) == "lib.Client"
        assert signature.raw_params == {"name": "str", "retries": "int"}
        assert signature.raw_returns == "Client"
        assert service.members_of("lib.Client")["ping"].source == "stub"


def test_service_collects_typeshed_root_stub() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        stub = root / "stubs" / "vendor"
        stub.mkdir(parents=True)
        stub.joinpath("__init__.pyi").write_text(
            "value: int\ndef f(x: int) -> str: ...\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(None), typeshed_roots=[root])

        service.collect_module("vendor")

        assert _builtin_instance(service.type_of("vendor", "value"), int)
        signature = service.signature_of("vendor", "f")
        assert signature is not None
        assert signature.name == "f"
        assert _builtin_instance(signature.params["x"], int)
        assert _builtin_instance(signature.returns, str)
        assert signature.raw_params == {"x": "int"}
        assert signature.raw_returns == "str"
        assert signature.source == "stub"


def test_service_returns_none_for_missing_symbol() -> None:
    service = TypeInfoService(ProjectContext(None))
    service.collect_module("pkg.mod", source="")

    assert service.type_of("pkg.mod", "missing") is None
    assert service.signature_of("pkg.mod", "missing") is None


def test_service_exposes_stub_diagnostics() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.joinpath("bad.py").write_text("", encoding="utf-8")
        root.joinpath("bad.pyi").write_text(
            "def broken(: ...\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("bad")

        diagnostics = service.diagnostics()
        assert diagnostics
        assert diagnostics[0].code == "stub_parse_failed"


def test_typeinfo_package_exports_service_api() -> None:
    assert typeinfo.TypeInfoService is TypeInfoService
    assert typeinfo.TypeFact is TypeFact
    assert typeinfo.FunctionTypeInfo is FunctionTypeInfo
    assert typeinfo.ClassTypeInfo is ClassTypeInfo
