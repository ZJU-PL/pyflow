from __future__ import annotations

import sysconfig
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
    TypeType,
    UnionType,
)
from pyflow.language.modules.project_resolution import ProjectContext


def _instance_name(value) -> str:
    if isinstance(value, TypeType):
        value = value.item
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


def test_service_exposes_standalone_inference_results() -> None:
    source = """
def identity(value):
    return value

answer = identity(1)
"""
    service = TypeInfoService(ProjectContext(None))
    service.collect_module("pkg.mod", source=source)

    assert _builtin_instance(service.type_of("pkg.mod", "answer"), int)
    signature = service.signature_of("pkg.mod", "identity")
    assert signature is not None
    assert _builtin_instance(signature.params["value"], int)
    assert _builtin_instance(signature.returns, int)
    result = service.inference_result("pkg.mod")
    assert result is not None and result.converged
    assert _builtin_instance(result.expression_type(5, 9), int)


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

    assert _instance_name(service.type_of("pkg.mod", "client")) == ("pkg.mod.Client")
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
    assert members["ping"].source == "annotation"
    assert members["ping"].kind == "method"
    assert isinstance(members["ping"].typ, CallableType)
    assert _builtin_instance(members["ping"].typ.return_type, bool)


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
            "class Client:\n" "    value: int\n",
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

        assert _instance_name(service.type_of("pkg.service", "client")) == ("pkg.models.Client")
        assert _instance_name(service.type_of("pkg.service", "made")) == ("pkg.models.Client")
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
            "import pkg.models as models\n\n" "client: models.Client\n" "made = models.Client()\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.service")

        assert _instance_name(service.type_of("pkg.service", "client")) == ("pkg.models.Client")
        assert _instance_name(service.type_of("pkg.service", "made")) == ("pkg.models.Client")


def test_service_resolves_relative_imports_and_package_exports() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text(
            "from .models import Client\n" "exported: Client\n",
            encoding="utf-8",
        )
        package.joinpath("models.py").write_text(
            "class Client: ...\n",
            encoding="utf-8",
        )
        package.joinpath("service.py").write_text(
            "from .models import Client\n\n" "client: Client\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.service")
        service.collect_module("pkg")

        assert _instance_name(service.type_of("pkg.service", "client")) == ("pkg.models.Client")
        assert _instance_name(service.type_of("pkg", "exported")) == ("pkg.models.Client")


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
            "from ns_pkg.models import Client\n\n" "client: Client\n",
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
            "def make(item):\n" "    return item\n",
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

        assert _instance_name(service.type_of("pkg.service", "client")) == ("pkg.models.Client")
        signature = service.signature_of("pkg.service", "make")
        assert signature is not None
        assert _instance_name(signature.params["item"]) == "pkg.models.Client"
        assert _instance_name(signature.returns) == "pkg.models.Client"
        function_type = service.type_of("pkg.service", "make")
        assert isinstance(function_type, CallableType)
        assert function_type.arg_types is not None
        assert _instance_name(function_type.arg_types[0]) == ("pkg.models.Client")
        assert _instance_name(function_type.return_type) == ("pkg.models.Client")


def test_service_prefers_module_local_class_names() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("a.py").write_text(
            "class Client: ...\n" "value: Client\n",
            encoding="utf-8",
        )
        package.joinpath("b.py").write_text(
            "class Client: ...\n" "value: Client\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.a")
        service.collect_module("pkg.b")

        assert _instance_name(service.type_of("pkg.a", "value")) == ("pkg.a.Client")
        assert _instance_name(service.type_of("pkg.b", "value")) == ("pkg.b.Client")


def test_service_resolves_reexported_import_alias_assignment() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text(
            "from pkg.impl import Client\n\n" "PublicClient = Client\n",
            encoding="utf-8",
        )
        package.joinpath("impl.py").write_text(
            "class Client: ...\n",
            encoding="utf-8",
        )
        package.joinpath("service.py").write_text(
            "import pkg\n\n" "client: pkg.PublicClient\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        service.collect_module("pkg.service")

        assert _instance_name(service.type_of("pkg", "PublicClient")) == ("pkg.impl.Client")
        assert _instance_name(service.type_of("pkg.service", "client")) == ("pkg.impl.Client")


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


def test_service_prefers_vendored_typeshed_for_stdlib() -> None:
    path = Path(sysconfig.get_paths()["stdlib"]) / "argparse.py"
    if not path.is_file():
        return

    service = TypeInfoService(ProjectContext(None))
    source, loaded_path = service._load_module_source("argparse", str(path))

    assert source is not None
    assert loaded_path is not None and loaded_path.endswith(".pyi")
    assert "__all__" in source


def test_service_reads_python_source_encoding_cookie() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "latin_module.py"
        path.write_bytes(
            "# coding: latin-1\nvalue = 'caf\N{LATIN SMALL LETTER E WITH ACUTE}'\n".encode(
                "latin-1"
            )
        )
        service = TypeInfoService(ProjectContext(tmp))

        service.collect_module("latin_module", path=str(path))

        assert _builtin_instance(service.type_of("latin_module", "value"), str)


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


def test_service_collection_diagnostics_and_import_refresh_scale_linearly() -> None:
    import time
    from pyflow.analysis.typeinfo.core.typesystem import ANY
    from pyflow.language.modules.type_stubs import StubDiagnostic

    service = TypeInfoService(ProjectContext(None), enable_static_inference=True)
    # Pre-populate thousands of collection diagnostics and verify O(1) dedup
    for idx in range(3000):
        service._add_collection_diagnostic(
            StubDiagnostic(
                code="type_dependency_partial",
                category="type_inference",
                module_name=f"dep_{idx}",
                message=f"Type information for dependency 'dep_{idx}' is partial",
                severity="warning",
            )
        )
    service._failed_modules.add("broken_dep")
    service._collected_modules.add("broken_dep")
    service._collection_stack.append("caller_mod")

    start = time.monotonic()
    for _ in range(5000):
        service._lookup_project_type(
            "broken_dep.missing_symbol",
            allow_synthetic=False,
            collect_missing=False,
        )
    elapsed = time.monotonic() - start
    service._collection_stack.pop()
    assert elapsed < 1.0, f"Expected O(1) diagnostic dedup, took {elapsed:.2f}s"
    assert len(service._collection_diagnostics) == 3001

    # Verify _summary_type caches CallableType by summary identity
    service.collect_module("util", source="def helper(x: int) -> str:\n    return str(x)\n")
    first = service._summary_type("util.helper")
    second = service._summary_type("util.helper")
    assert first is not None and first is second

    # Verify _refresh_import_facts memoizes shared import targets across modules
    for idx in range(200):
        mod = f"consumer_{idx}"
        service._collected_modules.add(mod)
        service._module_facts[mod] = {
            "helper": TypeFact(
                name="helper",
                typ=ANY,
                raw_annotation="util.helper",
                source="import",
                kind="import",
            )
        }
    assert service._refresh_import_facts() is True
    assert service._module_facts["consumer_0"]["helper"].typ is first
    assert service._module_facts["consumer_199"]["helper"].typ is first


def test_typeinfo_service_bounds_transitive_inference_and_preserves_unrelated_caches(
    tmp_path: Path,
):
    """Wave 1 perf guards: skip absent attrs, bound transitive inference, keep unaffected caches."""
    (tmp_path / "dep.py").write_text(
        "def present(x: int) -> int:\n    return x\n\nclass Box:\n    value = 1\n",
        encoding="utf-8",
    )
    (tmp_path / "entry.py").write_text(
        "import dep\n\ndef run() -> int:\n    return dep.present(1)\n",
        encoding="utf-8",
    )
    service = TypeInfoService(ProjectContext(tmp_path), enable_static_inference=True)
    service.collect_module("dep", path=str(tmp_path / "dep.py"))
    # Simulate deferred dependency status as during nested collection
    service._deferred_inference_modules.add("dep")
    service._inference_results.pop("dep", None)

    calls: list[str] = []
    original_ensure_inferred = service._ensure_inferred

    def tracked_ensure_inferred(module_name: str, *, transitive: bool = False) -> None:
        calls.append(module_name)
        original_ensure_inferred(module_name, transitive=transitive)

    service._ensure_inferred = tracked_ensure_inferred  # type: ignore[method-assign]
    assert (
        service._lookup_project_type(
            "dep.does_not_exist",
            allow_synthetic=False,
            collect_missing=True,
        )
        is None
    )
    assert calls == []

    # Targeted cache invalidation preserves unaffected non-None external symbols
    service._external_symbol_cache["other.Symbol"] = Instance(
        service.type_system.to_class_descriptor(int)
    )
    service._external_symbol_cache["dep.Box"] = Instance(
        service.type_system.to_class_descriptor(str)
    )
    service._external_symbol_cache["missing.Item"] = None
    service._invalidate_external_symbol_cache("dep")
    assert "other.Symbol" in service._external_symbol_cache
    assert "dep.Box" not in service._external_symbol_cache
    assert "missing.Item" not in service._external_symbol_cache

    # Transitive deferred inference obeys depth and module-count caps
    for idx in range(25):
        mod_name = f"fan_{idx}"
        src = f"def f_{idx}():\n    return {idx}\n"
        (tmp_path / f"{mod_name}.py").write_text(src, encoding="utf-8")
        service._module_sources[mod_name] = (src, str(tmp_path / f"{mod_name}.py"))
        service._deferred_inference_modules.add(mod_name)
    service._collecting_modules.add("entry")
    service._collection_stack.append("entry")
    try:
        service._transitive_inferred_count = 0
        for idx in range(25):
            service._ensure_inferred(f"fan_{idx}", transitive=True)
        assert service._transitive_inferred_count == service._max_transitive_inferred_modules
    finally:
        service._collection_stack.clear()
        service._collecting_modules.clear()

    # PEP 695 TypeAlias works even with enable_static_inference=False
    no_infer_service = TypeInfoService(ProjectContext(tmp_path), enable_static_inference=False)
    no_infer_service.collect_module(
        "aliases",
        source="class A:\n    pass\nclass B:\n    pass\ntype Pair = A | B\nx: Pair\n",
    )
    x_fact = no_infer_service.fact_of("aliases", "x")
    assert x_fact is not None and x_fact.typ is not None
    assert "aliases.A" in str(x_fact.typ) and "aliases.B" in str(x_fact.typ)


def test_call_inference_caches_return_dependencies():
    import ast as _ast
    from pyflow.analysis.typeinfo.inference._engine.state import _FunctionInfo
    from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine

    engine = StaticTypeInferenceEngine(ProjectContext(None))
    node = _ast.parse("def identity(x):\n    return x\n").body[0]
    fn_info = _FunctionInfo(
        qualified_name="mod.identity",
        node=node,
        parameter_names=["x"],
    )
    first = engine._call_rules._return_dependencies(fn_info)
    second = engine._call_rules._return_dependencies(fn_info)
    assert first == frozenset({"x"})
    assert first is second


def test_project_context_dir_entries_cache_invalidates_on_new_file(tmp_path: Path) -> None:
    ctx = ProjectContext(tmp_path)
    assert ctx.find_module("later_mod") is None
    (tmp_path / "later_mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    resolved = ctx.find_module("later_mod")
    assert resolved is not None
    assert resolved.module_name == "later_mod"


def test_service_caches_nested_lookup_and_bounds_refresh_passes(tmp_path: Path) -> None:
    (tmp_path / "dep.py").write_text("class Box:\n    x: int = 1\n", encoding="utf-8")
    (tmp_path / "consumer.py").write_text(
        "from dep import Box\n" "def make() -> Box:\n" "    return Box()\n",
        encoding="utf-8",
    )
    (tmp_path / "unrelated.py").write_text(
        "def id_fn(v: int) -> int:\n    return v\n", encoding="utf-8"
    )

    service = TypeInfoService(ProjectContext(tmp_path))
    service._active_project_lookups.add("consumer.make")
    try:
        looked = service._lookup_project_type(
            "dep.Box",
            allow_synthetic=False,
            collect_missing=True,
        )
        assert looked is not None
        assert ("dep.Box", False, True) in service._external_project_type_cache
    finally:
        service._active_project_lookups.clear()

    service.collect_module("consumer")
    service.collect_module("unrelated")
    epoch_before = service._facts_epoch
    # Collecting an unrelated leaf module must not trigger re-inference of consumer.
    re_runs: list[str] = []
    original = service._collect_inferred_source_facts

    def spy_collect(mod_name: str, src: str, path: str | None, *, options=None):
        re_runs.append(mod_name)
        return original(mod_name, src, path, options=options)

    service._collect_inferred_source_facts = spy_collect  # type: ignore[method-assign]
    service._refresh_stale_annotation_checks()
    assert re_runs == []
    assert service._facts_epoch == epoch_before
