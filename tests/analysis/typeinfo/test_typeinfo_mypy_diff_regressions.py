"""Regressions found by the mypy differential corpus harness.

Each test pins a gap where PyFlow disagreed with mypy on real corpus code:
receiver binding for classmethods, missing builtin/stdlib member signatures,
generic substitution into stub members, and protocol-driven overload binding.
"""

from __future__ import annotations

from pathlib import Path

from pyflow.analysis.typeinfo import (
    ProjectTypeInferenceEngine,
    StaticTypeInferenceEngine,
)
from pyflow.analysis.typeinfo.core.typesystem import CallableType, Instance
from pyflow.language.modules.project_resolution import ProjectContext


def infer(source: str):
    return StaticTypeInferenceEngine().infer_source("m", source)


def test_stdlib_classmethod_is_bound_on_class_and_instance() -> None:
    result = infer("""
import pathlib
import datetime

class_access = pathlib.Path.cwd
instance_access = pathlib.Path(".").cwd
now = datetime.datetime.now
""")

    assert str(result.type_of("class_access")) == "Callable[[], pathlib.Path]"
    assert str(result.type_of("instance_access")) == "Callable[[], pathlib.Path]"
    assert str(result.type_of("now")) == "Callable[[None | datetime.tzinfo], datetime.datetime]"


def test_instance_method_accessed_through_class_keeps_self() -> None:
    result = infer("""
import pathlib

unbound = pathlib.Path.exists
""")

    assert str(result.type_of("unbound")) == "Callable[[Any, bool], bool]"


def test_builtin_container_methods_keep_typeshed_signatures() -> None:
    result = infer("""
values: list[int] = []
append = values.append
lookup = {"a": 1}.get
split = "a,b".split
keys = dict.fromkeys
""")

    assert str(result.type_of("append")) == "Callable[[int], None]"
    assert str(result.type_of("lookup")) == "Callable[[str, None], None | int]"
    assert str(result.type_of("split")) == "Callable[[None | str, typing.SupportsIndex], list[str]]"
    assert str(result.type_of("keys")) == "Callable[[collections.abc.Iterable[_T], None], dict]"


def test_typing_alias_subscript_uses_value_type() -> None:
    result = infer("""
from typing import Dict, List

table: Dict[str, int] = {}
values: List[int] = []
first = table["a"]
second = values[0]
""")

    assert str(result.type_of("first")) == "int"
    assert str(result.type_of("second")) == "int"


def test_protocol_overload_binds_type_variable_from_member() -> None:
    result = infer("""
import math

up = math.ceil(1.5)
down = math.floor(2)
best = max([1, 2])
""")

    assert str(result.type_of("up")) == "int"
    assert str(result.type_of("down")) == "int"
    assert str(result.type_of("best")) == "int"


def test_cross_module_classmethod_is_bound(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "core.py").write_text(
        """
class Builder:
    @classmethod
    def create(cls, size: int) -> "Builder":
        return cls()
""",
        encoding="utf-8",
    )
    (package / "use.py").write_text(
        """
from pkg.core import Builder

factory = Builder.create
""",
        encoding="utf-8",
    )

    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["pkg.use"])

    assert str(result.modules["pkg.use"].type_of("factory")) == "Callable[[int], pkg.core.Builder]"


def test_missing_dependency_is_gradual_not_partial() -> None:
    result = infer("""
from external_package import Base

def consume(value: Base) -> Base:
    return value
""")

    assert result.status == "complete"
    codes = {item.code for item in result.diagnostics}
    assert "missing-external-type" in codes
    assert "unresolved-annotation" not in codes
    assert all(
        not item.affects_completeness
        for item in result.diagnostics
        if item.code == "missing-external-type"
    )
    assert str(result.type_of("m.consume")) == "Callable[[Any], Any]"


def test_project_internal_resolution_failure_stays_partial(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "core.py").write_text("class Present:\n    pass\n", encoding="utf-8")
    (package / "use.py").write_text(
        "from pkg.core import Missing\n\ndef consume(value: Missing) -> None:\n    pass\n",
        encoding="utf-8",
    )

    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["pkg.use"])
    module = result.modules["pkg.use"]

    assert module.status == "partial"
    assert any(
        item.code == "unresolved-annotation" and item.affects_completeness
        for item in module.diagnostics
    )


def test_newtype_keeps_nominal_identity_and_accepts_base_values() -> None:
    result = infer("""
from typing import NewType

UserId = NewType("UserId", int)

def consume(value: UserId) -> int:
    return value

def build(value: int) -> UserId:
    return UserId(value)

bad = consume(1)
""")

    ident = result.type_of("m.UserId")
    assert isinstance(ident, Instance) and ident.type.full_name == "m.UserId"
    built = result.type_of("m.build")
    assert isinstance(built, CallableType)
    assert str(built.return_type) == "m.UserId"
    assert built.arg_types is not None and str(built.arg_types[0]) == "int"
    mismatches = [item.message for item in result.diagnostics if item.code == "annotation-mismatch"]
    assert any("argument value of m.consume" in message for message in mismatches)


def test_decorator_keeps_wrapped_signature() -> None:
    result = infer("""
from typing import Callable, TypeVar, ParamSpec

P = ParamSpec("P")
R = TypeVar("R")

def typed(f: Callable[P, R]) -> Callable[P, R]:
    return f

@typed
def endpoint(value: int) -> str:
    return str(value)
""")

    assert str(result.type_of("m.endpoint")) == "Callable[[int], str]"


def test_type_variable_renders_by_name_only() -> None:
    result = infer("""
from typing import Callable, TypeVar

Decorated = TypeVar("Decorated", bound=Callable[..., object])

def make(handler: Decorated) -> Decorated:
    return handler
""")

    assert str(result.type_of("m.make")) == "Callable[[Decorated], Decorated]"


def test_new_on_class_returns_instance_without_false_positive() -> None:
    result = infer("""
class Options:
    def __init__(self) -> None:
        self.width = 1

def copy() -> Options:
    options: Options = Options.__new__(Options)
    return options
""")

    assert str(result.type_of("m.copy")) == "Callable[[], m.Options]"
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_inherited_member_uses_base_type_arguments() -> None:
    from pyflow.analysis.typeinfo import TypeInfoService

    service = TypeInfoService()
    service.collect_module(
        "sample",
        source="from collections import OrderedDict\nclass M(OrderedDict[str, int]):\n    pass\n",
        path="/tmp/sample.py",
    )

    keys = service.members_of("sample.M")["keys"].typ
    assert keys is not None
    rendered = str(keys)
    assert "_KT" not in rendered and "_VT" not in rendered
    assert "str" in rendered and "int" in rendered


def _site_packages(tmp_path: Path) -> Path:
    site = tmp_path / "site-packages"
    site.mkdir()
    return site


def test_pep561_typed_package_reexport_resolves(tmp_path: Path) -> None:
    from pyflow.analysis.typeinfo import TypeInfoService

    site = _site_packages(tmp_path)
    package = site / "typedpkg"
    package.mkdir()
    (package / "py.typed").write_text("", encoding="utf-8")
    (package / "core.py").write_text(
        "class Widget:\n    def render(self) -> str:\n        return 'x'\n",
        encoding="utf-8",
    )
    (package / "__init__.py").write_text(
        "from typing import TYPE_CHECKING\n" "if TYPE_CHECKING:\n" "    from .core import *\n",
        encoding="utf-8",
    )

    service = TypeInfoService(project_context=ProjectContext(tmp_path, sys_path=[str(site)]))

    widget = service.type_of("typedpkg", "Widget")
    assert isinstance(widget, Instance)
    assert widget.type.full_name == "typedpkg.core.Widget"


def test_untyped_installed_package_is_not_analysed(tmp_path: Path) -> None:
    from pyflow.analysis.typeinfo import TypeInfoService

    site = _site_packages(tmp_path)
    package = site / "untypedpkg"
    package.mkdir()
    (package / "__init__.py").write_text("class Thing:\n    pass\n", encoding="utf-8")

    service = TypeInfoService(project_context=ProjectContext(tmp_path, sys_path=[str(site)]))

    assert service.type_of("untypedpkg", "Thing") is None
    assert not [d for d in service.diagnostics() if d.code == "type_dependency_partial"]


def _infer_checked(source: str):
    from pyflow.analysis.typeinfo.inference.engine import InferenceOptions

    return StaticTypeInferenceEngine(
        options=InferenceOptions(check_member_access=True)
    ).infer_source("m", source)


def test_member_access_checks_match_mypy_codes() -> None:
    result = _infer_checked("""
class C:
    def __init__(self) -> None:
        self.value = 1

def use(c: C, maybe: int | None) -> None:
    missing = c.absent
    on_none = maybe.absent
    if maybe is not None:
        fine = maybe.bit_length()
""")

    codes = [item.code for item in result.diagnostics]
    assert "attr-defined" in codes
    assert "union-attr" in codes
    assert len([item for item in result.diagnostics if item.code == "union-attr"]) == 1
    # The narrowed branch must not be reported.
    assert not [item for item in result.diagnostics if "bit_length" in item.message]
    assert result.status == "complete"


def test_member_access_checks_skip_gradual_receivers() -> None:
    result = _infer_checked("""
def use(value):
    return value.anything
""")

    assert not [item for item in result.diagnostics if item.code in {"attr-defined", "union-attr"}]


def test_subscript_index_checks_match_mypy() -> None:
    result = infer("""
def use(values: list[int], table: dict[str, int]) -> None:
    first = values[0]
    by_name = table["key"]
    wrong_list = values["x"]
    wrong_dict = table[1]
    sliced = values[0:2]
""")

    messages = [item.message for item in result.diagnostics if item.code == "index"]
    assert any("list[int]" in message for message in messages)
    assert any("dict[str, int]" in message for message in messages)
    assert len(messages) == 2


def test_dotted_base_does_not_resolve_to_same_named_local_class(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "a.py").write_text(
        "class Request:\n    def method(self) -> str:\n        return 'GET'\n",
        encoding="utf-8",
    )
    (package / "b.py").write_text(
        "from pkg.a import Request as RequestBase\n"
        "class Request(RequestBase):\n    pass\n"
        "def use(request: Request) -> str:\n    return request.method()\n",
        encoding="utf-8",
    )

    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["pkg.b"])
    module = result.modules["pkg.b"]

    # The dotted base used to fall back to the local ``Request`` alias, making
    # the class inherit from itself and hiding every inherited member.
    assert not [item for item in module.diagnostics if item.code == "attr-defined"]
    assert str(module.functions["pkg.b.use"].return_type) == "str"


def test_diagnostic_policy_can_disable_and_override_severity() -> None:
    from pyflow.analysis.typeinfo.inference.engine import InferenceOptions

    source = "def use(values: list[int]) -> None:\n    x = values['bad']\n"

    default = StaticTypeInferenceEngine().infer_source("m", source)
    assert [item for item in default.diagnostics if item.code == "index"]

    disabled = StaticTypeInferenceEngine(
        options=InferenceOptions(disabled_diagnostics=frozenset({"index"}))
    ).infer_source("m", source)
    assert not [item for item in disabled.diagnostics if item.code == "index"]

    promoted = StaticTypeInferenceEngine(
        options=InferenceOptions(diagnostic_severity={"index": "error"})
    ).infer_source("m", source)
    promoted_index = [item for item in promoted.diagnostics if item.code == "index"]
    assert promoted_index and promoted_index[0].severity == "error"
    assert promoted.status == "partial"


def test_type_info_service_forwards_inference_options() -> None:
    from pyflow.analysis.typeinfo import TypeInfoService
    from pyflow.analysis.typeinfo.inference.engine import InferenceOptions

    source = "def use(values: list[int]) -> None:\n    x = values['bad']\n"
    service = TypeInfoService(
        inference_options=InferenceOptions(disabled_diagnostics=frozenset({"index"}))
    )
    service.collect_module("m", source=source, path="/tmp/m.py")

    result = service.inference_result("m")
    assert result is not None
    assert not [item for item in result.diagnostics if item.code == "index"]


def test_subscript_assignment_checks_declared_containers() -> None:
    result = infer("""
def use(values: list[int], table: dict[str, int]) -> None:
    values[0] = 1
    table["key"] = 2
    values[0] = "bad"
    table["key"] = 1.5
    inferred = {"a": 1}
    inferred["a"] = "widened"
""")

    codes = [item.code for item in result.diagnostics]
    assert codes.count("list-item") == 1
    assert codes.count("dict-item") == 1
    # Inferred containers keep the widening behaviour.
    assert not [item for item in result.diagnostics if "widened" in item.message]


def test_member_checks_trust_annotated_call_returns() -> None:
    result = infer("""
from typing import Optional

class ClassifierTags:
    multi_label: bool

class Tags:
    classifier_tags: Optional[ClassifierTags]

def get_tags() -> Tags:
    return Tags()

def use() -> None:
    tags = get_tags()
    direct = get_tags().classifier_tags.multi_label
    chained = tags.classifier_tags.multi_label
""")

    messages = [item.message for item in result.diagnostics if item.code == "union-attr"]
    assert len(messages) == 2


def test_member_checks_skip_unannotated_call_returns() -> None:
    result = infer("""
def get_value():
    return object()

def use() -> None:
    value = get_value()
    missing = value.anything
""")

    assert not [item for item in result.diagnostics if item.code in {"attr-defined", "union-attr"}]


def test_override_checks_same_module_hierarchy() -> None:
    result = infer("""
class Base:
    def run(self, value: int) -> int:
        return value
    def copy(self) -> "Base":
        return self

class Good(Base):
    def run(self, value: int) -> int:
        return value
    def copy(self) -> "Good":
        return self

class Bad(Base):
    def run(self, value: str) -> str:
        return value
""")

    messages = [item.message for item in result.diagnostics if item.code == "override"]
    assert messages == ['Signature of "run" incompatible with supertype "m.Base"']


def test_empty_dict_index_is_not_reported() -> None:
    result = infer("""
def use() -> None:
    empty = {}
    value = empty["key"]
""")

    assert not [item for item in result.diagnostics if item.code == "index"]


def test_project_configuration_disables_diagnostics(tmp_path: Path) -> None:
    from pyflow.analysis.typeinfo.inference.engine import InferenceOptions

    (tmp_path / "pyproject.toml").write_text(
        '[tool.pyflow.typeinfo]\ndisabled_diagnostics = ["index"]\n',
        encoding="utf-8",
    )
    (tmp_path / "m.py").write_text(
        "def f(values: list[int]) -> None:\n    x = values['bad']\n", encoding="utf-8"
    )

    configured = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["m"])
    assert not [d for d in configured.modules["m"].diagnostics if d.code == "index"]

    explicit = ProjectTypeInferenceEngine(
        ProjectContext(tmp_path), options=InferenceOptions()
    ).infer_project(["m"])
    assert [d for d in explicit.modules["m"].diagnostics if d.code == "index"]


def test_pyflow_toml_typeinfo_section_is_read(tmp_path: Path) -> None:
    from pyflow.analysis.typeinfo.inference.project_config import load_inference_options

    (tmp_path / "pyflow.toml").write_text(
        '[typeinfo]\ndiagnostic_severity = { override = "error" }\ncheck_overrides = false\n',
        encoding="utf-8",
    )
    options = load_inference_options(tmp_path)
    assert options.diagnostic_severity == {"override": "error"}
    assert options.check_overrides is False


def test_global_call_model_provider_plugin_hook() -> None:
    from pyflow.analysis.typeinfo.inference.call_models import (
        MappingCallModelProvider,
        register_call_model_provider,
        unregister_call_model_provider,
    )
    from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup

    provider = MappingCallModelProvider()
    provider.register_return_type("pluginlib.load", BuiltinTypeLookup()("str"))
    register_call_model_provider(provider)
    source = "import pluginlib\nx = pluginlib.load()\n"
    try:
        registered = infer(source)
        assert str(registered.type_of("m.x")) == "str"
    finally:
        unregister_call_model_provider(provider)

    # Without the plugin the external call stays unknown.
    assert infer(source).type_of("m.x") is None


def test_every_emitted_diagnostic_code_is_registered() -> None:
    import re

    import pyflow.analysis.typeinfo as typeinfo

    from pyflow.analysis.typeinfo.inference.diagnostics import DIAGNOSTICS

    root = Path(typeinfo.__file__).parent
    emitted: set[str] = set()
    for path in root.rglob("*.py"):
        for match in re.finditer(r'_add_diagnostic\(\s*"([a-z0-9-]+)"', path.read_text()):
            emitted.add(match.group(1))

    assert emitted, "expected at least one diagnostic emission"
    assert emitted <= set(DIAGNOSTICS), sorted(emitted - set(DIAGNOSTICS))


def test_member_checks_trust_declared_container_elements() -> None:
    result = infer("""
class Item:
    def present(self) -> int:
        return 1

def use(items: list[Item]) -> None:
    item = items[0]
    missing = item.absent
""")

    assert [item.code for item in result.diagnostics] == ["attr-defined"]


def test_member_checks_skip_inferred_container_elements() -> None:
    result = infer("""
def use(raw) -> None:
    item = raw[0]
    missing = item.absent
""")

    assert not [item for item in result.diagnostics if item.code == "attr-defined"]


def test_override_requires_declared_signatures() -> None:
    result = infer("""
class Base:
    def f(self, value: int) -> int:
        return value

class Sub(Base):
    def f(self, value):
        return value
""")

    # An inferred (unannotated) signature is not a contract the subclass has
    # to satisfy; mypy also does not report an override error here.
    assert not [item for item in result.diagnostics if item.code == "override"]


def test_unresolved_property_value_is_not_a_missing_member() -> None:
    result = infer("""
class C:
    @property
    def value(self):
        return unknown_factory()

def use(c: C) -> None:
    item = c.value
""")

    assert not [item for item in result.diagnostics if item.code == "attr-defined"]


def test_functional_namedtuple_fields_are_members() -> None:
    result = infer("""
from collections import namedtuple

class Pair(namedtuple("Pair", ("first", "second"))):
    pass

def use(pair: Pair) -> None:
    first = pair.first
    missing = pair.absent
""")

    messages = [item.message for item in result.diagnostics if item.code == "attr-defined"]
    assert len(messages) == 1 and "absent" in messages[0]
