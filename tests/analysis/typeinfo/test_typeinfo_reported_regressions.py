"""Regressions for user-facing typeinfo issues found on real projects."""

from __future__ import annotations

from pathlib import Path

from pyflow.analysis.typeinfo import (
    InferenceOptions,
    ProjectTypeInferenceEngine,
    StaticTypeInferenceEngine,
    TypeInfoService,
)
from pyflow.api.queries.type_info import TypeInfoQueries
from pyflow.language.modules.project_resolution import ProjectContext


def infer(source: str, *, strict: bool = False):
    return StaticTypeInferenceEngine(
        options=InferenceOptions(strict_annotations=strict)
    ).infer_source("m", source)


def raw_types(typ) -> set[type]:
    from pyflow.analysis.typeinfo.core.typesystem import Instance, NoneType

    if isinstance(typ, Instance):
        return {typ.type.raw_type}
    if isinstance(typ, NoneType):
        return {type(None)}
    return {
        type(None) if isinstance(item, NoneType) else item.type.raw_type
        for item in getattr(typ, "items", ())
        if isinstance(item, Instance) or isinstance(item, NoneType)
    }


def test_unresolved_external_parameter_keeps_annotation_alternatives(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import requests\n"
        "\n"
        "def f(x: requests.Response | None = None) -> None:\n"
        "    if x is not None:\n"
        "        y = x\n",
        encoding="utf-8",
    )
    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["a"])
    parameter = result.modules["a"].functions["a.f"].parameters["x"]
    assert parameter.public_type() is not None
    assert any(
        isinstance(
            item,
            __import__(
                "pyflow.analysis.typeinfo.core.typesystem", fromlist=["UnionType"]
            ).UnionType,
        )
        for item in parameter.types
    ) or raw_types(parameter.public_type()) == {None, requests.Response}


def test_any_arithmetic_stays_any() -> None:
    result = infer(
        "from typing import Any\n"
        "def f(x: Any) -> str:\n"
        "    return x + 1\n"
        "def g(x: Any) -> Any:\n"
        "    return x * 2\n",
        strict=True,
    )
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]
    for span, value in result.expressions.items():
        if span.lineno == 3 and span.col_offset == 11:
            assert str(value.runtime_type()) == "Any"


def test_min_max_default_is_used_and_does_not_terminate_module_analysis() -> None:
    result = infer(
        "x = max([], default=0)\n"
        "y = 1\n"
        "items: list[int] = []\n"
        "z = max(items, default=None)\n"
    )
    assert raw_types(result.type_of("x")) == {int}
    assert raw_types(result.type_of("y")) == {int}
    assert raw_types(result.type_of("z")) == {int, type(None)}


def test_builtin_keyword_arguments_are_modelled() -> None:
    result = infer(
        "a = round(1.55, ndigits=1)\n"
        "b = sum([1, 2], start=0.0)\n"
        "c = dict.fromkeys(['a'], value=1)\n"
        "d = max([], default='x')\n"
    )
    assert raw_types(result.type_of("a")) == {float}
    assert raw_types(result.type_of("b")) == {float}
    typ = result.type_of("c")
    assert str(typ) == "dict[str, int]"
    assert raw_types(result.type_of("d")) == {str}


def test_container_method_models_preserve_types() -> None:
    result = infer(
        "from collections import Counter, OrderedDict, defaultdict\n"
        "d: dict[str, int] = {'a': 1}\n"
        "a = d.copy()\n"
        "b = dict(d)\n"
        "l: list[int] = [1]\n"
        "c = l.sort()\n"
        "e = l.reverse()\n"
        "fs: frozenset[int] = frozenset({1})\n"
        "f = fs.copy()\n"
        "g = fs.union({2})\n"
        "counter: Counter[str] = Counter()\n"
        "h = counter.copy()\n"
        "ordered: OrderedDict[str, int] = OrderedDict()\n"
        "i = ordered.copy()\n"
    )
    assert str(result.type_of("a")) == "dict[str, int]"
    assert str(result.type_of("b")) == "dict[str, int]"
    assert raw_types(result.type_of("c")) == {type(None)}
    assert raw_types(result.type_of("e")) == {type(None)}
    assert str(result.type_of("f")) == "frozenset[int]"
    assert str(result.type_of("g")) == "frozenset[int]"
    assert "Counter[str]" in str(result.type_of("h"))
    assert "OrderedDict[str, int]" in str(result.type_of("i"))


def test_defaultdict_list_annotation_is_accepted() -> None:
    result = infer(
        "from collections import defaultdict\n"
        "a: defaultdict[str, list[int]] = defaultdict(list)\n"
        "b: defaultdict[str, list[int]] = defaultdict(lambda: [])\n",
        strict=True,
    )
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_any_str_is_a_constrained_typevar() -> None:
    result = infer(
        "import typing as t\n" "def f(x: t.AnyStr) -> t.AnyStr:\n" "    return x\n" "y = f('a')\n",
        strict=True,
    )
    assert raw_types(result.type_of("y")) == {str}
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_literal_display_and_optional_assignment_compatibility() -> None:
    result = infer(
        "from typing import Literal, Optional\n"
        "A = Literal['a', 'b']\n"
        "def f(x: Optional[A] = None):\n"
        "    y: Optional[A] = x\n",
        strict=True,
    )
    assert str(result.type_of("A")) == "Literal['a'] | Literal['b']"
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_literal_container_and_typed_dict_values_are_checked() -> None:
    result = infer(
        "from typing import Literal, TypedDict\n"
        "def f(xs: list[Literal['a']]) -> None: ...\n"
        "f(['a'])\n"
        "f(['b'])\n"
        "class T(TypedDict):\n"
        "    kind: Literal['a']\n"
        "good: T = {'kind': 'a'}\n"
        "bad: T = {'kind': 'b'}\n",
        strict=True,
    )
    mismatches = [item for item in result.diagnostics if item.code == "annotation-mismatch"]
    assert len(mismatches) == 2
    assert {item.span.lineno for item in mismatches} == {4, 8}


def test_literal_overloads_select_by_call_literal() -> None:
    result = infer(
        "from typing import Literal, overload\n"
        "@overload\n"
        "def g(x: Literal['a']) -> int: ...\n"
        "@overload\n"
        "def g(x: Literal['b']) -> str: ...\n"
        "def g(x): ...\n"
        "a = g('a')\n"
        "b = g('b')\n"
    )
    assert raw_types(result.type_of("a")) == {int}
    assert raw_types(result.type_of("b")) == {str}


def test_walrus_target_is_narrowed_in_true_branch() -> None:
    result = infer(
        "def takes_int(x: int) -> None: ...\n"
        "def f(x: int | None) -> None:\n"
        "    if (y := x) is not None:\n"
        "        takes_int(y)\n",
        strict=True,
    )
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_match_or_patterns_intersect_with_subject_type() -> None:
    result = infer(
        "def takes_str(x: str) -> None: ...\n"
        "def f(v: int | str) -> None:\n"
        "    match v:\n"
        "        case str() | bytes():\n"
        "            takes_str(v)\n",
        strict=True,
    )
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_starred_assignment_and_match_rest_targets() -> None:
    result = infer(
        "a, *rest = [1, 2, 3]\n"
        "*init, last = 'abc'\n"
        "def f(rows: list[tuple[int, str, str]]) -> None:\n"
        "    for first, *tail in rows:\n"
        "        p = first\n"
        "        q = tail\n"
        "def g(v: list[int]) -> None:\n"
        "    match v:\n"
        "        case [first, *rest]:\n"
        "            x = first\n"
        "            y = rest\n"
    )
    assert raw_types(result.type_of("rest")) == {list}
    assert str(result.type_of("rest")) == "list[int]"
    assert str(result.type_of("init")) == "list[str]"
    assert raw_types(result.type_of("last")) == {str}
    for span, value in result.expressions.items():
        if span.lineno == 6 and span.col_offset == 12:
            assert str(value.runtime_type()) == "list[str]"
        if span.lineno == 11 and span.col_offset == 16:
            assert str(value.runtime_type()) == "list[int]"


def test_nested_class_access_and_instantiation() -> None:
    result = infer(
        "class Outer:\n"
        "    class Inner:\n"
        "        value: int = 1\n"
        "i = Outer.Inner()\n"
        "x = i.value\n"
        "klass = Outer.Inner\n"
    )
    assert str(result.type_of("i")) == "m.Outer.Inner"
    assert raw_types(result.type_of("x")) == {int}
    assert str(result.type_of("klass")) == "type[m.Outer.Inner]"


def test_path_division_and_classmethods() -> None:
    result = infer(
        "from pathlib import Path\n"
        "a = Path('a') / 'b'\n"
        "b = Path.home()\n"
        "c = Path.cwd() / 'x'\n"
    )
    for name in ("a", "b", "c"):
        assert "pathlib" in str(result.type_of(name))


def test_expression_query_records_targets_and_prefers_identifier_at_start() -> None:
    result = infer(
        "x = 'hello'\n"
        "y = x.upper()\n"
        "class A:\n"
        "    value: int = 1\n"
        "a = A()\n"
        "z = a.value + 1\n"
        "def f(v: int) -> str:\n"
        "    return str(v)\n"
    )
    assert raw_types(result.expression_type(1, 0)) == {str}
    assert raw_types(result.expression_type(2, 0)) == {str}
    assert str(result.expression_type(4, 4)) == "int"
    assert str(result.expression_type(6, 4)) == "m.A"
    assert str(result.expression_type(6, 6)) == "int"


def test_type_ignore_on_return_suppresses_return_mismatch() -> None:
    result = infer(
        "def f() -> int:\n"
        "    return 'x'  # type: ignore\n"
        "def g() -> int:\n"
        "    return 'x'\n",
        strict=True,
    )
    mismatches = [item for item in result.diagnostics if item.code == "annotation-mismatch"]
    assert len(mismatches) == 1
    assert "m.g" in mismatches[0].message


def test_project_engine_isolates_encoding_and_recursion_failures(tmp_path: Path) -> None:
    root = tmp_path / "latin"
    root.mkdir()
    (root / "a.py").write_bytes(b"# -*- coding: latin-1 -*-\nx = '\xe9'\n")
    first = ProjectTypeInferenceEngine(ProjectContext(root)).infer_project(["a"])
    assert raw_types(first.modules["a"].type_of("x")) == {str}

    deep_root = tmp_path / "deep"
    deep_root.mkdir()
    (deep_root / "a.py").write_text("x = " + " + ".join(["1"] * 1500) + "\n", encoding="utf-8")
    second = ProjectTypeInferenceEngine(ProjectContext(deep_root)).infer_project(["a"])
    assert any(item.code == "module-inference-error" for item in second.diagnostics)


def test_stub_package_reexports_and_star_imports_are_visible(tmp_path: Path) -> None:
    package = tmp_path / "lib"
    package.mkdir()
    (package / "__init__.pyi").write_text("from .models import Widget\n", encoding="utf-8")
    (package / "models.pyi").write_text(
        "class Widget:\n" "    name: str\n" "    def render(self, width: int) -> bytes: ...\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from lib import Widget\n" "w = Widget()\n" "name = w.name\n" "rendered = w.render(1)\n",
        encoding="utf-8",
    )
    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("app")
    assert raw_types(service.type_of("app", "name")) == {str}
    assert raw_types(service.type_of("app", "rendered")) == {bytes}

    star = tmp_path / "star"
    star.mkdir()
    (star / "__init__.pyi").write_text("from .models import *\n", encoding="utf-8")
    (star / "models.pyi").write_text("class Thing:\n    value: int\n", encoding="utf-8")
    (tmp_path / "star_app.py").write_text(
        "from star import Thing\nthing = Thing()\nvalue = thing.value\n",
        encoding="utf-8",
    )
    service.collect_module("star_app")
    assert raw_types(service.type_of("star_app", "value")) == {int}


def test_typeshed_third_party_layout_and_generic_stub_methods(tmp_path: Path) -> None:
    typeshed = tmp_path / "typeshed"
    distribution = typeshed / "stubs" / "vendor" / "vendor"
    distribution.mkdir(parents=True)
    (distribution / "__init__.pyi").write_text(
        "class Widget:\n    name: str\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from vendor import Widget\nw = Widget()\nname = w.name\n",
        encoding="utf-8",
    )
    service = TypeInfoService(ProjectContext(tmp_path), typeshed_roots=[typeshed])
    service.collect_module("app")
    assert raw_types(service.type_of("app", "name")) == {str}

    generic = tmp_path / "generic"
    generic.mkdir()
    (tmp_path / "genlib.pyi").write_text(
        "from typing import Generic, TypeVar\n"
        "T = TypeVar('T')\n"
        "class Box(Generic[T]):\n"
        "    def get(self) -> T: ...\n",
        encoding="utf-8",
    )
    (tmp_path / "gen_app.py").write_text(
        "from genlib import Box\nb: Box[int] = Box()\nx = b.get()\n",
        encoding="utf-8",
    )
    service.collect_module("gen_app")
    assert raw_types(service.type_of("gen_app", "x")) == {int}


def test_type_info_queries_can_filter_diagnostics_by_module(tmp_path: Path) -> None:
    service = TypeInfoService(ProjectContext(tmp_path))
    source = "import nowhere_xyz\ndef f(x: nowhere_xyz.Thing | None = None): ...\n"
    service.collect_module("first", source=source, path=str(tmp_path / "first.py"))
    service.collect_module("second", source=source, path=str(tmp_path / "second.py"))
    queries = TypeInfoQueries(service)
    filtered = queries.get_diagnostics("first")
    assert filtered
    assert {item.module_name for item in filtered} == {"first"}


def test_builtin_class_objects_satisfy_callable_annotations() -> None:
    result = infer(
        "from typing import Callable\n"
        "a: Callable[[int], str] = str\n"
        "b: Callable[[], list[int]] = list\n"
        "def take(cb: Callable[[int], str]) -> None: ...\n"
        "take(str)\n",
        strict=True,
    )
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]
