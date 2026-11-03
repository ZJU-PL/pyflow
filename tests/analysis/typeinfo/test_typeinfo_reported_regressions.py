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


def test_typed_dict_key_specific_methods_preserve_the_declaration() -> None:
    result = infer(
        "from typing import TypedDict, NotRequired\n"
        "class Movie(TypedDict):\n"
        "    title: str\n"
        "    year: NotRequired[int]\n"
        "m: Movie = {'title': 'x'}\n"
        "a = m.get('title')\n"
        "b = m.get('year')\n"
        "c = m.setdefault('year', 0)\n"
        "d = m.pop('year', 0)\n"
        "e = m.copy()\n"
        "m.update({'year': 1})\n"
        "f = m\n",
        strict=True,
    )
    assert raw_types(result.type_of("a")) == {str}
    assert raw_types(result.type_of("b")) == {int, type(None)}
    assert raw_types(result.type_of("c")) == {int}
    assert raw_types(result.type_of("d")) == {int}
    assert str(result.type_of("e")) == "m.Movie"
    assert str(result.type_of("f")) == "m.Movie"
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_dataclass_pseudo_fields_are_not_instance_members() -> None:
    result = infer(
        "from dataclasses import dataclass, InitVar, KW_ONLY, field\n"
        "@dataclass\n"
        "class Child:\n"
        "    value: int\n"
        "    extra: InitVar[str] = 'x'\n"
        "    _: KW_ONLY\n"
        "    items: list[int] = field(default_factory=list)\n"
        "child = Child(1)\n"
        "items = child.items\n"
    )
    assert result.status == "complete"
    assert result.type_of("m.Child.extra") is None
    assert raw_types(result.type_of("items")) == {list}


def test_namedtuple_and_enum_helper_members() -> None:
    result = infer(
        "from enum import Enum\n"
        "from typing import NamedTuple\n"
        "class Point(NamedTuple):\n"
        "    x: int\n"
        "    y: str = 'a'\n"
        "p = Point(1)\n"
        "field_names = Point._fields\n"
        "defaults = p._field_defaults\n"
        "replaced = p._replace(x=2)\n"
        "mapping = p._asdict()\n"
        "class Color(Enum):\n"
        "    RED = 1\n"
        "    BLUE = 2\n"
        "red = Color['RED']\n"
        "members = Color.__members__\n"
    )
    assert "tuple[str, ...]" == str(result.type_of("field_names"))
    assert str(result.type_of("defaults")) == "dict[str, Any]"
    assert str(result.type_of("replaced")) == "m.Point"
    assert str(result.type_of("mapping")) == "dict[str, Any]"
    assert str(result.type_of("red")) == "m.Color"
    assert str(result.type_of("members")) == "dict[str, m.Color]"


def test_datetime_regex_pathlib_and_os_path_helpers() -> None:
    result = infer(
        "import os, re\n"
        "from datetime import date, datetime\n"
        "from pathlib import Path\n"
        "b = b'abc'\n"
        "hexed = b.hex()\n"
        "now = datetime.now()\n"
        "current_time = now.time()\n"
        "zone = now.tzinfo\n"
        "parsed = datetime.strptime('2020', '%Y')\n"
        "today = date.fromisoformat('2020-01-01')\n"
        "pattern = re.compile('a')\n"
        "match = pattern.match('abc')\n"
        "found = re.findall('a', 'abc')\n"
        "p = Path('x')\n"
        "info = p.stat()\n"
        "owner = p.owner()\n"
        "exists = os.path.exists('x')\n"
        "stem, ext = os.path.splitext('x.txt')\n"
    )
    assert raw_types(result.type_of("hexed")) == {str}
    assert str(result.type_of("current_time")) == "datetime.time"
    assert "datetime.tzinfo" in str(result.type_of("zone"))
    assert str(result.type_of("parsed")) == "datetime.datetime"
    assert str(result.type_of("today")) == "datetime.date"
    assert str(result.type_of("pattern")) == "re.Pattern[str]"
    assert "re.Match[str]" in str(result.type_of("match"))
    assert str(result.type_of("found")) == "list[str]"
    assert str(result.type_of("info")) == "os.stat_result"
    assert raw_types(result.type_of("owner")) == {str}
    assert raw_types(result.type_of("exists")) == {bool}
    assert str(result.type_of("stem")) == "str"
    assert str(result.type_of("ext")) == "str"


def test_itertools_functools_json_queue_and_contextvar_models() -> None:
    result = infer(
        "import functools, itertools, json\n"
        "from contextvars import ContextVar\n"
        "from queue import Queue\n"
        "from concurrent.futures import Future\n"
        "def f(a: int, b: str) -> bool: return True\n"
        "partial_by_keyword = functools.partial(f, b='x')\n"
        "accumulated = itertools.accumulate([1, 2])\n"
        "chained = itertools.chain.from_iterable([[1], [2]])\n"
        "tees = itertools.tee([1, 2], n=3)\n"
        "dumped = json.dumps({})\n"
        "queue: Queue[int] = Queue()\n"
        "queued = queue.get()\n"
        "var: ContextVar[int] = ContextVar('v')\n"
        "current = var.get()\n"
        "future: Future[str] = Future()\n"
        "resolved = future.result()\n"
    )
    assert str(result.type_of("partial_by_keyword")) == "Callable[[int], bool]"
    assert str(result.type_of("accumulated")) == "collections.abc.Iterator[int]"
    assert str(result.type_of("chained")) == "collections.abc.Iterator[int]"
    assert str(result.type_of("tees")).count("Iterator[int]") == 3
    assert raw_types(result.type_of("dumped")) == {str}
    assert raw_types(result.type_of("queued")) == {int}
    assert raw_types(result.type_of("current")) == {int}
    assert raw_types(result.type_of("resolved")) == {str}


def test_paramspec_forwarding_and_method_argument_ignore() -> None:
    result = infer(
        "from typing import Callable, ParamSpec\n"
        "P = ParamSpec('P')\n"
        "def forward(f: Callable[P, None], *a: P.args, **kw: P.kwargs) -> None:\n"
        "    f(*a, **kw)\n"
        "def target(x: int, y: str) -> None: ...\n"
        "forward(target, 1, 'a')\n"
        "class C:\n"
        "    value: str | None = None\n"
        "class M:\n"
        "    def take(self, x: str) -> None: ...\n"
        "    def run(self, c: C) -> None:\n"
        "        self.take(\n"
        "            c.value,  # type: ignore[arg-type]\n"
        "        )\n",
        strict=True,
    )
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_abstract_container_methods_work_without_stubs() -> None:
    result = infer(
        "from collections.abc import Mapping, Sequence, MutableSequence\n"
        "m: Mapping[str, int] = {}\n"
        "a = m.get('x')\n"
        "b = m['x']\n"
        "s: Sequence[int] = []\n"
        "c = s[0]\n"
        "ms: MutableSequence[int] = []\n"
        "d = ms.pop()\n"
        "ms.append(1)\n"
    )
    assert raw_types(result.type_of("a")) == {int, type(None)}
    assert raw_types(result.type_of("b")) == {int}
    assert raw_types(result.type_of("c")) == {int}
    assert raw_types(result.type_of("d")) == {int}


def test_enum_literal_overloads_and_assignments() -> None:
    result = infer(
        "from enum import Enum\n"
        "from typing import Literal, overload\n"
        "class E(Enum):\n"
        "    A = 1\n"
        "    B = 2\n"
        "@overload\n"
        "def f(x: Literal[E.A]) -> int: ...\n"
        "@overload\n"
        "def f(x: Literal[E.B]) -> str: ...\n"
        "def f(x): ...\n"
        "a = f(E.A)\n"
        "b = f(E.B)\n"
        "good: Literal[E.A] = E.A\n"
        "bad: Literal[E.A] = E.B\n",
        strict=True,
    )
    assert raw_types(result.type_of("a")) == {int}
    assert raw_types(result.type_of("b")) == {str}
    mismatches = [item for item in result.diagnostics if item.code == "annotation-mismatch"]
    assert len(mismatches) == 1
    assert "Literal[E.A]" in mismatches[0].message


def test_loop_break_assignments_reach_the_loop_exit() -> None:
    result = infer(
        "def f(xs: list[int]) -> None:\n"
        "    found = None\n"
        "    for index, value in enumerate(xs):\n"
        "        if value == 1:\n"
        "            found = index\n"
        "            break\n"
        "    if found is not None:\n"
        "        print(found)\n"
    )
    value = result.value_of("m.f")
    assert value is not None
    span = next(span for span in result.expressions if span.lineno == 8 and span.col_offset == 14)
    assert str(result.expressions[span].runtime_type()) == "int"


def test_threading_lock_and_event_models() -> None:
    result = infer(
        "import threading\n"
        "lock = threading.Lock()\n"
        "with lock:\n"
        "    pass\n"
        "event = threading.Event()\n"
        "waiting = event.wait()\n"
        "thread = threading.Thread()\n"
        "name = thread.name\n"
        "alive = thread.is_alive()\n"
    )
    assert str(result.type_of("waiting")) == "bool"
    assert str(result.type_of("name")) == "str"
    assert str(result.type_of("alive")) == "bool"
    assert result.status == "complete"
    assert not [item for item in result.diagnostics if "context manager" in item.message]


def test_continue_and_try_break_environments_are_joined() -> None:
    result = infer(
        "def f(xs: list[int]) -> None:\n"
        "    found = None\n"
        "    for value in xs:\n"
        "        try:\n"
        "            if value == 1:\n"
        "                found = value\n"
        "                continue\n"
        "        except Exception:\n"
        "            pass\n"
        "    for value in xs:\n"
        "        try:\n"
        "            if value == 2:\n"
        "                found = value\n"
        "                break\n"
        "        finally:\n"
        "            pass\n"
        "    if found is not None:\n"
        "        print(found)\n"
    )
    span = next(span for span in result.expressions if span.lineno == 18 and span.col_offset == 14)
    assert raw_types(result.expressions[span].runtime_type()) == {int}


def test_asyncio_and_contextlib_models() -> None:
    result = infer(
        "import asyncio\n"
        "from contextlib import closing, nullcontext\n"
        "async def value() -> int: return 1\n"
        "async def main():\n"
        "    got = await value()\n"
        "    task = asyncio.create_task(value())\n"
        "    task_value = await task\n"
        "    waited = await asyncio.wait_for(value(), 1)\n"
        "    lock = asyncio.Lock()\n"
        "    async with lock:\n"
        "        pass\n"
        "    event = asyncio.Event()\n"
        "    ready = await event.wait()\n"
        "    return got, task_value, waited, ready\n"
        "with closing(open('x')) as handle:\n"
        "    text = handle.read()\n"
        "with nullcontext(1) as number:\n"
        "    pass\n"
        "ran = asyncio.run(value())\n"
    )
    main_return = result.functions["m.main"].return_value.public_type()
    assert str(main_return) == "tuple[int, int, int, bool]"
    assert raw_types(result.type_of("text")) == {str}
    assert raw_types(result.type_of("number")) == {int}
    assert raw_types(result.type_of("ran")) == {int}
    assert result.status == "complete"
    assert not [item for item in result.diagnostics if "context manager" in item.message]


def test_subprocess_shutil_logging_and_tempfile_models() -> None:
    result = infer(
        "import logging, shutil, subprocess, tempfile\n"
        "completed = subprocess.run(['ls'], capture_output=True)\n"
        "stdout = completed.stdout\n"
        "return_code = completed.returncode\n"
        "text_stdout = subprocess.run(['ls'], text=True).stdout\n"
        "output = subprocess.check_output(['ls'])\n"
        "call_code = subprocess.call(['ls'])\n"
        "which = shutil.which('ls')\n"
        "copied = shutil.copy('a', 'b')\n"
        "usage = shutil.disk_usage('.')\n"
        "logger = logging.getLogger('x')\n"
        "logger_name = logger.name\n"
        "logger_level = logger.level\n"
        "logger.info('x')\n"
        "directory = tempfile.mkdtemp()\n"
        "handle, path = tempfile.mkstemp()\n"
        "with tempfile.NamedTemporaryFile() as temporary:\n"
        "    temporary_name = temporary.name\n"
        "    temporary_data = temporary.read()\n"
        "with tempfile.TemporaryDirectory() as temporary_dir:\n"
        "    pass\n"
    )
    assert str(result.type_of("completed")) == "subprocess.CompletedProcess[bytes]"
    assert str(result.type_of("stdout")) == "None | bytes"
    assert raw_types(result.type_of("return_code")) == {int}
    assert str(result.type_of("text_stdout")) == "None | str"
    assert raw_types(result.type_of("output")) == {bytes}
    assert raw_types(result.type_of("call_code")) == {int}
    assert str(result.type_of("which")) == "None | str"
    assert raw_types(result.type_of("copied")) == {str}
    assert str(result.type_of("usage")) == "tuple[int, int, int]"
    assert raw_types(result.type_of("logger_name")) == {str}
    assert raw_types(result.type_of("logger_level")) == {int}
    assert raw_types(result.type_of("directory")) == {str}
    assert raw_types(result.type_of("path")) == {str}
    assert raw_types(result.type_of("temporary_name")) == {str}
    assert raw_types(result.type_of("temporary_data")) == {bytes}


def test_any_calls_members_and_subscripts_stay_any() -> None:
    result = infer(
        "from typing import Any\n"
        "def f(x: Any) -> None:\n"
        "    called = x()\n"
        "    member = x.foo\n"
        "    indexed = x[0]\n"
    )
    for line, column in ((3, 13), (4, 13), (5, 14)):
        span = next(
            span for span in result.expressions if span.lineno == line and span.col_offset == column
        )
        assert str(result.expressions[span].runtime_type()) == "Any"
