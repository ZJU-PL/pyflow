"""Runtime and semantic regressions from the second editor field report."""

import ast
from pathlib import Path
import sys

import pytest

from pyflow.lsp.document_analysis import document_diagnostics, infer_document
from pyflow.lsp.workspace import SourceIndex, SymbolKind


def indexed(tmp_path, source, filename="app.py"):
    path = tmp_path / filename
    return SourceIndex({str(path): source}, (tmp_path,)), path


def mismatches(source):
    return [
        d
        for d in infer_document("/tmp/semantic_probe.py", "probe", source).diagnostics
        if d.code == "annotation-mismatch"
    ]


@pytest.mark.parametrize(
    "module,annotation,value",
    [
        ("typing", "Iterable[str]", "['a', 'b']"),
        ("collections.abc", "Iterable[int]", "{1, 2}"),
        ("typing", "Sequence[int]", "(1, 2)"),
        ("typing", "Collection[int]", "[1, 2]"),
        ("typing", "Mapping[str, int]", "{'a': 1}"),
        ("collections.abc", "Mapping[str, object]", "{'a': 1}"),
        ("typing", "Iterable[str]", "{'a': 1}"),
    ],
)
def test_builtin_collections_satisfy_standard_abstract_annotations(module, annotation, value):
    name = annotation.split("[")[0]
    assert not mismatches(
        f"from {module} import {name}\ndef f() -> {annotation}:\n    return {value}\n"
    )


@pytest.mark.parametrize(
    "annotation,value",
    [
        ("Iterable[str]", "[1]"),
        ("Mapping[str, int]", "{'a': 'wrong'}"),
        ("Sequence[str]", "(1, 2)"),
        ("Mapping[str, int]", "{1: 2}"),
    ],
)
def test_collection_element_mismatches_are_still_reported(annotation, value):
    name = annotation.split("[")[0]
    assert mismatches(f"from typing import {name}\ndef f() -> {annotation}:\n    return {value}\n")


@pytest.mark.parametrize(
    "annotation,asynchronous",
    [
        ("Iterator[int]", False),
        ("Iterable[int]", False),
        ("Generator[int, None, str]", False),
        ("AsyncIterator[int]", True),
        ("AsyncGenerator[int, None]", True),
    ],
)
def test_generator_annotations_check_yields_not_terminal_none(annotation, asynchronous):
    name = annotation.split("[")[0]
    prefix = "async " if asynchronous else ""
    ending = "    return 'done'\n" if name == "Generator" else "    return\n"
    source = (
        f"from typing import {name}\n{prefix}def values() -> {annotation}:\n    yield 1\n    yield 2\n"
        + ending
    )
    assert not mismatches(source)
    bad = source.replace("yield 2", "yield 'wrong'")
    assert any("yield of" in diagnostic.message for diagnostic in mismatches(bad))


def test_generator_return_channel_and_missing_normal_returns_are_checked():
    assert mismatches(
        "from typing import Generator\ndef g() -> Generator[int, None, str]:\n    yield 1\n    return 3\n"
    )
    assert mismatches("def f(flag) -> int:\n    if flag:\n        return 1\n")


@pytest.mark.parametrize(
    "body",
    [
        "if value is not None:\n        return value\n    return 0",
        "if value is None:\n        return 0\n    return value",
        "if None is value:\n        return 0\n    return value",
        "if not isinstance(value, int):\n        return 0\n    return value",
    ],
)
def test_union_narrowing_survives_early_returns(body):
    assert not mismatches("def parse(value: int | None) -> int:\n    " + body + "\n")


@pytest.mark.parametrize("guard", ["self.value is None", "not self.value"])
def test_attribute_narrowing_and_assignment_are_local_to_control_flow(guard):
    source = f"class C:\n    value: str | None\n    def read(self) -> str:\n        if {guard}:\n            self.value = 'default'\n        return self.value\n"
    assert not mismatches(source)
    assert mismatches(
        "class C:\n    value: str | None\n    def read(self) -> str:\n        if self.value is not None:\n            self.value = None\n            return self.value\n        return ''\n"
    )


def test_internal_precision_notes_are_not_editor_diagnostics(tmp_path):
    source = "def f(items, manager):\n    with manager:\n        return items[:, 1:4], [*items]\n"
    index, path = indexed(tmp_path, source)
    assert any(d.affects_completeness for d in infer_document(str(path), "app", source).diagnostics)
    diagnostics = document_diagnostics(index, path.as_uri())
    assert not any(
        d["code"]
        in {"unsupported-expression", "unmodeled-context-manager", "unsupported-statement"}
        for d in diagnostics
    )


def test_unrelated_unresolved_members_do_not_veto_a_known_rename(tmp_path):
    source = "class MyResource:\n    def close(self): pass\ndef use():\n    resource = MyResource()\n    resource.close()\ndef other(unknown):\n    unknown.close()\n"
    index, path = indexed(tmp_path, source)
    assert {location.start_line for location in index.rename_ranges_at(path.as_uri(), 1, 10)} == {
        1,
        4,
    }
    assert index.definitions_at(path.as_uri(), 6, 14) == []


@pytest.mark.parametrize("call", ["configure(timeout=60)", "alias(timeout=60)"])
def test_keyword_arguments_are_parameter_references(tmp_path, call):
    source = (
        "def configure(timeout: int = 30):\n    return timeout\nalias = configure\n" + call + "\n"
    )
    index, path = indexed(tmp_path, source)
    column = call.index("timeout") + 2
    assert index.definitions_at(path.as_uri(), 3, column)[0].start_line == 0
    locations = index.rename_ranges_at(path.as_uri(), 0, 18)
    assert {location.start_line for location in locations} == {0, 1, 3}


def test_imported_and_bound_keyword_calls_exclude_unrelated_parameters(tmp_path):
    provider, consumer = tmp_path / "api.py", tmp_path / "client.py"
    index = SourceIndex(
        {
            str(
                provider
            ): "class Client:\n    def configure(self, timeout=30): return timeout\ndef configure(timeout=30): return timeout\n",
            str(
                consumer
            ): "from api import Client, configure as config\nclient = Client()\nclient.configure(timeout=60)\nconfig(timeout=40)\n",
        },
        (tmp_path,),
    )
    assert index.definitions_at(consumer.as_uri(), 2, 21)[0].start_line == 1
    assert index.definitions_at(consumer.as_uri(), 3, 10)[0].start_line == 2
    assert {
        location.start_line
        for location in index.references_at(provider.as_uri(), 1, 28, include_declaration=True)
        if location.uri == consumer.as_uri()
    } == {2}


def test_kwargs_and_positional_only_labels_do_not_bind_as_parameters(tmp_path):
    source = "def f(pos, /, **options): return pos\nf(pos=1, options=2)\n"
    index, path = indexed(tmp_path, source)
    assert index.definitions_at(path.as_uri(), 1, 3) == []
    assert index.definitions_at(path.as_uri(), 1, 11) == []
    assert not any(
        item["code"] == "undefined-name" for item in document_diagnostics(index, path.as_uri())
    )


def test_rename_updates_literal_all_exports(tmp_path):
    source = (
        "__all__ = ['MyClass']\n__all__ += ['helper']\nclass MyClass: pass\ndef helper(): pass\n"
    )
    index, path = indexed(tmp_path, source)
    assert {r.start_line for r in index.rename_ranges_at(path.as_uri(), 2, 8)} == {0, 2}
    assert {r.start_line for r in index.rename_ranges_at(path.as_uri(), 3, 7)} == {1, 3}
    assert {
        r.start_line for r in index.references_at(path.as_uri(), 2, 8, include_declaration=True)
    } == {0, 2}


def test_property_reads_and_writes_use_distinct_accessors(tmp_path):
    source = "class Box:\n    @property\n    def val(self):\n        '''Get value.'''\n        return 1\n    @val.setter\n    def val(self, new_val):\n        '''Set value.'''\n        pass\nb = Box()\nprint(b.val)\nb.val = 2\n"
    index, path = indexed(tmp_path, source)
    assert index.definitions_at(path.as_uri(), 10, 9)[0].start_line == 2
    assert "Get value." in index.hover_at(path.as_uri(), 10, 9)["contents"]["value"]
    assert index.definitions_at(path.as_uri(), 11, 3)[0].start_line == 6
    assert {r.start_line for r in index.rename_ranges_at(path.as_uri(), 2, 9)} >= {2, 5, 6, 10, 11}


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 syntax needs Python 3.12")
@pytest.mark.parametrize(
    "source,line,column,count",
    [
        ("def f[T](value: T) -> T:\n    return value\n", 0, 16, 3),
        ("class C[T]:\n    field: T\n", 1, 11, 2),
        ("type Alias[T] = list[T]\n", 0, 21, 2),
    ],
)
def test_pep695_type_parameter_definitions_references_and_rename(
    tmp_path, source, line, column, count
):
    index, path = indexed(tmp_path, source)
    symbol = index.symbol_at(path.as_uri(), line, column)
    assert symbol is not None and symbol.symbol_id.kind is SymbolKind.TYPE_PARAMETER
    assert len(index.rename_ranges_at(path.as_uri(), line, column)) == count
    assert not any(
        item["code"] == "undefined-name" for item in document_diagnostics(index, path.as_uri())
    )


def test_intermediate_module_navigation_uses_package_files(tmp_path):
    package = tmp_path / "pkg"
    subpackage = package / "subpkg"
    subpackage.mkdir(parents=True)
    root_init, sub_init, module = (
        package / "__init__.py",
        subpackage / "__init__.py",
        subpackage / "module.py",
    )
    consumer = tmp_path / "main.py"
    sources = {
        str(root_init): "",
        str(sub_init): "",
        str(module): "def run(): pass\n",
        str(consumer): "import pkg.subpkg.module\npkg.subpkg.module.run()\n",
    }
    root_init.write_text("")
    sub_init.write_text("")
    index = SourceIndex(sources, (tmp_path,))
    assert index.definitions_at(consumer.as_uri(), 1, 7)[0].uri == sub_init.as_uri()
    assert index.definitions_at(consumer.as_uri(), 1, 15)[0].uri == module.as_uri()
    assert index.definitions_at(consumer.as_uri(), 0, 13)[0].uri == sub_init.as_uri()


def test_outline_is_nested_and_includes_fields_and_constants(tmp_path):
    source = "MAX_RETRIES = 5\ntimeout: int = 10\nclass Client:\n    count: int = 0\n    def run(self):\n        local = 1\n        return local\n"
    index, path = indexed(tmp_path, source)
    nodes = index.document_symbol_tree(path.as_uri())
    assert [(node["name"], node["kind"]) for node in nodes] == [
        ("MAX_RETRIES", 14),
        ("timeout", 13),
        ("Client", 5),
    ]
    assert [(node["name"], node["kind"]) for node in nodes[-1]["children"]] == [
        ("count", 8),
        ("run", 6),
    ]
    assert "local" not in str(nodes)


def test_workspace_search_excludes_transient_bindings_and_ranks_declarations(tmp_path):
    source = "app = 1\nclass Application:\n    def run(self):\n        app_local = 2\n        return app_local\ndef application(): pass\n"
    index, _ = indexed(tmp_path, source)
    matches = index.workspace_symbols("app")
    names = [symbol.name for symbol in matches]
    assert "app_local" not in names and "self" not in names
    variable = next(
        index
        for index, symbol in enumerate(matches)
        if symbol.name == "app" and symbol.symbol_id.kind is SymbolKind.VARIABLE
    )
    assert names.index("Application") < variable
    assert names.index("application") < variable


@pytest.mark.parametrize(
    "expression,annotation",
    [("items[:2]", "list[int]"), ("items[1:]", "list[int]"), ("[*items]", "list[int]")],
)
def test_standard_slice_and_unpack_expressions_keep_container_types(expression, annotation):
    assert not mismatches(f"def f(items: list[int]) -> {annotation}:\n    return {expression}\n")


def test_slice_assignment_does_not_nest_the_replacement_list():
    assert not mismatches(
        "def f(items: list[int]) -> list[int]:\n    items[:] = [1, 2]\n    return items\n"
    )


def test_finally_and_non_falling_through_loops_do_not_add_none_returns():
    assert not mismatches(
        "def f() -> int:\n    try:\n        return 1\n    finally:\n        cleanup()\n"
    )
    assert not mismatches(
        "def f(flag) -> int:\n    while True:\n        if flag:\n            return 1\n"
    )
    assert mismatches(
        "def f() -> int:\n    try:\n        return 1\n    finally:\n        return 'wrong'\n"
    )


def test_unknown_external_hierarchy_is_uncertain_not_an_incompatibility():
    source = (
        "from external import Base, Derived\ndef f(value: Derived) -> Base:\n    return value\n"
    )
    result = infer_document("/tmp/external_hierarchy.py", "probe", source)
    assert not any(d.code == "annotation-mismatch" for d in result.diagnostics)
    assert any(
        d.code == "unresolved-annotation" and d.affects_completeness for d in result.diagnostics
    )


def test_resolved_external_hierarchy_still_rejects_incompatible_types():
    from pyflow.analysis.typeinfo import StaticTypeInferenceEngine, InferenceOptions
    from pyflow.analysis.typeinfo.core.typesystem import ClassDescriptor, Instance

    base = type("Base", (), {"__module__": "external"})
    unrelated = type("Other", (), {"__module__": "external"})
    facts = {
        "external.Base": Instance(ClassDescriptor(base)),
        "external.Other": Instance(ClassDescriptor(unrelated)),
    }
    engine = StaticTypeInferenceEngine(
        external_symbol_resolver=facts.get, options=InferenceOptions(strict_annotations=True)
    )
    result = engine.infer_source(
        "probe", "from external import Base, Other\ndef f() -> Base:\n    return Other()\n"
    )
    assert any(d.code == "annotation-mismatch" for d in result.diagnostics)


def test_property_getter_type_is_not_overwritten_by_setter():
    source = "class B:\n    @property\n    def val(self) -> int: return 1\n    @val.setter\n    def val(self, new_val): pass\nclass Child(B): pass\ndef f() -> int: return Child().val\n"
    assert not mismatches(source)
    assert mismatches(source.replace("def f() -> int", "def f() -> str"))


def test_src_layout_and_pytest_fixtures_link_method_references(tmp_path):
    package = tmp_path / "src" / "demo"
    tests = tmp_path / "tests"
    package.mkdir(parents=True)
    tests.mkdir()
    init = package / "__init__.py"
    init.write_text("from .app import Client\n")
    app, fixtures, consumer = package / "app.py", tests / "conftest.py", tests / "test_client.py"
    sources = {
        str(init): init.read_text(),
        str(app): "class Client:\n    def run(self): pass\n",
        str(
            fixtures
        ): "import pytest\nfrom demo import Client\n@pytest.fixture\ndef client():\n    return Client()\n",
        str(consumer): "def test_client(client):\n    client.run()\n",
    }
    index = SourceIndex(sources, (tmp_path,))
    target = index.definitions_at(consumer.as_uri(), 1, 13)
    assert target and target[0].uri == app.as_uri()
    assert index.module_for_uri(app.as_uri()) == "demo.app"
    assert {location.uri for location in index.rename_ranges_at(app.as_uri(), 1, 10)} == {
        app.as_uri(),
        consumer.as_uri(),
    }


def test_fixture_scope_does_not_infer_unrelated_normal_function_parameters(tmp_path):
    fixtures, normal = tmp_path / "conftest.py", tmp_path / "app.py"
    index = SourceIndex(
        {
            str(
                fixtures
            ): "import pytest\nclass Client:\n    def close(self): pass\n@pytest.fixture\ndef client(): return Client()\n",
            str(normal): "def helper(client):\n    client.close()\n",
        },
        (tmp_path,),
    )
    assert index.definitions_at(normal.as_uri(), 1, 14) == []


def test_known_return_annotation_overrides_nullable_factory_storage(tmp_path):
    source = "class Client:\n    def close(self): pass\n_cache = None\ndef get_client() -> Client:\n    global _cache\n    if _cache is None:\n        _cache = Client()\n    return _cache\nclient = get_client()\nclient.close()\n"
    index, path = indexed(tmp_path, source)
    assert {location.start_line for location in index.rename_ranges_at(path.as_uri(), 1, 10)} == {
        1,
        9,
    }


def test_unrelated_syntax_error_does_not_veto_rename_in_a_valid_file(tmp_path):
    good, bad = tmp_path / "good.py", tmp_path / "bad.py"
    index = SourceIndex(
        {str(good): "def run(): pass\nrun()\n", str(bad): "def broken(:\n"}, (tmp_path,)
    )
    assert {location.start_line for location in index.rename_ranges_at(good.as_uri(), 0, 6)} == {
        0,
        1,
    }


def test_impossible_guard_branches_do_not_create_annotation_errors():
    assert not mismatches(
        "def f(value: int) -> int:\n    if value is None:\n        return None\n    return value\n"
    )
    assert not mismatches(
        "def f(value: str) -> str:\n    if isinstance(value, int):\n        return 0\n    return value\n"
    )


def test_renaming_escaped_and_annotated_all_entries_preserves_valid_python(tmp_path):
    from types import SimpleNamespace
    from pyflow.lsp.lsp_handler import LspHandler

    source = "__all__: list[str] = ['M\\x79Class']\nclass MyClass: pass\n"
    index, path = indexed(tmp_path, source)
    manager = SimpleNamespace(
        is_loaded=True, current_snapshot=lambda: SimpleNamespace(source_index=index)
    )
    result = LspHandler(manager)._handle_rename(
        {
            "textDocument": {"uri": path.as_uri()},
            "position": {"line": 1, "character": 8},
            "newName": "Renamed",
        }
    )
    lines = source.splitlines(keepends=True)
    for edit in sorted(
        result["changes"][path.as_uri()],
        key=lambda edit: (edit["range"]["start"]["line"], edit["range"]["start"]["character"]),
        reverse=True,
    ):
        row = edit["range"]["start"]["line"]
        start, end = edit["range"]["start"]["character"], edit["range"]["end"]["character"]
        lines[row] = lines[row][:start] + edit["newText"] + lines[row][end:]
    tree = ast.parse("".join(lines))
    assert ast.literal_eval(tree.body[0].value) == ["Renamed"]
    assert tree.body[1].name == "Renamed"


@pytest.mark.parametrize(
    "setup,call,expected",
    [
        ("", "Box(timeout=3)", 1),
        ("obj = Box()\n", "obj(timeout=3)", 2),
        ("def factory(): return Box\nCtor = factory()\n", "Ctor(timeout=3)", 1),
        ("def factory(): return Box()\nobj = factory()\n", "obj(timeout=3)", 2),
    ],
)
def test_constructor_and_callable_instance_keyword_signatures_are_distinct(
    tmp_path, setup, call, expected
):
    source = (
        "class Box:\n    def __init__(self, timeout=1): pass\n    def __call__(self, timeout=2): return timeout\n"
        + setup
        + call
        + "\n"
    )
    index, path = indexed(tmp_path, source)
    row = len(source.splitlines()) - 1
    assert (
        index.definitions_at(path.as_uri(), row, call.index("timeout") + 2)[0].start_line
        == expected
    )


def test_constructing_an_aliased_class_creates_a_callable_instance(tmp_path):
    source = "class Box:\n    def __init__(self, timeout=1): pass\n    def __call__(self, timeout=2): return timeout\nCtor = Box\nobj = Ctor()\nobj(timeout=3)\n"
    index, path = indexed(tmp_path, source)
    assert index.definitions_at(path.as_uri(), 5, 6)[0].start_line == 2


def test_collection_views_project_their_actual_element_types():
    assert not mismatches(
        "from typing import Iterable\ndef f() -> Iterable[tuple[str, int]]:\n    return {'a': 1}.items()\n"
    )
    assert mismatches(
        "from typing import Iterable\ndef f() -> Iterable[str]:\n    return {'a': 1}.items()\n"
    )
    assert mismatches(
        "from typing import MutableSequence\ndef f() -> MutableSequence[str]:\n    return [1]\n"
    )


def test_loop_analysis_budget_notes_remain_in_api_not_editor(tmp_path):
    source = "def f():\n    value = 0\n    for _ in range(10):\n        value = [value]\n    return value\n"
    index, path = indexed(tmp_path, source)
    result = infer_document(str(path), "app", source)
    assert any(d.code == "loop-widened" for d in result.diagnostics)
    assert not any(d["code"] == "loop-widened" for d in document_diagnostics(index, path.as_uri()))


@pytest.mark.parametrize(
    "annotation,expression",
    [
        ("Console | None", "console if console is not None else Console()"),
        ("Optional[Console]", "console if console else Console()"),
    ],
)
def test_conditional_default_receivers_preserve_non_optional_identity(
    tmp_path, annotation, expression
):
    source = f"from typing import Optional\nclass Console:\n    def line(self): pass\nclass Live:\n    def __init__(self, console: {annotation} = None):\n        self.console = {expression}\n    def refresh(self):\n        self.console.line()\n"
    index, path = indexed(tmp_path, source)
    assert index.definitions_at(path.as_uri(), 7, 23)[0].start_line == 2
    assert {location.start_line for location in index.rename_ranges_at(path.as_uri(), 2, 10)} == {
        2,
        7,
    }


def test_parameter_rename_declines_ambiguous_keyword_call_targets(tmp_path):
    source = "def first(timeout): return timeout\ndef second(timeout): return timeout\ndef use(flag):\n    function = first if flag else second\n    function(timeout=60)\n"
    index, path = indexed(tmp_path, source)
    assert index.rename_ranges_at(path.as_uri(), 0, 14) == []


def test_untyped_alternate_callable_does_not_make_keyword_rename_complete(tmp_path):
    source = "def known(timeout): return timeout\ndef use(flag, unknown):\n    handler = known if flag else unknown\n    handler(timeout=1)\n"
    index, path = indexed(tmp_path, source)
    assert index.rename_ranges_at(path.as_uri(), 0, 13) == []


def test_cyclic_property_and_field_aliases_do_not_abort_indexing(tmp_path):
    source = "class Wrapper:\n    def __init__(self):\n        self.callback = self.callback_factory()\n    def callback_factory(self):\n        return self.callback\n    def run(self):\n        self.callback()\nwrapper = Wrapper()\nwrapper.run()\n"
    index, path = indexed(tmp_path, source)
    assert index.definitions_at(path.as_uri(), 8, 10)[0].start_line == 5


def test_optional_receiver_does_not_make_a_nonexistent_none_member_ambiguous(tmp_path):
    source = "class Console:\n    def line(self): pass\ndef use(console: Console | None):\n    console = console or Console()\n    console.line()\n"
    index, path = indexed(tmp_path, source)
    assert {location.start_line for location in index.rename_ranges_at(path.as_uri(), 1, 10)} == {
        1,
        4,
    }
    ambiguous = "class C:\n    def __repr__(self): return ''\ndef use(value: C | None):\n    value.__repr__()\n"
    other, path = indexed(tmp_path, ambiguous)
    assert other.rename_ranges_at(path.as_uri(), 1, 12) == []


def test_method_override_shadows_an_inherited_property():
    source = "from typing import Callable\nclass Base:\n    @property\n    def value(self) -> int: return 1\nclass Child(Base):\n    def value(self) -> str: return ''\ndef f() -> Callable[..., str]: return Child().value\n"
    assert not mismatches(source)
