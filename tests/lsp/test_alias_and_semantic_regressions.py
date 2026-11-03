"""Regressions for import aliases, completion receivers and semantic snapshots."""

import ast
from pathlib import Path

import pytest

from pyflow.lsp import AnalysisManager
from pyflow.lsp.document_analysis import document_diagnostics
from pyflow.lsp.refactor import validate_rename
from pyflow.lsp.workspace import SourceIndex, path_to_uri


def _workspace(tmp_path: Path, main_source: str):
    models = tmp_path / "models.py"
    models.write_text(
        "class Widget:\n    def greet(self, name: str) -> str:\n        return name\n"
    )
    main = tmp_path / "main.py"
    main.write_text(main_source)
    index = SourceIndex({str(models): models.read_text(), str(main): main.read_text()}, (tmp_path,))
    return index, models, main


def test_import_alias_navigation_and_rename_stay_local(tmp_path: Path):
    source = (
        "from models import Widget as W\n"
        "import models as m\n"
        "\n"
        "def use() -> None:\n"
        "    W('a')\n"
        "    m.Widget('b')\n"
    )
    index, models, main = _workspace(tmp_path, source)
    uri = path_to_uri(main)
    alias_col = source.splitlines()[0].index("W", source.splitlines()[0].index(" as ") + 4)
    module_alias_col = source.splitlines()[1].index("m", source.splitlines()[1].index(" as ") + 4)

    hover = index.hover_at(uri, 0, alias_col)
    assert hover is not None
    assert "import models.Widget as W" in hover["contents"]["value"]
    assert index.definitions_at(uri, 0, alias_col)[0].start_line == 0
    assert index.definitions_at(uri, 0, alias_col)[0].uri == path_to_uri(models)

    alias_ranges = index.rename_ranges_at(uri, 0, alias_col)
    assert {(item.start_line, item.start_character) for item in alias_ranges} == {
        (0, alias_col),
        (4, source.splitlines()[4].index("W")),
    }
    module_ranges = index.rename_ranges_at(uri, 1, module_alias_col)
    assert {(item.start_line, item.start_character) for item in module_ranges} == {
        (1, module_alias_col),
        (5, source.splitlines()[5].index("m")),
    }


def test_renaming_the_class_does_not_touch_an_explicit_alias(tmp_path: Path):
    source = "from models import Widget as W\n\ndef use() -> None:\n    W('a')\n"
    index, models, main = _workspace(tmp_path, source)
    models_uri = path_to_uri(models)
    ranges = index.rename_ranges_at(models_uri, 0, models.read_text().index("Widget"))
    import_line = source.splitlines()[0]
    original_col = import_line.index("Widget")
    alias_col = import_line.index("W", import_line.index(" as ") + 4)
    main_uri = path_to_uri(main)
    assert any(
        item.uri == main_uri and item.start_line == 0 and item.start_character == original_col
        for item in ranges
    )
    assert not any(
        item.uri == main_uri and item.start_line == 0 and item.start_character == alias_col
        for item in ranges
    )
    symbol = index.symbol_at(models_uri, 0, models.read_text().index("Widget"))
    validate_rename(index, symbol, ranges, "Renamed")


@pytest.mark.parametrize(
    "receiver_expression",
    [
        "    value = 1 + w.greet",
        "    value = True and w.greet",
        "    value = identity(1) + w.greet",
    ],
)
def test_member_completion_after_binary_and_bool_operators(tmp_path: Path, receiver_expression):
    source = (
        "from models import Widget\n"
        "\n"
        "def identity(value):\n"
        "    return value\n"
        "\n"
        "def use(w: Widget) -> None:\n"
        f"{receiver_expression}\n"
    )
    index, _, main = _workspace(tmp_path, source)
    incomplete = source.replace(".greet", ".")
    current = index.with_source_files(
        {
            **{
                str(models_file): models_file.read_text()
                for models_file in (tmp_path / "models.py",)
            },
            str(main): incomplete,
        }
    )
    line = len(incomplete.rstrip("\n").splitlines()) - 1
    labels = {
        item["label"]
        for item in current.completion_items(
            path_to_uri(main), line, len(incomplete.splitlines()[line])
        )
    }
    assert "greet" in labels


@pytest.mark.parametrize(
    "source,expected",
    [
        ("class A:\n    def f(self):\n        return __class__\n", []),
        ("class A:\n    module = __module__\n    qualname = __qualname__\n", []),
        ("x = __class__\n", ["__class__"]),
        ("class A:\n    def f(self):\n        return __qualname__\n", ["__qualname__"]),
        ("class A:\n    values = [__class__ for _ in [1]]\n", ["__class__"]),
    ],
)
def test_compiler_provided_names_are_not_undefined(tmp_path: Path, source, expected):
    path = tmp_path / "implicit.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    names = [
        item["message"].split("'")[1]
        for item in document_diagnostics(index, path.as_uri())
        if item.get("code") == "undefined-name"
    ]
    assert names == expected


def test_full_pipeline_keeps_ipa_results_and_call_graph_feature(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        "def helper(value: int) -> int:\n    return value\n\ndef caller() -> int:\n    return helper(1)\n"
    )
    manager = AnalysisManager()
    manager.load_files([path], passes=["ipa", "cpa", "lifetime"])
    snapshot = manager.current_snapshot()
    assert "ipa" in snapshot.program.session.results
    assert snapshot.features.call_graph


def test_delete_attribute_does_not_abort_cpa(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        "class Box:\n"
        "    def __init__(self) -> None:\n"
        "        self.value = 1\n"
        "\n"
        "def clear(box: Box) -> None:\n"
        "    del box.value\n"
    )
    manager = AnalysisManager()
    manager.load_files([path], passes=["ipa", "cpa"])
    assert manager.current_snapshot().features.cpa


def test_unicode_identifiers_navigate_complete_and_rename(tmp_path: Path):
    source = (
        "café = 1\n"
        "\n"
        "class Café:\n"
        "    def __init__(self) -> None:\n"
        "        self.属性 = 2\n"
        "    def méto(self, 变量: int) -> int:\n"
        "        return 变量 + café\n"
    )
    path = tmp_path / "unicode_ids.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()
    assert {"café", "Café", "属性", "méto"} <= {
        symbol.name for symbol in index.document_symbols(uri)
    }
    assert index.word_at(uri, 6, 15) == "变量"
    assert "属性" in {item["label"] for item in index.completion_items(uri, 4, 13)}
    assert "属性" in {item["label"] for item in index.completion_items(uri, 4, 14)}

    lines = source.splitlines()
    for source_range in index.rename_ranges_at(uri, 5, 19):
        assert (
            lines[source_range.start_line][
                source_range.start_character : source_range.end_character
            ]
            == "变量"
        )


def test_from_import_module_path_is_navigable(tmp_path: Path):
    models = tmp_path / "models.py"
    models.write_text("class Widget:\n    pass\n")
    main = tmp_path / "main.py"
    main.write_text("from models import Widget\n\nvalue = Widget()\n")
    index = SourceIndex({str(models): models.read_text(), str(main): main.read_text()}, (tmp_path,))
    definitions = index.definitions_at(path_to_uri(main), 0, 7)
    assert [item.uri for item in definitions] == [path_to_uri(models)]


def test_multi_root_workspace_resolves_across_roots(tmp_path: Path):
    r1 = tmp_path / "r1"
    r2 = tmp_path / "r2"
    (r1 / "alpha").mkdir(parents=True)
    (r2 / "beta").mkdir(parents=True)
    (r1 / "alpha" / "__init__.py").write_text(
        "class A:\n    def hi(self) -> str:\n        return 'a'\n"
    )
    (r2 / "beta" / "__init__.py").write_text("class B:\n    pass\n")
    use = r2 / "beta" / "use.py"
    use.write_text("from alpha import A\n\ndef run(a: A) -> str:\n    return a.hi()\n")
    sources = {
        str(path): path.read_text()
        for path in [r1 / "alpha" / "__init__.py", r2 / "beta" / "__init__.py", use]
    }
    index = SourceIndex(sources, (r1, r2))
    definitions = index.definitions_at(path_to_uri(use), 3, 13)
    assert [item.uri for item in definitions] == [path_to_uri(r1 / "alpha" / "__init__.py")]
    assert "hi" in {item["label"] for item in index.completion_items(path_to_uri(use), 3, 13)}


def test_utf8_bom_in_overlay_is_tolerated(tmp_path: Path):
    path = tmp_path / "bom.py"
    source = "\ufeffdef alpha() -> int:\n    return 1\n"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()
    assert [symbol.name for symbol in index.document_symbols(uri)] == ["alpha"]
    assert document_diagnostics(index, uri) == []


def test_unsupported_document_uri_is_ignored(tmp_path: Path):
    import asyncio

    from pyflow.lsp import AnalysisManager, LspHandler

    path = tmp_path / "app.py"
    path.write_text("value = 1\n")
    manager = AnalysisManager()
    manager.load_files([path], run_pipeline=False)
    handler = LspHandler(manager)
    document = {
        "uri": "untitled:Untitled-1",
        "languageId": "python",
        "version": 1,
        "text": "x = 1\n",
    }
    asyncio.run(handler._handle_did_open({"textDocument": document}))
    asyncio.run(
        handler._handle_did_change(
            {
                "textDocument": {"uri": "untitled:Untitled-1", "version": 2},
                "contentChanges": [{"text": "x = 2\n"}],
            }
        )
    )
    assert "untitled:Untitled-1" not in handler._open_documents


def test_string_annotations_are_references_and_renameable(tmp_path: Path):
    source = (
        "from typing import Literal, Optional\n"
        "\n"
        "class Widget:\n"
        "    pass\n"
        "\n"
        'def make(x: "Widget", y: Optional["Widget"] = None) -> "Widget":\n'
        "    return x\n"
        "\n"
        'value: Literal["Widget"] = "Widget"\n'
    )
    path = tmp_path / "forward.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()

    string_ranges = {
        (reference.location.start_line, reference.location.start_character)
        for reference in index.references
        if reference.location.uri == uri and reference.string_literal is False
    }

    def positions(line_no: int, name: str) -> set[tuple[int, int]]:
        line = source.splitlines()[line_no]
        found, start = set(), 0
        while (index := line.find(name, start)) >= 0:
            found.add((line_no, index))
            start = index + 1
        return found

    assert positions(5, "Widget") <= string_ranges
    assert not (positions(8, "Widget") & string_ranges)  # Literal values, not references

    ranges = index.rename_ranges_at(uri, 2, 6)
    lines = source.splitlines()
    for source_range in sorted(
        ranges, key=lambda item: (item.start_line, item.start_character), reverse=True
    ):
        lines[source_range.start_line] = (
            lines[source_range.start_line][: source_range.start_character]
            + "ZWidget"
            + lines[source_range.start_line][source_range.end_character :]
        )
    updated = "\n".join(lines)
    ast.parse(updated)
    assert 'x: "ZWidget"' in updated
    assert 'Optional["ZWidget"]' in updated
    assert '-> "ZWidget"' in updated
    assert 'Literal["Widget"] = "Widget"' in updated


def test_escaped_string_annotation_is_replaced_as_a_literal(tmp_path: Path):
    source = "class Widget:\n" "    pass\n" "\n" 'def make(x: "Wid\\x67et") -> None:\n' "    pass\n"
    path = tmp_path / "escaped.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()
    references = [
        item for item in index.references if item.location.uri == uri and item.name == "Widget"
    ]
    assert references and references[0].string_literal
    ranges = index.rename_ranges_at(uri, 0, 6)
    assert any(item.start_line == 3 for item in ranges)
    assert index.replacement_text(
        [item for item in ranges if item.start_line == 3][0], "ZWidget"
    ) == repr("ZWidget")


def test_unknown_names_in_string_annotations_are_not_diagnostics(tmp_path: Path):
    source = 'def f(x: "UnknownType") -> None:\n    pass\n'
    path = tmp_path / "unknown.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert document_diagnostics(index, path.as_uri()) == []


def test_symlinked_source_tree_is_indexed_without_cycles(tmp_path: Path):
    from pyflow.frontend.file_selection import discover_python_files
    from pyflow.lsp import AnalysisManager

    real = tmp_path / "shared" / "pkg"
    real.mkdir(parents=True)
    (real / "__init__.py").write_text("class Shared:\n    pass\n")
    (tmp_path / "linkedpkg").symlink_to(real, target_is_directory=True)
    (tmp_path / "main.py").write_text(
        "from linkedpkg import Shared\n\ndef use(x: Shared) -> None:\n    pass\n"
    )
    (tmp_path / "cycle").symlink_to(tmp_path, target_is_directory=True)

    manager = AnalysisManager()
    manager.load_source_workspaces([str(tmp_path)])
    index = manager.current_snapshot().source_index
    assert any(symbol.qualified_name == "linkedpkg.Shared" for symbol in index.symbols)
    definitions = index.definitions_at(path_to_uri(tmp_path / "main.py"), 0, 23)
    assert [item.uri for item in definitions] == [
        path_to_uri(tmp_path / "linkedpkg" / "__init__.py")
    ]

    # A self-referencing directory must not recurse forever.
    discovered = discover_python_files(
        tmp_path, recursive=True, exclude=("cycle",), follow_symlinks=True
    )
    assert any(path.name == "main.py" for path in discovered)


def test_handler_barrier_waits_for_pending_index_rebuild(tmp_path: Path):
    import asyncio

    from pyflow.lsp import AnalysisManager, LspHandler

    path = tmp_path / "app.py"
    path.write_text("def alpha() -> int:\n    return 1\n")
    manager = AnalysisManager()
    manager.load_files([path], run_pipeline=False)
    handler = LspHandler(manager)

    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()

        async def fake_ensure(uri):
            started.set()
            await release.wait()

        handler._ensure_index = fake_ensure
        change = asyncio.create_task(
            handler._handle_did_change(
                {
                    "textDocument": {"uri": path.as_uri(), "version": 2},
                    "contentChanges": [{"text": "def beta() -> int:\n    return 2\n"}],
                }
            )
        )
        await started.wait()
        waiter = asyncio.create_task(handler._wait_pending_index())
        await asyncio.sleep(0)
        assert not waiter.done()
        release.set()
        await asyncio.gather(change, waiter)
        assert handler._pending_index == {}

    asyncio.run(scenario())


def test_malformed_request_parameters_are_invalid_params(tmp_path: Path):
    import pytest

    from pyflow.lsp import AnalysisManager, LspHandler
    from pyflow.lsp.transport import ErrorCodes, JsonRpcError

    path = tmp_path / "app.py"
    path.write_text("value = 1\n")
    manager = AnalysisManager()
    manager.load_files([path], run_pipeline=False)
    handler = LspHandler(manager)

    with pytest.raises(JsonRpcError) as invalid_position:
        handler._handle_completion(
            {
                "textDocument": {"uri": path.as_uri()},
                "position": {"line": "not-a-number", "character": 0},
            }
        )
    assert invalid_position.value.code == ErrorCodes.InvalidParams

    with pytest.raises(JsonRpcError) as invalid_query:
        handler._handle_workspace_symbol({"query": None})
    assert invalid_query.value.code == ErrorCodes.InvalidParams


def test_slots_declarations_are_fields_and_renameable(tmp_path: Path):
    source = (
        "class Slotted:\n"
        '    __slots__ = ("x", "y")\n'
        "\n"
        "    def __init__(self) -> None:\n"
        "        self.x = 1\n"
        "        self.y = 2\n"
    )
    path = tmp_path / "slots.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()
    fields = {symbol.name: symbol for symbol in index.document_symbols(uri)}
    assert {"x", "y"} <= set(fields)
    assert fields["x"].selection_range.start_line == 1
    assert fields["x"].selection_range.start_character == 18

    lines = source.splitlines()
    for source_range in index.rename_ranges_at(uri, 4, 13):
        lines[source_range.start_line] = (
            lines[source_range.start_line][: source_range.start_character]
            + "z"
            + lines[source_range.start_line][source_range.end_character :]
        )
    updated = "\n".join(lines)
    ast.parse(updated)
    assert '__slots__ = ("z", "y")' in updated
    assert "self.z = 1" in updated


def test_escaped_slots_entry_is_replaced_as_a_literal(tmp_path: Path):
    source = 'class Slotted:\n    __slots__ = ("\\x78",)\n'
    path = tmp_path / "escaped_slots.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()
    references = [
        item for item in index.references if item.location.uri == uri and item.name == "x"
    ]
    assert references and references[0].string_literal
    ranges = index.rename_ranges_at(uri, 1, 18)
    slot_range = [item for item in ranges if item.start_line == 1]
    assert index.replacement_text(slot_range[0], "z") == repr("z")


def test_typeddict_fields_follow_subscripts_literals_and_constructor_keywords(tmp_path: Path):
    source = (
        "from typing import TypedDict\n"
        "\n"
        "class Movie(TypedDict):\n"
        "    title: str\n"
        "    year: int\n"
        "\n"
        "def use(m: Movie, title: str) -> None:\n"
        '    print(m["title"])\n'
        '    other: Movie = {"title": title, "year": 2000}\n'
        "    copy = Movie(title=title, year=1)\n"
    )
    path = tmp_path / "movie.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()

    ranges = index.rename_ranges_at(uri, 3, 6)
    assert {(item.start_line, item.start_character) for item in ranges} == {
        (3, 4),
        (7, 13),
        (8, 21),
        (9, 17),
    }
    definitions = index.definitions_at(uri, 7, 13)
    assert [(item.start_line, item.start_character) for item in definitions] == [(3, 4)]
    assert "title: str" in index.hover_at(uri, 7, 13)["contents"]["value"]

    lines = source.splitlines()
    for source_range in sorted(
        ranges, key=lambda item: (item.start_line, item.start_character), reverse=True
    ):
        lines[source_range.start_line] = (
            lines[source_range.start_line][: source_range.start_character]
            + "heading"
            + lines[source_range.start_line][source_range.end_character :]
        )
    updated = "\n".join(lines)
    ast.parse(updated)
    assert 'm["heading"]' in updated
    assert '{"heading": title, "year": 2000}' in updated
    assert "Movie(heading=title, year=1)" in updated


def test_plain_dict_subscripts_remain_unresolved(tmp_path: Path):
    source = 'def f(data: dict[str, int]) -> int:\n    return data["a"]\n'
    path = tmp_path / "plain.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()
    assert index.symbol_at(uri, 1, 17) is None
    assert index.definitions_at(uri, 1, 17) == []


def test_pydantic_model_fields_follow_constructor_keywords(tmp_path: Path):
    source = (
        "from pydantic import BaseModel\n"
        "\n"
        "class User(BaseModel):\n"
        "    name: str\n"
        "    age: int = 0\n"
        "\n"
        'user = User(name="a", age=2)\n'
    )
    path = tmp_path / "model.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()
    name_ranges = index.rename_ranges_at(uri, 3, 6)
    assert {(item.start_line, item.start_character) for item in name_ranges} == {
        (3, 4),
        (6, 12),
    }
    age_ranges = index.rename_ranges_at(uri, 4, 6)
    assert {(item.start_line, item.start_character) for item in age_ranges} == {
        (4, 4),
        (6, 22),
    }


def test_attrs_decorated_fields_follow_constructor_keywords(tmp_path: Path):
    source = (
        "import attrs\n"
        "\n"
        "@attrs.define\n"
        "class User:\n"
        "    name: str\n"
        "    age: int = 0\n"
        "\n"
        'user = User(name="a", age=2)\n'
    )
    path = tmp_path / "attrs_model.py"
    path.write_text(source)
    index = SourceIndex({str(path): source}, (tmp_path,))
    uri = path.as_uri()
    assert {
        (item.start_line, item.start_character) for item in index.rename_ranges_at(uri, 4, 6)
    } == {
        (4, 4),
        (7, 12),
    }
