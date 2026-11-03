"""Regressions for import aliases, completion receivers and semantic snapshots."""

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
