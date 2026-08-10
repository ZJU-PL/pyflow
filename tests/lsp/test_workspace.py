"""Tests for source-accurate LSP workspace indexing."""

from pathlib import Path

from pyflow.lsp.workspace import (
    SourceIndex,
    SymbolKind,
    WorkspaceDocuments,
    lsp_character_to_offset,
    offset_to_lsp_character,
    path_to_uri,
    uri_to_path,
)


def _index(tmp_path: Path) -> tuple[SourceIndex, str]:
    path = tmp_path / "sample.py"
    source = (
        "def target(value):\n"
        "    return value\n\n"
        "def caller():\n"
        "    return target(1)\n"
    )
    path.write_text(source)
    return SourceIndex({str(path): source}, (tmp_path,)), path.as_uri()


def test_file_uri_round_trip_handles_spaces(tmp_path: Path):
    path = tmp_path / "with space.py"
    assert uri_to_path(path_to_uri(path)) == str(path.absolute())


def test_utf16_character_conversion():
    line = "a😀b"
    assert lsp_character_to_offset(line, 3) == 2
    assert offset_to_lsp_character(line, 2) == 3


def test_document_symbols_are_filtered_by_uri(tmp_path: Path):
    index, uri = _index(tmp_path)
    assert [symbol.name for symbol in index.document_symbols(uri)] == [
        "target",
        "caller",
    ]
    assert index.document_symbols("file:///other.py") == []


def test_definition_resolves_identifier_under_cursor(tmp_path: Path):
    index, uri = _index(tmp_path)
    definitions = index.definitions_at(uri, 4, 12)
    assert len(definitions) == 1
    assert definitions[0].start_line == 0
    assert definitions[0].start_character == 4


def test_references_return_real_source_locations(tmp_path: Path):
    index, uri = _index(tmp_path)
    references = index.references_at(uri, 0, 5, include_declaration=True)
    assert {(item.start_line, item.start_character) for item in references} == {
        (0, 4),
        (4, 11),
    }


def test_call_hierarchy_uses_call_site_ranges(tmp_path: Path):
    index, _uri = _index(tmp_path)
    incoming = index.incoming_calls("sample.target")
    assert len(incoming) == 1
    caller, ranges = incoming[0]
    assert caller.qualified_name == "sample.caller"
    assert ranges[0].start_line == 4

    outgoing = index.outgoing_calls("sample.caller")
    assert len(outgoing) == 1
    assert outgoing[0][0].qualified_name == "sample.target"


def test_workspace_documents_track_overlays(tmp_path: Path):
    documents = WorkspaceDocuments()
    path = str(tmp_path / "sample.py")
    documents.open(path, "x = 1\n", 1)
    documents.change(path, [{"text": "x = 2\n"}], 2)
    assert documents.source_overrides()[path] == "x = 2\n"
    documents.close(path)
    assert documents.source_overrides() == {}


def test_workspace_documents_apply_incremental_utf16_changes_and_reject_stale():
    documents = WorkspaceDocuments()
    path = "/tmp/sample.py"
    assert documents.open(path, "value = '😀'\n", 1)
    assert documents.change(
        path,
        [
            {
                "range": {
                    "start": {"line": 0, "character": 0},
                    "end": {"line": 0, "character": 5},
                },
                "text": "result",
            }
        ],
        2,
    )
    assert documents.text(path) == "result = '😀'\n"
    assert not documents.change(path, [{"text": "stale"}], 1)
    assert documents.text(path) == "result = '😀'\n"


def test_symbol_identity_distinguishes_methods_and_local_shadowing(tmp_path: Path):
    path = tmp_path / "symbols.py"
    source = (
        "class A:\n    def foo(self): return 1\n\n"
        "class B:\n    def foo(self): return 2\n\n"
        "def foo(): return 3\n\n"
        "def use():\n    foo = 4\n    return foo\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    a_foo = index.symbol_by_name("symbols.A.foo")
    b_foo = index.symbol_by_name("symbols.B.foo")
    local_foo = index.definitions_at(path.as_uri(), 9, 4)[0]

    assert a_foo is not None and b_foo is not None
    assert a_foo.symbol_id != b_foo.symbol_id
    assert a_foo.symbol_id.kind is SymbolKind.METHOD
    assert local_foo.start_line == 9
    references = index.references_at(
        path.as_uri(), 10, 11, include_declaration=True
    )
    assert {item.start_line for item in references} == {9, 10}


def test_import_alias_resolves_to_imported_symbol_identity(tmp_path: Path):
    provider = tmp_path / "provider.py"
    consumer = tmp_path / "consumer.py"
    provider_source = "def target():\n    return 1\n"
    consumer_source = "from provider import target as alias\n\ndef use():\n    return alias()\n"
    index = SourceIndex(
        {str(provider): provider_source, str(consumer): consumer_source}, (tmp_path,)
    )

    definition = index.definitions_at(consumer.as_uri(), 3, 11)

    assert len(definition) == 1
    assert definition[0].uri == provider.as_uri()


def test_reassignment_reuses_lexical_binding_and_nested_function_is_not_method(
    tmp_path: Path,
):
    path = tmp_path / "bindings.py"
    source = (
        "class A:\n"
        "    def method(self):\n"
        "        def inner():\n"
        "            return 1\n"
        "        return inner\n\n"
        "def use():\n"
        "    value = 1\n"
        "    value = 2\n"
        "    return value\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))

    inner = index.symbol_by_name("bindings.A.method.inner")
    assignment = index.symbol_at(path.as_uri(), 8, 5)
    reference = index.symbol_at(path.as_uri(), 9, 12)

    assert inner is not None
    assert inner.symbol_id.kind is SymbolKind.FUNCTION
    assert assignment is not None and reference is not None
    assert assignment.symbol_id == reference.symbol_id
    assert len([s for s in index.symbols if s.name == "value"]) == 1


def test_ambiguous_symbol_fallback_and_multi_root_module_identity(tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_file = first / "shared.py"
    second_file = second / "shared.py"
    first_file.write_text("def same(): pass\n\ndef use(): return same()\n")
    second_file.write_text("def same(): pass\n")
    index = SourceIndex(
        {
            str(first_file): first_file.read_text(),
            str(second_file): second_file.read_text(),
        },
        (first, second),
    )

    assert {symbol.module for symbol in index.symbols} == {"shared"}
    assert index.symbol_by_name("same") is None
    assert index.incoming_calls("same") == []
