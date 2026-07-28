"""Tests for source-accurate LSP workspace indexing."""

from pathlib import Path

from pyflow.lsp.workspace import (
    SourceIndex,
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
    return SourceIndex({str(path): source}, str(tmp_path)), path.as_uri()


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
    documents.change(path, "x = 2\n", 2)
    assert documents.source_overrides()[path] == "x = 2\n"
    documents.close(path)
    assert documents.source_overrides() == {}
