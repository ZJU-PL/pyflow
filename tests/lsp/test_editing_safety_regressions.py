"""Multi-document editing, diagnostics and refactoring safety regressions."""

import asyncio
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from pyflow.lsp import AnalysisManager, LspHandler, JsonRpcServer
from pyflow.lsp.document_analysis import document_diagnostics
from pyflow.lsp.transport import JsonRpcError
from pyflow.lsp.workspace import SourceIndex


def handler_for(index):
    return LspHandler(
        SimpleNamespace(
            is_loaded=True, current_snapshot=lambda: SimpleNamespace(source_index=index)
        )
    )


def rename(index, path, line, column, name):
    return handler_for(index)._handle_rename(
        {
            "textDocument": {"uri": path.as_uri()},
            "position": {"line": line, "character": column},
            "newName": name,
        }
    )


@pytest.mark.parametrize(
    "source,line,column,new_name",
    [
        (
            "def compute(target, existing_var):\n    target = target + 1\n    return target + existing_var\n",
            0,
            14,
            "existing_var",
        ),
        ("existing = 1\ndef f(target):\n    return target + existing\n", 1, 8, "existing"),
        (
            "def f(target):\n    def inner(existing):\n        return target + existing\n    return inner\n",
            0,
            8,
            "existing",
        ),
        ("target = 1\ndef f(existing):\n    return target + existing\n", 0, 3, "existing"),
        ("class C:\n    def first(self): pass\n    def second(self): pass\n", 1, 9, "second"),
        (
            "class Base:\n    def other(self): pass\nclass C(Base):\n    def target(self): pass\n",
            3,
            10,
            "other",
        ),
    ],
)
def test_rename_refuses_scope_collision_and_reference_capture(
    tmp_path, source, line, column, new_name
):
    path = tmp_path / "app.py"
    index = SourceIndex({str(path): source}, (tmp_path,))
    with pytest.raises(JsonRpcError) as error:
        rename(index, path, line, column, new_name)
    assert error.value.code == -32602
    assert any(
        word in str(error.value).lower() for word in ["conflict", "capture", "shadow", "invalid"]
    )
    assert index.source_files[str(path)] == source


def test_same_name_in_an_unrelated_scope_does_not_block_rename(tmp_path):
    path = tmp_path / "app.py"
    source = "def f(target): return target\ndef g(existing): return existing\n"
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert len(rename(index, path, 0, 8, "existing")["changes"][path.as_uri()]) == 2


def test_global_declaration_is_renamed_and_local_capture_is_rejected(tmp_path):
    path = tmp_path / "app.py"
    source = "target=1\ndef f():\n    global target\n    target += 1\n    return target\n"
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert len(rename(index, path, 0, 2, "updated")["changes"][path.as_uri()]) == 4
    bad = source.replace("    target += 1", "    existing = 2\n    target += 1")
    index = SourceIndex({str(path): bad}, (tmp_path,))
    with pytest.raises(JsonRpcError):
        rename(index, path, 0, 2, "existing")


@pytest.mark.parametrize(
    "source",
    [
        "try:\n    import click\nexcept ImportError:\n    exit()\n@click.command()\ndef hello(): pass\n",
        'try:\n    import tomllib\nexcept ImportError:\n    import tomli as tomllib\nvalue=tomllib.loads("x=1")\n',
        "try:\n    import click\nexcept ImportError:\n    click=None\nif click is not None:\n    click.command()\n",
    ],
)
def test_conditional_imports_are_not_undefined_names(tmp_path, source):
    path = tmp_path / "app.py"
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert not any(
        item["code"] == "undefined-name" for item in document_diagnostics(index, path.as_uri())
    )


def test_class_pattern_fields_and_captures_have_distinct_bindings(tmp_path):
    path = tmp_path / "app.py"
    source = "class Click:\n    x: int\n    y: int\ndef f(event):\n    match event:\n        case Click(x=val_x, y=val_y):\n            print(val_x, val_y)\n"
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert index.definitions_at(path.as_uri(), 5, 15)[0].start_line == 0
    assert index.definitions_at(path.as_uri(), 5, 19)[0].start_line == 1
    assert index.definitions_at(path.as_uri(), 6, 20)[0].start_line == 5
    assert not any(
        d["code"] == "undefined-name" for d in document_diagnostics(index, path.as_uri())
    )
    edits = rename(index, path, 1, 4, "horizontal")["changes"][path.as_uri()]
    assert {edit["range"]["start"]["line"] for edit in edits} == {1, 5}


def test_positional_match_args_are_field_references(tmp_path):
    path = tmp_path / "app.py"
    source = 'class Point:\n    __match_args__=("x", "y")\n    x: int\n    y: int\ndef f(point):\n    match point:\n        case Point(a, b):\n            return a, b\n'
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert index.definitions_at(path.as_uri(), 6, 16)[0].start_line == 0
    edits = rename(index, path, 2, 4, "horizontal")["changes"][path.as_uri()]
    assert {edit["range"]["start"]["line"] for edit in edits} == {1, 2}


@pytest.mark.parametrize("indent", ["    ", "\t"])
def test_incomplete_indented_wrappers_preserve_and_then_reparse_symbols(tmp_path, indent):
    path = tmp_path / "app.py"
    original = "def first(value):\n    return value\n\ndef second():\n    return first(1)\n"
    index = SourceIndex({str(path): original}, (tmp_path,))
    partial = "try:\n" + "".join(
        indent + line if line.strip() else line for line in original.splitlines(keepends=True)
    )
    recovering = index.with_source_files({str(path): partial})
    first = recovering.symbol_by_name("app.first")
    assert first is not None and first.selection_range.start_line == 1
    assert first.selection_range.start_character == len(indent) + 4
    assert recovering.hover_at(path.as_uri(), 1, len(indent) + 6)
    assert recovering.definitions_at(path.as_uri(), 5, len(indent) + 13)[0].start_line == 1
    repaired = recovering.with_source_files({str(path): partial + "except Exception:\n    pass\n"})
    assert repaired.symbol_by_name("app.first").selection_range == first.selection_range
    assert not repaired.diagnostics_for_uri(path.as_uri())


async def protocol_handler(tmp_path, capabilities=None):
    manager = AnalysisManager()
    handler = LspHandler(manager)
    rpc = JsonRpcServer()
    sent = []

    async def send(payload):
        sent.append(payload)

    rpc._send = send
    handler.register_on(rpc)
    await handler._handle_initialize(
        {"rootUri": tmp_path.as_uri(), "capabilities": capabilities or {}}
    )
    return handler, sent


def test_push_diagnostics_open_change_save_close_are_versioned_and_cleared(tmp_path):
    async def exercise():
        handler, sent = await protocol_handler(tmp_path)
        path = tmp_path / "app.py"
        uri = path.as_uri()
        await handler._handle_did_open(
            {"textDocument": {"uri": uri, "version": 1, "text": "def broken(:\n"}}
        )
        await asyncio.sleep(0.25)
        assert sent[-1]["method"] == "textDocument/publishDiagnostics"
        assert sent[-1]["params"]["version"] == 1 and sent[-1]["params"]["diagnostics"]
        await handler._handle_did_change(
            {"textDocument": {"uri": uri, "version": 2}, "contentChanges": [{"text": "value=1\n"}]}
        )
        await asyncio.sleep(0.25)
        assert sent[-1]["params"]["version"] == 2 and sent[-1]["params"]["diagnostics"] == []
        before = len(sent)
        await handler._handle_did_save({"textDocument": {"uri": uri}})
        await asyncio.sleep(0.25)
        assert len(sent) > before
        await handler._handle_did_close({"textDocument": {"uri": uri}})
        assert sent[-1]["params"] == {"uri": uri, "diagnostics": []}
        handler._handle_shutdown(None)

    asyncio.run(exercise())


def test_pull_capable_clients_do_not_receive_duplicate_push(tmp_path):
    async def exercise():
        handler, sent = await protocol_handler(tmp_path, {"textDocument": {"diagnostic": {}}})
        uri = (tmp_path / "app.py").as_uri()
        await handler._handle_did_open(
            {"textDocument": {"uri": uri, "version": 1, "text": "def broken(:\n"}}
        )
        await asyncio.sleep(0.25)
        assert not sent
        result = await handler._handle_document_diagnostic({"textDocument": {"uri": uri}})
        assert result["items"]
        handler._handle_shutdown(None)

    asyncio.run(exercise())


def test_multi_document_push_never_publishes_cancelled_or_closed_versions(tmp_path, monkeypatch):
    from pyflow.lsp import document_analysis

    entered, release = threading.Event(), threading.Event()

    def diagnose(index, uri):
        text = index.text_for_uri(uri)
        if text == "old\n":
            entered.set()
            assert release.wait(3)
        return [
            {
                "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}},
                "message": text,
                "severity": 1,
            }
        ]

    monkeypatch.setattr(document_analysis, "document_diagnostics", diagnose)

    async def exercise():
        handler, sent = await protocol_handler(tmp_path)
        a, b = (tmp_path / "a.py").as_uri(), (tmp_path / "b.py").as_uri()
        await handler._handle_did_open({"textDocument": {"uri": a, "version": 1, "text": "old\n"}})
        assert await asyncio.to_thread(entered.wait, 3)
        await handler._handle_did_change(
            {"textDocument": {"uri": a, "version": 2}, "contentChanges": [{"text": "new\n"}]}
        )
        await handler._handle_did_open(
            {"textDocument": {"uri": b, "version": 1, "text": "other\n"}}
        )
        release.set()
        await asyncio.sleep(0.4)
        assert all(
            item["params"].get("version") != 1 for item in sent if item["params"]["uri"] == a
        )
        assert {item["params"]["uri"] for item in sent} == {a, b}
        await handler._handle_did_close({"textDocument": {"uri": a}})
        before = len(sent)
        await asyncio.sleep(0.2)
        assert len(sent) == before
        handler._handle_shutdown(None)

    try:
        asyncio.run(exercise())
    finally:
        release.set()


def test_framework_proxy_and_state_models_use_qualified_identity(tmp_path):
    writer, reader = tmp_path / "middleware.py", tmp_path / "routes.py"
    index = SourceIndex(
        {
            str(
                writer
            ): 'from fastapi import Request\ndef set_user(request: Request):\n    request.state.user="alice"\n',
            str(
                reader
            ): 'from fastapi import Request\nfrom flask import current_app\ndef read(request: Request):\n    current_app.config["SECRET_KEY"]\n    return request.state.user\n',
        },
        (tmp_path,),
    )
    assert index.definitions_at(reader.as_uri(), 4, 27)[0].uri == writer.as_uri()
    assert "str" in index.hover_at(reader.as_uri(), 4, 27)["contents"]["value"]
    assert index.definitions_at(reader.as_uri(), 3, 20)
    edits = rename(index, reader, 4, 27, "account")["changes"]
    assert set(edits) == {writer.as_uri(), reader.as_uri()}


def test_request_state_and_application_state_do_not_share_slots(tmp_path):
    path = tmp_path / "app.py"
    source = 'from fastapi import Request, FastAPI\napp=FastAPI()\napp.state.user="application"\ndef f(request: Request):\n    request.state.user="request"\n    return request.state.user\n'
    index = SourceIndex({str(path): source}, (tmp_path,))
    edits = rename(index, path, 4, 20, "account")["changes"][path.as_uri()]
    assert {edit["range"]["start"]["line"] for edit in edits} == {4, 5}


def test_unrelated_request_and_proxy_names_do_not_borrow_framework_models(tmp_path):
    path = tmp_path / "app.py"
    source = 'from unrelated import Request, current_app\ndef f(request: Request):\n    request.state.user="x"\n    return current_app.config\n'
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert not index.definitions_at(path.as_uri(), 2, 20)
    assert not index.definitions_at(path.as_uri(), 3, 25)


def test_class_pattern_as_capture_does_not_steal_a_keyword_field_token(tmp_path):
    path = tmp_path / "app.py"
    source = "class C:\n    x: int\ndef f(value):\n    match value:\n        case C(x=inner) as x:\n            return x, inner\n"
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert index.definitions_at(path.as_uri(), 4, 15)[0].start_line == 1
    capture = index.definitions_at(path.as_uri(), 5, 20)[0]
    assert capture.start_line == 4 and capture.start_character == 27
    edits = rename(index, path, 5, 20, "matched")["changes"][path.as_uri()]
    assert {
        edit["range"]["start"]["character"] for edit in edits if edit["range"]["start"]["line"] == 4
    } == {27}
