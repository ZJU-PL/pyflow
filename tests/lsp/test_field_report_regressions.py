"""Editor-visible regressions from the top100 LSP field evaluation."""

import asyncio
import io
import json
from pathlib import Path
import subprocess
import sys

import pytest

from pyflow.lsp import AnalysisManager, LspHandler
from pyflow.lsp.workspace import SourceIndex
from pyflow.lsp.transport import JsonRpcError, _create_message


def position(path, line, character):
    return {
        "textDocument": {"uri": path.as_uri()},
        "position": {"line": line, "character": character},
    }


def source_manager(tmp_path, source):
    path = tmp_path / "app.py"
    path.write_text(source)
    manager = AnalysisManager()
    manager.load_source_workspaces([str(tmp_path)])
    return manager, path


def test_initialize_never_runs_compiler_and_accepts_empty_workspace(tmp_path, monkeypatch):
    import pyflow.lsp.server as module

    monkeypatch.setattr(
        module,
        "build_interface_from_paths",
        lambda *a, **k: pytest.fail("initialize entered the compiler"),
    )
    (tmp_path / "app.py").write_text("class A:\n    def f(self):\n        del self.value\n")
    manager = AnalysisManager()
    result = asyncio.run(LspHandler(manager)._handle_initialize({"rootUri": tmp_path.as_uri()}))
    assert manager.is_loaded
    assert result["capabilities"]["hoverProvider"]
    assert not manager.supports("cpa")
    empty = tmp_path / "empty"
    empty.mkdir()
    asyncio.run(LspHandler(manager)._handle_initialize({"rootUri": empty.as_uri()}))
    assert manager.is_loaded
    assert not manager.source_index.symbols


@pytest.mark.parametrize("preload", [False, True])
def test_stdio_initialize_is_strictly_framed(tmp_path, preload):
    (tmp_path / "app.py").write_text("class A:\n    def f(self):\n        del self.value\n")
    command = [sys.executable, "-m", "pyflow.cli.main", "lsp"]
    if preload:
        command.extend(["--root", str(tmp_path)])
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"rootUri": tmp_path.as_uri()},
    }
    completed = subprocess.run(
        command, input=_create_message(request), capture_output=True, timeout=10
    )
    assert completed.returncode == 0, completed.stderr.decode()
    header, separator, body = completed.stdout.partition(b"\r\n\r\n")
    assert separator and header.startswith(b"Content-Length: "), completed.stdout
    assert int(header.split(b": ")[1]) == len(body)
    assert json.loads(body)["result"]["capabilities"]["definitionProvider"] is True


def test_protocol_stream_survives_incidental_prints(tmp_path, monkeypatch):
    from argparse import Namespace
    from pyflow.cli import lsp

    raw = io.BytesIO()
    output = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    error = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(sys, "stderr", error)
    monkeypatch.setattr(
        AnalysisManager, "load_source_workspaces", lambda *args: print("compiler noise")
    )

    async def run(rpc):
        print("worker noise")
        await rpc._send({"jsonrpc": "2.0", "id": 1, "result": None})

    monkeypatch.setattr(lsp.JsonRpcServer, "run", run)
    lsp.run_lsp(Namespace(root=tmp_path, mode="full"))
    assert raw.getvalue().startswith(b"Content-Length:")
    assert b"noise" not in raw.getvalue()
    assert "compiler noise" in error.getvalue() and "worker noise" in error.getvalue()


def test_optional_pipeline_failure_keeps_editor_services(tmp_path, monkeypatch):
    manager, path = source_manager(tmp_path, "def target(): return 1\n")

    def broken(*args, **kwargs):
        raise RuntimeError("unsupported DeleteAttr")

    monkeypatch.setattr(manager, "load_files", broken)
    result = asyncio.run(
        LspHandler(manager)._handle_execute_command({"command": "pyflow.analyzeWorkspace"})
    )
    assert result["diagnostics"][0]["code"] == "semantic-analysis-failed"
    assert manager.is_loaded
    assert manager.source_index.definitions_at(path.as_uri(), 0, 6)


@pytest.mark.parametrize(
    "expression", ["value = GPT()", "value: GPT", "original = GPT()\n    value = original"]
)
def test_instance_members_use_class_identity(tmp_path, expression):
    source = (
        "class GPT:\n    def generate(self): pass\nclass Other:\n    def generate(self): pass\ndef use():\n    "
        + expression
        + "\n    value.generate()\n"
    )
    path = tmp_path / "model.py"
    index = SourceIndex({str(path): source}, (tmp_path,))
    line = len(source.splitlines()) - 1
    assert index.definitions_at(path.as_uri(), line, 13)[0].start_line == 1
    target = index.symbol_by_name("model.GPT.generate")
    assert len(index.incoming_calls(target.symbol_id)) == 1
    edits = index.rename_ranges_at(path.as_uri(), 1, 10)
    assert {item.start_line for item in edits} == {1, line}


def test_module_imports_chains_fields_and_factory_returns(tmp_path):
    model = tmp_path / "model.py"
    consumer = tmp_path / "consumer.py"
    provider = "class Child:\n    def run(self): pass\nclass Parent:\n    def __init__(self):\n        self.child = Child()\ndef make() -> Parent:\n    return Parent()\n"
    user = "import model as m\ndef use():\n    value = m.make()\n    value.child.run()\n"
    index = SourceIndex({str(model): provider, str(consumer): user}, (tmp_path,))
    assert index.definitions_at(consumer.as_uri(), 2, 16)[0].start_line == 5
    assert index.definitions_at(consumer.as_uri(), 3, 17)[0].start_line == 1
    assert index.incoming_calls("model.Child.run")[0][0].qualified_name == "consumer.use"


def test_relative_import_and_inherited_method(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("")
    base = package / "base.py"
    child = package / "child.py"
    index = SourceIndex(
        {
            str(base): "class Base:\n    def run(self): pass\n",
            str(
                child
            ): "from .base import Base\nclass Child(Base): pass\nvalue = Child()\nvalue.run()\n",
        },
        (tmp_path,),
    )
    assert index.definitions_at(child.as_uri(), 3, 7)[0].uri == base.as_uri()


def test_unknown_receivers_never_jump_to_a_unique_global_namesake(tmp_path):
    path = tmp_path / "app.py"
    source = "class A:\n    def run(self): pass\ndef use(unknown):\n    unknown.run()\n"
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert index.definitions_at(path.as_uri(), 3, 14) == []
    assert index.rename_ranges_at(path.as_uri(), 1, 10) == []
    assert index.outgoing_calls("app.use") == []


def test_hover_declarations_docstrings_offsets_and_current_edits(tmp_path):
    source = 'class Model:\n    """A text model."""\n    def generate(self, count: int = 3) -> str:\n        """Generate text."""\n        return \'hi\'\ndef use():\n    value = 1\n    return value\n'
    manager, path = source_manager(tmp_path, source)
    handler = LspHandler(manager)

    async def exercise():
        for character in range(8, 16):
            hover = await handler._handle_hover(position(path, 2, character))
            assert "def generate(self, count: int=3) -> str" in hover["contents"]["value"]
            assert "Generate text." in hover["contents"]["value"]
        assert (
            "A text model."
            in (await handler._handle_hover(position(path, 0, 8)))["contents"]["value"]
        )
        manager.open_document(path.as_uri(), source.replace("value = 1", "value = 'hello'"), 1)
        assert manager.current_snapshot().semantic_stale
        hover = await handler._handle_hover(position(path, 7, 14))
        assert "str" in hover["contents"]["value"]

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "text,expected,absent",
    [
        ("self.", "generate", "unrelated"),
        ("math.", "sqrt", "unrelated"),
        ("loc", "local_value", "unrelated"),
    ],
)
def test_completion_is_contextual_during_incomplete_edits(tmp_path, text, expected, absent):
    source = "import math\nclass Model:\n    def generate(self): pass\n    def use(self, parameter):\n        local_value = 1\n        pass\ndef unrelated(): pass\n"
    manager, path = source_manager(tmp_path, source)
    manager.open_document(path.as_uri(), source.replace("        pass", "        " + text), 1)
    handler = LspHandler(manager)
    result = handler._handle_completion(position(path, 5, 8 + len(text)))
    labels = {item["label"] for item in result["items"]}
    assert expected in labels
    assert absent not in labels
    if text == "self.":
        assert "sqrt" not in labels


def test_syntax_error_keeps_and_rebases_unedited_symbols(tmp_path):
    source = "def first(): pass\ndef second():\n    return first()\n"
    path = tmp_path / "app.py"
    index = SourceIndex({str(path): source}, (tmp_path,))
    changed = "# inserted\n" + source.replace("return first()", "return first(")
    updated = index.with_source_files({str(path): changed})
    assert {s.name for s in updated.document_symbols(path.as_uri())} == {"first", "second"}
    assert updated.symbol_by_name("app.first").selection_range.start_line == 1
    assert updated.diagnostics_for_uri(path.as_uri())
    assert updated.rename_ranges_at(path.as_uri(), 1, 6) == []
    assert index.symbol_by_name("app.first").selection_range.start_line == 0


def test_typing_never_launches_whole_project_pipeline(tmp_path, monkeypatch):
    manager, path = source_manager(tmp_path, "value = 1\n")
    monkeypatch.setattr(manager, "reload", lambda: pytest.fail("typing triggered compiler reload"))
    handler = LspHandler(manager)

    async def exercise():
        await handler._handle_did_open(
            {"textDocument": {"uri": path.as_uri(), "text": "value = 1\n", "version": 1}}
        )
        for version in range(2, 10):
            await handler._handle_did_change(
                {
                    "textDocument": {"uri": path.as_uri(), "version": version},
                    "contentChanges": [{"text": f"value = {version}\n"}],
                }
            )
        await asyncio.sleep(0.4)
        assert handler._semantic_task is None

    asyncio.run(exercise())


def test_single_document_does_not_scan_parent_directory(tmp_path, monkeypatch):
    path = tmp_path / "opened.py"
    sibling = tmp_path / "unrelated.py"
    sibling.write_text("def unrelated(): pass\n")
    manager = AnalysisManager()
    monkeypatch.setattr(
        manager,
        "_discover_python_files",
        lambda *a: pytest.fail("single document caused recursive scan"),
    )
    asyncio.run(
        LspHandler(manager)._handle_did_open(
            {"textDocument": {"uri": path.as_uri(), "text": "def current(): pass\n", "version": 1}}
        )
    )
    assert {s.name for s in manager.source_index.symbols} == {"current"}
    assert str(sibling) not in manager.source_index.source_files


def test_diagnostics_include_type_undefined_and_security_from_overlay(tmp_path):
    manager, path = source_manager(tmp_path, "value = 1\n")
    text = "import os as command\nvalue: int = 'bad'\ndef run():\n    command.system(input())\n    return missing_name\n"
    manager.open_document(path.as_uri(), text, 1)
    handler = LspHandler(manager)
    result = asyncio.run(
        handler._handle_document_diagnostic({"textDocument": {"uri": path.as_uri()}})
    )
    items = result["items"]
    assert any(item["code"] == "annotation-mismatch" for item in items)
    assert any(
        item["code"] == "undefined-name" and item["range"]["start"]["line"] == 4 for item in items
    )
    assert any(
        item["source"] == "pyflow-security"
        and item["data"]["cwe"] == "CWE-78"
        and item["range"]["start"]["line"] == 3
        for item in items
    )
    assert not any(item["code"] == "analysis-failed" for item in items)
    manager.change_document(path.as_uri(), [{"text": "value = 2\n"}], 2)
    assert (
        asyncio.run(handler._handle_document_diagnostic({"textDocument": {"uri": path.as_uri()}}))[
            "items"
        ]
        == []
    )


def test_rename_updates_exports_but_preserves_explicit_import_alias(tmp_path):
    provider, consumer = tmp_path / "model.py", tmp_path / "main.py"
    index = SourceIndex(
        {
            str(provider): "class Model: pass\n",
            str(consumer): "from model import Model as M\nvalue = M()\n",
        },
        (tmp_path,),
    )
    edits = index.rename_ranges_at(provider.as_uri(), 0, 8)
    assert {(edit.uri, edit.start_line, edit.start_character) for edit in edits} == {
        (provider.as_uri(), 0, 6),
        (consumer.as_uri(), 0, 18),
    }


def test_hover_infers_a_nontrivial_local_expression_at_interior_columns(tmp_path):
    manager, path = source_manager(
        tmp_path, "def f():\n    computed = 1 + 2\n    return computed\n"
    )
    handler = LspHandler(manager)

    async def exercise():
        for column in range(11, 19):
            result = await handler._handle_hover(position(path, 2, column))
            assert "int" in result["contents"]["value"]

    asyncio.run(exercise())


def test_type_query_contains_middle_and_multiline_expression_positions():
    from pyflow.analysis.typeinfo import StaticTypeInferenceEngine

    result = StaticTypeInferenceEngine().infer_source(
        "app", "def f():\n    value = 'text'\n    return (\n        value\n    )\n"
    )
    assert str(result.expression_type(4, 10)) == "str"
    assert result.expression_type(4, 30) is None


def test_partial_receiver_evidence_supports_navigation_but_refuses_rename(tmp_path):
    path = tmp_path / "sample.py"
    source = "class Model:\n    def generate(self): pass\nmodel = Model()\nmodel = unknown_wrapper(model)\nmodel.generate()\n"
    index = SourceIndex({str(path): source}, (tmp_path,))
    assert index.definitions_at(path.as_uri(), 4, 10)[0].start_line == 1
    assert index.incoming_calls("sample.Model.generate")[0][0].name == "sample"
    assert index.rename_ranges_at(path.as_uri(), 1, 10) == []


def test_exit_notification_stops_process_with_stdin_still_open():
    proc = subprocess.Popen(
        [sys.executable, "-m", "pyflow.cli.main", "lsp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        proc.stdin.write(_create_message({"jsonrpc": "2.0", "method": "exit"}))
        proc.stdin.flush()
        assert proc.wait(timeout=3) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate()
