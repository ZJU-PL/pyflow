"""Tests for pyflow.lsp.lsp_handler — LSP protocol handler."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

import pytest

from pyflow.lsp import AnalysisManager, LspHandler, JsonRpcServer
from pyflow.lsp.workspace import SourceIndex

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


async def _capture_send_mock(rpc):
    sent = []

    async def capture(payload):
        sent.append(payload)

    rpc._send = capture  # type: ignore[assignment]
    return sent


def _dispatch(rpc, msg):
    sent = _run(_capture_send_mock(rpc))
    _run(rpc._dispatch(msg))
    return sent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_server():
    srv = MagicMock(spec=AnalysisManager)
    srv.is_loaded = True
    snapshot = MagicMock()
    snapshot.semantic_stale = False
    snapshot.require_fresh_semantics.return_value = snapshot
    snapshot.queries.call_graph.get_callers.return_value = ["caller_a"]
    snapshot.queries.call_graph.get_callees.return_value = ["callee_b"]
    snapshot.queries.call_graph.get_callgraph_data.return_value = {"nodes": []}
    snapshot.queries.type_info.get_expression_type.return_value = "int"
    snapshot.queries.data_flow.get_aliases_for_variable.return_value = MagicMock(
        variable="x", aliases=set(), is_aliased=False, ref_count=0, is_escaped=False
    )
    srv.current_snapshot.return_value = snapshot
    srv.supports.return_value = True

    mock_program = MagicMock()
    mock_program.liveCode = []
    type(srv).program = PropertyMock(return_value=mock_program)
    return srv


@pytest.fixture
def handlers(mock_server):
    rpc = JsonRpcServer()
    handler = LspHandler(mock_server)
    handler.register_on(rpc)
    return rpc


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestInitialize:
    def test_registers_standard_call_hierarchy_methods(self, handlers):
        assert "textDocument/prepareCallHierarchy" in handlers._handlers
        assert "callHierarchy/incomingCalls" in handlers._handlers
        assert "callHierarchy/outgoingCalls" in handlers._handlers

    def test_initialize_returns_capabilities(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "initialize",
                "params": {"rootUri": None},
            },
        )
        caps = sent[0].get("result", {}).get("capabilities", {})
        assert caps.get("definitionProvider") is True
        assert caps.get("referencesProvider") is True
        assert caps.get("hoverProvider") is True
        assert caps.get("callHierarchyProvider") is True
        assert caps.get("positionEncoding") == "utf-16"
        assert "typeDefinitionProvider" not in caps
        assert "implementationProvider" not in caps
        assert "signatureHelpProvider" not in caps

    def test_initialize_loads_project_when_root_uri_provided(self, mock_server):
        rpc = JsonRpcServer()
        LspHandler(mock_server).register_on(rpc)
        _dispatch(
            rpc,
            {
                "id": 1,
                "method": "initialize",
                "params": {"rootUri": "file:///tmp/testproj"},
            },
        )
        mock_server.load_workspaces.assert_called_once_with(["/tmp/testproj"])

    def test_workspace_folder_changes_reload_the_updated_root_set(self, mock_server):
        mock_server.workspace_roots = ("/workspace/first",)
        rpc = JsonRpcServer()
        LspHandler(mock_server).register_on(rpc)
        _dispatch(
            rpc,
            {
                "method": "workspace/didChangeWorkspaceFolders",
                "params": {
                    "event": {
                        "added": [{"uri": "file:///workspace/second"}],
                        "removed": [],
                    }
                },
            },
        )
        mock_server.load_workspaces.assert_called_once_with(
            ["/workspace/first", "/workspace/second"]
        )


class TestShutdown:
    def test_shutdown_calls_close(self, handlers):
        mock_srv = handlers._handlers["shutdown"].__self__._server  # noqa
        _dispatch(
            handlers,
            {
                "id": 2,
                "method": "shutdown",
                "params": None,
            },
        )
        assert mock_srv.close.called


# ---------------------------------------------------------------------------
# Handlers that require is_loaded = False
# ---------------------------------------------------------------------------


@pytest.fixture
def unloaded_server():
    srv = MagicMock(spec=AnalysisManager)
    srv.is_loaded = False
    return srv


@pytest.fixture
def unloaded_rpc(unloaded_server):
    r = JsonRpcServer()
    LspHandler(unloaded_server).register_on(r)
    return r


class TestHandlersRejectRequestsWhenUnloaded:
    def test_definition(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "textDocument/definition",
                "params": {
                    "textDocument": {"uri": "file:///a.py"},
                    "position": {"line": 0, "character": 0},
                },
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_references(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "textDocument/references",
                "params": {
                    "textDocument": {"uri": "file:///a.py"},
                    "position": {"line": 0, "character": 0},
                },
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_document_symbol(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "textDocument/documentSymbol",
                "params": {"textDocument": {"uri": "file:///a.py"}},
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_completion(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "textDocument/completion",
                "params": {
                    "textDocument": {"uri": "file:///a.py"},
                    "position": {"line": 0, "character": 0},
                },
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_hover(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "textDocument/hover",
                "params": {
                    "textDocument": {"uri": "file:///a.py"},
                    "position": {"line": 0, "character": 0},
                },
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_call_hierarchy_prepare(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "textDocument/callHierarchy/prepare",
                "params": {
                    "textDocument": {"uri": "file:///a.py"},
                    "position": {"line": 0, "character": 0},
                },
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_workspace_symbol(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "workspace/symbol",
                "params": {"query": "foo"},
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_pyflow_callers(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "pyflow/getCallers",
                "params": {"function": "foo"},
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_pyflow_callees(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "pyflow/getCallees",
                "params": {"function": "foo"},
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_pyflow_callgraph(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "pyflow/getCallgraph",
                "params": {},
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_pyflow_type(self, unloaded_rpc):
        sent = _dispatch(
            unloaded_rpc,
            {
                "id": 1,
                "method": "pyflow/getType",
                "params": {"module": "m", "line": 1, "column": 0},
            },
        )
        assert sent[0]["error"]["code"] == -32600


# ---------------------------------------------------------------------------
# Pyflow custom extensions (loaded server)
# ---------------------------------------------------------------------------


class TestPyflowExtensions:
    def test_get_callers(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "pyflow/getCallers",
                "params": {"function": "foo"},
            },
        )
        assert sent[0]["result"] == ["caller_a"]

    def test_get_callees(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "pyflow/getCallees",
                "params": {"function": "foo"},
            },
        )
        assert sent[0]["result"] == ["callee_b"]

    def test_get_callgraph(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "pyflow/getCallgraph",
                "params": {},
            },
        )
        assert sent[0]["result"] == {"nodes": []}

    def test_get_type(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "pyflow/getType",
                "params": {"module": "m", "line": 1, "column": 0},
            },
        )
        assert sent[0]["result"] == {"type": "int"}

    def test_get_aliases(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "pyflow/getAliases",
                "params": {"variable": "x"},
            },
        )
        assert sent[0]["result"]["variable"] == "x"

    def test_stale_semantic_snapshot_suppresses_hover_and_semantic_queries(
        self, mock_server
    ):
        snapshot = mock_server.current_snapshot.return_value
        snapshot.semantic_stale = True
        snapshot.source_index.module_for_uri.return_value = "m"
        rpc = JsonRpcServer()
        LspHandler(mock_server).register_on(rpc)

        hover = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/hover",
                "params": {
                    "textDocument": {"uri": "file:///sample.py"},
                    "position": {"line": 0, "character": 0},
                },
            },
        )
        callers = _dispatch(
            rpc,
            {
                "id": 2,
                "method": "pyflow/getCallers",
                "params": {"function": "foo"},
            },
        )

        assert hover[0]["result"] is None
        assert callers[0]["error"]["code"] == -32800


def test_semantic_reload_coalesces_edit_bursts(mock_server):
    async def exercise() -> None:
        handler = LspHandler(mock_server)
        for _ in range(20):
            handler._schedule_semantic_reload()
        await asyncio.sleep(0.2)
        assert mock_server.reload.call_count == 1
        assert handler._semantic_task is None

    _run(exercise())


class TestStandardLspExtensions:
    def test_rename_and_diagnostics_use_current_source_snapshot(
        self, mock_server, tmp_path: Path
    ):
        path = tmp_path / "sample.py"
        source = "def target():\n    return target()\n"
        index = SourceIndex({str(path): source}, (tmp_path,))
        snapshot = mock_server.current_snapshot.return_value
        snapshot.source_index = index
        snapshot.revision = 7
        snapshot.source_revision = 3
        rpc = JsonRpcServer()
        LspHandler(mock_server).register_on(rpc)

        prepare = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/prepareRename",
                "params": {
                    "textDocument": {"uri": path.as_uri()},
                    "position": {"line": 1, "character": 11},
                },
            },
        )
        renamed = _dispatch(
            rpc,
            {
                "id": 2,
                "method": "textDocument/rename",
                "params": {
                    "textDocument": {"uri": path.as_uri()},
                    "position": {"line": 1, "character": 11},
                    "newName": "renamed",
                },
            },
        )
        diagnostics = _dispatch(
            rpc,
            {
                "id": 3,
                "method": "textDocument/diagnostic",
                "params": {"textDocument": {"uri": path.as_uri()}},
            },
        )

        assert prepare[0]["result"]["start"]["line"] == 0
        edits = renamed[0]["result"]["changes"][path.as_uri()]
        assert len(edits) == 2
        assert all(edit["newText"] == "renamed" for edit in edits)
        assert diagnostics[0]["result"] == {"kind": "full", "items": [], "resultId": "7:3"}

    def test_rename_lambda_parameter_excludes_shadowed_outer_parameter(
        self, mock_server, tmp_path: Path
    ):
        path = tmp_path / "lambda_scope.py"
        source = (
            "def function(value):\n"
            "    transform = lambda value: value + 1\n"
            "    return value\n"
        )
        snapshot = mock_server.current_snapshot.return_value
        snapshot.source_index = SourceIndex({str(path): source}, (tmp_path,))
        rpc = JsonRpcServer()
        LspHandler(mock_server).register_on(rpc)

        renamed = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/rename",
                "params": {
                    "textDocument": {"uri": path.as_uri()},
                    "position": {"line": 1, "character": 24},
                    "newName": "item",
                },
            },
        )

        edits = renamed[0]["result"]["changes"][path.as_uri()]
        positions = {
            (
                edit["range"]["start"]["line"],
                edit["range"]["start"]["character"],
            )
            for edit in edits
        }
        assert positions == {(1, 23), (1, 30)}
