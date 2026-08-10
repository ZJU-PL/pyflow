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


class TestStandardLspExtensions:
    def test_rename_and_diagnostics_use_current_source_snapshot(
        self, mock_server, tmp_path: Path
    ):
        path = tmp_path / "sample.py"
        source = "def target():\n    return target()\n"
        index = SourceIndex({str(path): source}, str(tmp_path))
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
