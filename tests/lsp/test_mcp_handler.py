"""Tests for pyflow.lsp.mcp_handler — MCP protocol adapter."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, PropertyMock

import pytest

from pyflow.lsp import McpHandler, JsonRpcServer, PyflowAnalysisServer

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
    srv = MagicMock(spec=PyflowAnalysisServer)
    type(srv).is_loaded = PropertyMock(return_value=True)

    srv.get_capabilities.return_value = {"callgraph": True}
    srv.get_callgraph_data.return_value = {"nodes": ["a"], "edges": []}
    srv.get_callers.return_value = ["caller1"]
    srv.get_callees.return_value = ["callee1"]
    srv.get_shortest_path.return_value = ["a", "b"]
    srv.get_expression_type.return_value = {"type": "int"}
    srv.get_function_test_profile.return_value = {
        "name": "f",
        "complexity": 1,
    }
    srv.get_aliases_for_variable.return_value = {"variable": "x", "aliases": []}
    srv.get_cfg_structure.return_value = {"nodes": []}

    mock_program = MagicMock()
    mock_program.liveCode = []
    type(srv).program = PropertyMock(return_value=mock_program)
    return srv


@pytest.fixture
def handlers(mock_server):
    rpc = JsonRpcServer()
    McpHandler(mock_server).register_on(rpc)
    return rpc


# ---------------------------------------------------------------------------
# MCP Lifecycle
# ---------------------------------------------------------------------------


class TestInitialize:
    def test_registers_standard_mcp_method_names(self, handlers):
        assert "initialize" in handlers._handlers
        assert "resources/list" in handlers._handlers
        assert "resources/read" in handlers._handlers
        assert "tools/list" in handlers._handlers
        assert "tools/call" in handlers._handlers

    def test_initialize_returns_protocol_version_and_capabilities(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.initialize",
                "params": {},
            },
        )
        result = sent[0]["result"]
        assert "protocolVersion" in result
        assert "capabilities" in result
        assert "serverInfo" in result
        assert result["serverInfo"]["name"] == "pyflow"


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


class TestResources:
    def test_lists_function_resource_template(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "resources/templates/list",
                "params": {},
            },
        )
        templates = sent[0]["result"]["resourceTemplates"]
        assert templates[0]["uriTemplate"] == "pyflow://function/{name}"

    def test_list_resources_returns_resource_list(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.resources.list",
                "params": {},
            },
        )
        resources = sent[0]["result"]["resources"]
        assert len(resources) == 3
        uris = [r["uri"] for r in resources]
        assert "pyflow://capabilities" in uris
        assert "pyflow://callgraph" in uris
        assert "pyflow://functions" in uris

    def test_read_resource_capabilities(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.resources.read",
                "params": {"uri": "pyflow://capabilities"},
            },
        )
        assert "contents" in sent[0]["result"]
        assert sent[0]["result"]["contents"][0]["uri"] == "pyflow://capabilities"
        assert sent[0]["result"]["contents"][0]["mimeType"] == "application/json"

    def test_read_resource_callgraph(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.resources.read",
                "params": {"uri": "pyflow://callgraph"},
            },
        )
        assert sent[0]["result"]["contents"][0]["uri"] == "pyflow://callgraph"

    def test_read_resource_functions(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.resources.read",
                "params": {"uri": "pyflow://functions"},
            },
        )
        assert sent[0]["result"]["contents"][0]["uri"] == "pyflow://functions"

    def test_read_resource_unknown_returns_error(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.resources.read",
                "params": {"uri": "pyflow://unknown"},
            },
        )
        assert sent[0]["error"]["code"] == -32602

    def test_read_resource_returns_error_when_not_loaded(self, mock_server):
        type(mock_server).is_loaded = PropertyMock(return_value=False)
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        sent = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.resources.read",
                "params": {"uri": "pyflow://capabilities"},
            },
        )
        assert sent[0]["error"]["code"] == -32600


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


class TestTools:
    def test_list_tools_filters_unavailable_capabilities(self, mock_server):
        mock_server.supports.side_effect = lambda capability: capability != "aliases"
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        sent = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "tools/list",
                "params": {},
            },
        )
        names = {tool["name"] for tool in sent[0]["result"]["tools"]}
        assert "get_aliases" not in names
        assert "get_callers" in names

    def test_list_tools_returns_tool_list(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.tools.list",
                "params": {},
            },
        )
        tools = sent[0]["result"]["tools"]
        names = [t["name"] for t in tools]
        assert "get_callers" in names
        assert "get_callees" in names
        assert "get_shortest_path" in names
        assert "get_expression_type" in names
        assert "get_function_test_profile" in names
        assert "get_aliases" in names
        assert "get_cfg_structure" in names

    def test_call_tool_get_callers(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "get_callers", "arguments": {"function": "foo"}},
            },
        )
        text = sent[0]["result"]["content"][0]["text"]
        assert "caller1" in text

    def test_call_tool_get_callees(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "get_callees", "arguments": {"function": "foo"}},
            },
        )
        text = sent[0]["result"]["content"][0]["text"]
        assert "callee1" in text

    def test_call_tool_get_shortest_path(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {
                    "name": "get_shortest_path",
                    "arguments": {"source": "a", "target": "z"},
                },
            },
        )
        assert sent[0]["result"]["content"][0]["text"] is not None

    def test_call_tool_get_expression_type(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {
                    "name": "get_expression_type",
                    "arguments": {"module": "m", "line": 1, "column": 0},
                },
            },
        )
        assert "int" in sent[0]["result"]["content"][0]["text"]

    def test_call_tool_get_function_test_profile(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {
                    "name": "get_function_test_profile",
                    "arguments": {"function": "f"},
                },
            },
        )
        assert "complexity" in sent[0]["result"]["content"][0]["text"]

    def test_call_tool_get_aliases(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "get_aliases", "arguments": {"variable": "x"}},
            },
        )
        assert "x" in sent[0]["result"]["content"][0]["text"]

    def test_call_tool_get_cfg_structure(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {
                    "name": "get_cfg_structure",
                    "arguments": {"function": "foo"},
                },
            },
        )
        assert "nodes" in sent[0]["result"]["content"][0]["text"]

    def test_call_tool_unknown_returns_error(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "unknown_tool", "arguments": {}},
            },
        )
        assert sent[0]["result"]["isError"] is True

    def test_call_tool_returns_error_when_not_loaded(self, mock_server):
        type(mock_server).is_loaded = PropertyMock(return_value=False)
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        sent = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "get_callers", "arguments": {"function": "f"}},
            },
        )
        assert sent[0]["error"]["code"] == -32600

    def test_call_tool_returns_error_on_exception(self, mock_server):
        mock_server.get_callers.side_effect = ValueError("boom")
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        sent = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "get_callers", "arguments": {"function": "f"}},
            },
        )
        assert sent[0]["result"]["isError"] is True
