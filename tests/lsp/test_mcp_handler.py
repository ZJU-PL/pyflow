"""Tests for pyflow.lsp.mcp_handler — MCP protocol adapter."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest

from pyflow.lsp import AnalysisManager, McpHandler, JsonRpcServer
from pyflow.lsp.mcp_handler import LEGACY_PROTOCOL_VERSION, MCP_PROTOCOL_VERSION

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
    # Historical fixture payloads used the experimental dotted spelling. Keep
    # test fixtures focused on the standard registered endpoints rather than
    # retaining that alias in production.
    method = msg.get("method", "")
    standard_methods = {
        "mcp.initialize": "initialize",
        "mcp.resources.list": "resources/list",
        "mcp.resources.read": "resources/read",
        "mcp.tools.list": "tools/list",
        "mcp.tools.call": "tools/call",
    }
    if method in standard_methods:
        msg = {**msg, "method": standard_methods[method]}
    sent = _run(_capture_send_mock(rpc))
    _run(rpc._dispatch(msg))
    return sent


def _modern_meta() -> dict[str, dict[str, object]]:
    return {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_server():
    srv = MagicMock(spec=AnalysisManager)
    type(srv).is_loaded = PropertyMock(return_value=True)

    snapshot = MagicMock()
    snapshot.semantic_stale = False
    snapshot.require_fresh_semantics.return_value = snapshot
    snapshot.features = MagicMock()
    snapshot.features.supports.return_value = True
    snapshot.features.__dict__.update(
        call_graph=True,
        control_flow=True,
        cpa=True,
        lifetime=True,
        heap=True,
        type_info=True,
    )
    snapshot.queries.call_graph.get_callgraph_data.return_value = {"nodes": ["a"], "edges": []}
    snapshot.queries.call_graph.get_callers.return_value = ["caller1"]
    snapshot.queries.call_graph.get_callees.return_value = ["callee1"]
    snapshot.queries.call_graph.get_shortest_path.return_value = ["a", "b"]
    snapshot.queries.type_info.get_expression_type.return_value = "int"
    snapshot.queries.test_generation.get_function_test_profile.return_value = SimpleNamespace(
        name="f", signature="()", parameters=[], return_type="int", calls=[],
        called_by=[], has_branches=False, has_loops=False, complexity=1,
        external_dependencies=[],
    )
    snapshot.queries.data_flow.get_aliases_for_variable.return_value = SimpleNamespace(
        variable="x", aliases=set(), is_aliased=False, ref_count=0, is_escaped=False
    )
    snapshot.queries.control_flow.get_cfg_structure.return_value = {"nodes": []}
    srv.current_snapshot.return_value = snapshot
    srv.supports.return_value = True

    mock_program = MagicMock()
    mock_program.liveCode = []
    type(srv).program = PropertyMock(return_value=mock_program)
    return srv


@pytest.fixture
def handlers(mock_server):
    rpc = JsonRpcServer()
    McpHandler(mock_server).register_on(rpc)
    _dispatch(rpc, {"id": 0, "method": "initialize", "params": {}})
    _dispatch(rpc, {"method": "notifications/initialized", "params": {}})
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
        assert "server/discover" in handlers._handlers

    def test_initialize_returns_protocol_version_and_capabilities(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "initialize",
                "params": {},
            },
        )
        result = sent[0]["result"]
        assert "protocolVersion" in result
        assert "capabilities" in result
        assert "serverInfo" in result
        assert result["serverInfo"]["name"] == "pyflow"

    def test_modern_requests_use_discovery_and_legacy_initialize(self, handlers):
        modern = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
        )
        legacy = _dispatch(
            handlers,
            {
                "id": 2,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            },
        )
        result = modern[0]["result"]
        assert result["resultType"] == "complete"
        assert result["supportedVersions"] == [MCP_PROTOCOL_VERSION]
        assert result["ttlMs"] > 0
        assert result["cacheScope"] == "private"
        assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "pyflow"
        assert legacy[0]["result"]["protocolVersion"] == LEGACY_PROTOCOL_VERSION

    def test_legacy_queries_require_initialized_notification(self, mock_server):
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        initialized = _dispatch(
            rpc, {"id": 1, "method": "initialize", "params": {}}
        )
        before_ready = _dispatch(
            rpc, {"id": 2, "method": "tools/list", "params": {}}
        )
        _dispatch(rpc, {"method": "notifications/initialized", "params": {}})
        after_ready = _dispatch(
            rpc, {"id": 3, "method": "tools/list", "params": {}}
        )

        assert initialized[0]["result"]["protocolVersion"] == LEGACY_PROTOCOL_VERSION
        assert before_ready[0]["error"]["code"] == -32600
        assert "tools" in after_ready[0]["result"]

    def test_modern_initialize_is_rejected(self, handlers):
        sent = _dispatch(
            handlers,
            {
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
            },
        )
        assert sent[0]["error"]["code"] == -32022
        assert sent[0]["error"]["data"] == {
            "requested": MCP_PROTOCOL_VERSION,
            "supported": [MCP_PROTOCOL_VERSION],
        }

    def test_modern_requests_validate_metadata_and_exact_version(self, mock_server):
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        missing_capabilities = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION
                    }
                },
            },
        )
        future_version = _dispatch(
            rpc,
            {
                "id": 2,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2030-01-01",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
        )

        assert missing_capabilities[0]["error"]["code"] == -32602
        assert future_version[0]["error"]["code"] == -32022

    def test_uninitialized_request_without_modern_metadata_is_rejected(self, mock_server):
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        sent = _dispatch(
            rpc,
            {"id": 1, "method": "tools/list", "params": {}},
        )
        assert sent[0]["error"]["code"] == -32600


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

    def test_read_resource_uses_one_pinned_snapshot(self, mock_server):
        snapshot = mock_server.current_snapshot.return_value
        mock_server.current_snapshot.reset_mock()
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        _dispatch(rpc, {"id": 0, "method": "initialize", "params": {}})
        _dispatch(rpc, {"method": "notifications/initialized", "params": {}})

        sent = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "resources/read",
                "params": {"uri": "pyflow://capabilities"},
            },
        )

        assert "contents" in sent[0]["result"]
        assert mock_server.current_snapshot.call_count == 1
        assert mock_server.current_snapshot.return_value is snapshot

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
        mock_server.current_snapshot.return_value.features.supports.side_effect = (
            lambda capability: capability != "aliases"
        )
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        _dispatch(rpc, {"id": 0, "method": "initialize", "params": {}})
        _dispatch(rpc, {"method": "notifications/initialized", "params": {}})
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
        assert {
            "search_symbol",
            "get_symbol",
            "get_callgraph_neighborhood",
            "get_references",
        } <= set(names)
        assert all("outputSchema" in tool for tool in tools)

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
        mock_server.current_snapshot.return_value.queries.call_graph.get_callers.side_effect = (
            ValueError("boom")
        )
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        _dispatch(rpc, {"id": 0, "method": "initialize", "params": {}})
        _dispatch(rpc, {"method": "notifications/initialized", "params": {}})
        sent = _dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "get_callers", "arguments": {"function": "f"}},
            },
        )
        assert sent[0]["result"]["isError"] is True

    def test_modern_results_are_complete_and_arrays_are_structured(self, handlers):
        params = {
            "name": "get_callers",
            "arguments": {"function": "foo"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        }
        sent = _dispatch(
            handlers,
            {"id": 1, "method": "tools/call", "params": params},
        )
        result = sent[0]["result"]
        assert result["resultType"] == "complete"
        assert result["structuredContent"] == ["caller1"]

    def test_modern_resource_results_are_complete(self, handlers):
        endpoints = [
            ("tools/list", {}),
            ("resources/list", {}),
            ("resources/templates/list", {}),
            ("resources/read", {"uri": "pyflow://capabilities"}),
        ]
        for request_id, (method, extra) in enumerate(endpoints, start=1):
            sent = _dispatch(
                handlers,
                {
                    "id": request_id,
                    "method": method,
                    "params": {**extra, **_modern_meta()},
                },
            )
            result = sent[0]["result"]
            assert result["resultType"] == "complete"
            assert result["ttlMs"] == (0 if method == "resources/read" else 60_000)
            assert result["cacheScope"] == "private"
            assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "pyflow"

    def test_stale_snapshot_keeps_tools_stable_and_rejects_semantic_calls(
        self, mock_server
    ):
        mock_server.current_snapshot.return_value.semantic_stale = True
        rpc = JsonRpcServer()
        McpHandler(mock_server).register_on(rpc)
        _dispatch(rpc, {"id": 0, "method": "initialize", "params": {}})
        _dispatch(rpc, {"method": "notifications/initialized", "params": {}})

        listed = _dispatch(
            rpc,
            {"id": 1, "method": "tools/list", "params": {}},
        )
        called = _dispatch(
            rpc,
            {
                "id": 2,
                "method": "tools/call",
                "params": {"name": "get_callers", "arguments": {"function": "foo"}},
            },
        )

        names = {tool["name"] for tool in listed[0]["result"]["tools"]}
        assert "get_callers" in names
        assert called[0]["result"]["isError"] is True
