"""
MCP (Model Context Protocol) adapter for pyflow.

MCP is a lightweight protocol for LLM agents to query analysis results.
It reuses the same JSON-RPC 2.0 transport layer and exposes pyflow's
analysis capabilities as MCP resources and tools.

Resources:
  - pyflow://capabilities          → server capabilities
  - pyflow://callgraph             → full call graph
  - pyflow://functions             → list of known functions
  - pyflow://function/{name}       → function details

Tools:
  - get_callers(function)
  - get_callees(function)
  - get_shortest_path(source, target)
  - get_expression_type(module, line, column)
  - get_function_test_profile(function)
  - get_aliases(variable)
  - get_cfg_structure(function)
"""

import logging
from typing import Any, Optional

from .transport import JsonRpcServer
from .server import PyflowAnalysisServer

LOG = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2024-11-05"


class McpHandler:
    """Bridges pyflow's analysis to the Model Context Protocol.

    Registers MCP methods on a ``JsonRpcServer`` so that LLM agents
    can discover and query pyflow's analysis results.
    """

    def __init__(self, server: PyflowAnalysisServer):
        self._server = server

    def register_on(self, rpc: JsonRpcServer) -> None:
        rpc.register("mcp.initialize", self._handle_initialize)

        # Resource discovery
        rpc.register("mcp.resources.list", self._handle_list_resources)
        rpc.register("mcp.resources.read", self._handle_read_resource)

        # Tool discovery
        rpc.register("mcp.tools.list", self._handle_list_tools)
        rpc.register("mcp.tools.call", self._handle_call_tool)

    # ------------------------------------------------------------------
    # MCP Lifecycle
    # ------------------------------------------------------------------

    def _handle_initialize(self, params: Any) -> dict[str, Any]:
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "resources": {},
                "tools": {},
            },
            "serverInfo": {
                "name": "pyflow",
                "version": self._version(),
            },
        }

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    def _handle_list_resources(self, params: Any) -> dict[str, Any]:
        return {
            "resources": [
                {
                    "uri": "pyflow://capabilities",
                    "name": "Server Capabilities",
                    "description": "List available analysis capabilities",
                },
                {
                    "uri": "pyflow://callgraph",
                    "name": "Call Graph",
                    "description": "Full call graph as adjacency data",
                },
                {
                    "uri": "pyflow://functions",
                    "name": "Function List",
                    "description": "All known functions from analysis",
                },
            ]
        }

    def _handle_read_resource(self, params: Any) -> Optional[dict[str, Any]]:
        uri = (params or {}).get("uri", "")
        if not self._server.is_loaded:
            return self._error("Server not loaded")

        if uri == "pyflow://capabilities":
            return {"contents": [
                {"uri": uri, "text": str(self._server.get_capabilities())}
            ]}
        if uri == "pyflow://callgraph":
            return {"contents": [
                {"uri": uri, "text": str(self._server.get_callgraph_data())}
            ]}
        if uri == "pyflow://functions":
            funcs = list(getattr(self._server.program, "liveCode", []))
            names = []
            for code in funcs:
                n = getattr(code, "codeName", None)
                names.append(n() if callable(n) else str(n) if n else "?")
            return {"contents": [
                {"uri": uri, "text": "\n".join(sorted(names))}
            ]}
        return self._error(f"Unknown resource: {uri}")

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def _handle_list_tools(self, params: Any) -> dict[str, Any]:
        return {
            "tools": [
                {
                    "name": "get_callers",
                    "description": "List functions that call the given function",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "function": {"type": "string"}
                        },
                        "required": ["function"],
                    },
                },
                {
                    "name": "get_callees",
                    "description": "List functions called by the given function",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "function": {"type": "string"}
                        },
                        "required": ["function"],
                    },
                },
                {
                    "name": "get_shortest_path",
                    "description": "Shortest call path between two functions",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "source": {"type": "string"},
                            "target": {"type": "string"},
                        },
                        "required": ["source", "target"],
                    },
                },
                {
                    "name": "get_expression_type",
                    "description": "Inferred type at a source position",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "module": {"type": "string"},
                            "line": {"type": "integer"},
                            "column": {"type": "integer"},
                        },
                        "required": ["module", "line", "column"],
                    },
                },
                {
                    "name": "get_function_test_profile",
                    "description": "Test profile for a function",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "function": {"type": "string"}
                        },
                        "required": ["function"],
                    },
                },
                {
                    "name": "get_aliases",
                    "description": "Alias information for a variable",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "variable": {"type": "string"}
                        },
                        "required": ["variable"],
                    },
                },
                {
                    "name": "get_cfg_structure",
                    "description": "CFG structure for a function",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "function": {"type": "string"}
                        },
                        "required": ["function"],
                    },
                },
            ]
        }

    def _handle_call_tool(self, params: Any) -> dict[str, Any]:
        if not self._server.is_loaded:
            return self._error("Server not loaded")

        name = (params or {}).get("name", "")
        args = (params or {}).get("arguments", {}) or {}

        tool_map = {
            "get_callers": lambda: self._server.get_callers(
                args.get("function", "")),
            "get_callees": lambda: self._server.get_callees(
                args.get("function", "")),
            "get_shortest_path": lambda: self._server.get_shortest_path(
                args.get("source", ""), args.get("target", "")),
            "get_expression_type": lambda: self._server.get_expression_type(
                args.get("module", ""),
                args.get("line", 0),
                args.get("column", 0),
            ),
            "get_function_test_profile": lambda: self._server.get_function_test_profile(
                args.get("function", "")),
            "get_aliases": lambda: self._server.get_aliases_for_variable(
                args.get("variable", "")),
            "get_cfg_structure": lambda: self._server.get_cfg_structure(
                args.get("function", "")),
        }

        handler = tool_map.get(name)
        if handler is None:
            return self._error(f"Unknown tool: {name}")

        try:
            result = handler()
            return {"content": [
                {"type": "text", "text": str(result)}
            ]}
        except Exception as exc:
            LOG.exception("Tool %s failed", name)
            return self._error(str(exc))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _error(msg: str) -> dict[str, Any]:
        return {"isError": True, "content": [{"type": "text", "text": msg}]}

    @staticmethod
    def _version() -> str:
        try:
            from pyflow import __version__
            return __version__
        except ImportError:
            return "0.0.0"
