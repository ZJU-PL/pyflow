"""Standards-compatible MCP adapter for pyflow semantic queries."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable
from urllib.parse import unquote

from .server import PyflowAnalysisServer
from .transport import ErrorCodes, JsonRpcError, JsonRpcServer

LOG = logging.getLogger(__name__)
MCP_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = {MCP_PROTOCOL_VERSION, "2024-11-05"}


class McpHandler:
    """Expose pyflow resources and tools through the MCP JSON-RPC surface."""

    def __init__(self, server: PyflowAnalysisServer):
        self._server = server
        self._initialized = False

    def register_on(self, rpc: JsonRpcServer) -> None:
        methods = {
            "initialize": self._handle_initialize,
            "notifications/initialized": self._handle_initialized,
            "resources/list": self._handle_list_resources,
            "resources/templates/list": self._handle_list_resource_templates,
            "resources/read": self._handle_read_resource,
            "tools/list": self._handle_list_tools,
            "tools/call": self._handle_call_tool,
        }
        for name, handler in methods.items():
            if name.startswith("notifications/"):
                rpc.register_notification(name, handler)
            else:
                rpc.register(name, handler)

        # Compatibility aliases used by the original experimental adapter.
        for name, handler in methods.items():
            if name == "notifications/initialized":
                continue
            rpc.register(f"mcp.{name.replace('/', '.')}", handler)

    def _handle_initialize(self, params: Any) -> dict[str, Any]:
        requested = (params or {}).get("protocolVersion")
        version = (
            requested
            if requested in SUPPORTED_PROTOCOL_VERSIONS
            else MCP_PROTOCOL_VERSION
        )
        return {
            "protocolVersion": version,
            "capabilities": {"resources": {}, "tools": {"listChanged": False}},
            "serverInfo": {"name": "pyflow", "version": self._version()},
            "instructions": (
                "Query pyflow's static-analysis snapshot. Function names may be "
                "qualified; inspect pyflow://functions before graph queries."
            ),
        }

    def _handle_initialized(self, params: Any) -> None:
        self._initialized = True

    def _handle_list_resources(self, params: Any) -> dict[str, Any]:
        resources = [
            {
                "uri": "pyflow://capabilities",
                "name": "Server Capabilities",
                "description": "Available analysis capabilities and server mode",
                "mimeType": "application/json",
            },
            {
                "uri": "pyflow://functions",
                "name": "Function List",
                "description": "Source-indexed functions and methods",
                "mimeType": "application/json",
            },
        ]
        if self._server.is_loaded and self._server.supports("callgraph"):
            resources.append(
                {
                    "uri": "pyflow://callgraph",
                    "name": "Call Graph",
                    "description": "Full call graph as adjacency data",
                    "mimeType": "application/json",
                }
            )
        return {"resources": resources}

    def _handle_list_resource_templates(self, params: Any) -> dict[str, Any]:
        return {
            "resourceTemplates": [
                {
                    "uriTemplate": "pyflow://function/{name}",
                    "name": "Function Details",
                    "description": (
                        "Source location and analysis profile for a function"
                    ),
                    "mimeType": "application/json",
                }
            ]
        }

    def _handle_read_resource(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        uri = (params or {}).get("uri", "")
        if uri == "pyflow://capabilities":
            value: Any = self._server.get_capabilities()
        elif uri == "pyflow://callgraph":
            self._require_capability("callgraph")
            value = self._server.get_callgraph_data()
        elif uri == "pyflow://functions":
            value = [
                {
                    "name": symbol.name,
                    "qualifiedName": symbol.qualified_name,
                    "uri": symbol.full_range.uri,
                    "range": symbol.full_range.to_lsp(),
                }
                for symbol in self._server.source_index.symbols
                if symbol.kind in {6, 12}
            ]
        elif uri.startswith("pyflow://function/"):
            name = unquote(uri.removeprefix("pyflow://function/"))
            symbol = self._server.source_index.symbol_by_name(name)
            if symbol is None:
                raise JsonRpcError(
                    ErrorCodes.InvalidParams, f"Unknown function: {name}"
                )
            value = {
                "name": symbol.name,
                "qualifiedName": symbol.qualified_name,
                "location": symbol.selection_range.location(),
                "profile": self._server.get_function_test_profile(
                    symbol.qualified_name
                ),
            }
        else:
            raise JsonRpcError(ErrorCodes.InvalidParams, f"Unknown resource: {uri}")
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(value, default=str, sort_keys=True),
                }
            ]
        }

    def _handle_list_tools(self, params: Any) -> dict[str, Any]:
        tools = []
        for spec in self._tool_specs():
            capability = spec.pop("_capability")
            if capability is None or (
                self._server.is_loaded and self._server.supports(capability)
            ):
                tools.append(spec)
        return {"tools": tools}

    def _handle_call_tool(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        name = (params or {}).get("name", "")
        args = (params or {}).get("arguments", {}) or {}
        dispatch: dict[str, tuple[str | None, tuple[str, ...], Callable[[], Any]]] = {
            "get_callers": (
                "callers",
                ("function",),
                lambda: self._server.get_callers(args["function"]),
            ),
            "get_callees": (
                "callees",
                ("function",),
                lambda: self._server.get_callees(args["function"]),
            ),
            "get_shortest_path": (
                "callgraph",
                ("source", "target"),
                lambda: self._server.get_shortest_path(args["source"], args["target"]),
            ),
            "get_expression_type": (
                "type_info",
                ("module", "line", "column"),
                lambda: self._server.get_expression_type(
                    args["module"], int(args["line"]), int(args["column"])
                ),
            ),
            "get_function_test_profile": (
                "function_summaries",
                ("function",),
                lambda: self._server.get_function_test_profile(args["function"]),
            ),
            "get_aliases": (
                "aliases",
                ("variable",),
                lambda: self._server.get_aliases_for_variable(args["variable"]),
            ),
            "get_cfg_structure": (
                "cfg",
                ("function",),
                lambda: self._server.get_cfg_structure(args["function"]),
            ),
        }
        entry = dispatch.get(name)
        if entry is None:
            return self._tool_error(f"Unknown tool: {name}")
        capability, required, handler = entry
        missing = [field for field in required if field not in args]
        if missing:
            return self._tool_error(f"Missing required arguments: {', '.join(missing)}")
        if capability and not self._server.supports(capability):
            return self._tool_error(
                f"Tool {name} is unavailable in {self._server.server_mode.value} mode"
            )
        try:
            result = handler()
        except Exception as exc:
            LOG.exception("Tool %s failed", name)
            return self._tool_error(str(exc))
        response = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, default=str, sort_keys=True),
                }
            ],
            "isError": False,
        }
        if isinstance(result, dict):
            response["structuredContent"] = result
        return response

    def _tool_specs(self) -> list[dict[str, Any]]:
        def tool(
            name: str,
            description: str,
            properties: dict[str, dict[str, str]],
            capability: str | None,
        ) -> dict[str, Any]:
            return {
                "name": name,
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "required": list(properties),
                    "additionalProperties": False,
                },
                "_capability": capability,
            }

        string = {"type": "string"}
        integer = {"type": "integer"}
        return [
            tool(
                "get_callers",
                "List callers of a function",
                {"function": string},
                "callers",
            ),
            tool(
                "get_callees",
                "List callees of a function",
                {"function": string},
                "callees",
            ),
            tool(
                "get_shortest_path",
                "Shortest call path between two functions",
                {"source": string, "target": string},
                "callgraph",
            ),
            tool(
                "get_expression_type",
                "Inferred type at a one-based source line and UTF-8 byte column",
                {"module": string, "line": integer, "column": integer},
                "type_info",
            ),
            tool(
                "get_function_test_profile",
                "Analysis-derived test profile for a function",
                {"function": string},
                "function_summaries",
            ),
            tool(
                "get_aliases",
                "Alias information for a variable",
                {"variable": string},
                "aliases",
            ),
            tool(
                "get_cfg_structure",
                "CFG structure for a function",
                {"function": string},
                "cfg",
            ),
        ]

    def _require_loaded(self) -> None:
        if not self._server.is_loaded:
            raise JsonRpcError(ErrorCodes.InvalidRequest, "Workspace is not loaded")

    def _require_capability(self, capability: str) -> None:
        if not self._server.supports(capability):
            raise JsonRpcError(
                ErrorCodes.InvalidRequest,
                (
                    f"Capability {capability} is unavailable in "
                    f"{self._server.server_mode.value} mode"
                ),
            )

    @staticmethod
    def _tool_error(message: str) -> dict[str, Any]:
        return {
            "isError": True,
            "content": [{"type": "text", "text": message}],
        }

    @staticmethod
    def _version() -> str:
        try:
            from pyflow import __version__

            return __version__
        except ImportError:
            return "0.0.0"


__all__ = ["MCP_PROTOCOL_VERSION", "McpHandler"]
