"""Standards-compatible MCP adapter for pyflow semantic queries."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable
from urllib.parse import unquote

from .server import AnalysisManager
from .transport import ErrorCodes, JsonRpcError, JsonRpcServer

LOG = logging.getLogger(__name__)
# Keep protocol negotiation in this adapter.  Query/core code never imports it.
MCP_PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_PROTOCOL_VERSIONS = {
    MCP_PROTOCOL_VERSION,
    "2025-11-25",
    "2025-06-18",
    "2024-11-05",
}


class McpHandler:
    """Expose pyflow resources and tools through the MCP JSON-RPC surface."""

    def __init__(self, server: AnalysisManager):
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
            "notifications/cancelled": self._handle_cancelled,
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

    def _handle_cancelled(self, params: Any) -> None:
        # Queries are currently synchronous and bounded.  The adapter accepts
        # the lifecycle notification now so future cancellable analysis work
        # can be added without changing the query domain.
        return None

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
            value: Any = self._server.current_snapshot().features.__dict__
        elif uri == "pyflow://callgraph":
            self._require_capability("callgraph")
            value = self._server.current_snapshot().queries.call_graph.get_callgraph_data()
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
                "profile": _serialize_profile(
                    self._server.current_snapshot()
                    .queries.test_generation.get_function_test_profile(
                        symbol.qualified_name
                    )
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
        if not isinstance(args, dict):
            return self._tool_error("Tool arguments must be an object")
        snapshot = self._server.current_snapshot()
        dispatch: dict[str, tuple[str | None, tuple[str, ...], Callable[[], Any]]] = {
            "get_callers": (
                "callers",
                ("function",),
                lambda: snapshot.queries.call_graph.get_callers(args["function"]),
            ),
            "get_callees": (
                "callees",
                ("function",),
                lambda: snapshot.queries.call_graph.get_callees(args["function"]),
            ),
            "get_shortest_path": (
                "callgraph",
                ("source", "target"),
                lambda: snapshot.queries.call_graph.get_shortest_path(
                    args["source"], args["target"]
                ),
            ),
            "get_expression_type": (
                "type_info",
                ("module", "line", "column"),
                lambda: _serialize_type(
                    snapshot.queries.type_info.get_expression_type(
                        args["module"], int(args["line"]), int(args["column"])
                    )
                ),
            ),
            "get_function_test_profile": (
                "function_summaries",
                ("function",),
                lambda: _serialize_profile(
                    snapshot.queries.test_generation.get_function_test_profile(
                        args["function"]
                    )
                ),
            ),
            "get_aliases": (
                "aliases",
                ("variable",),
                lambda: _serialize_alias(
                    snapshot.queries.data_flow.get_aliases_for_variable(args["variable"])
                ),
            ),
            "get_cfg_structure": (
                "cfg",
                ("function",),
                lambda: snapshot.queries.control_flow.get_cfg_structure(args["function"]),
            ),
            "search_symbol": (
                None,
                ("query",),
                lambda: _search_symbols(snapshot.source_index, args),
            ),
            "get_symbol": (
                None,
                ("name",),
                lambda: _get_symbol(snapshot.source_index, str(args["name"])),
            ),
            "get_callgraph_neighborhood": (
                "callgraph",
                ("function",),
                lambda: _callgraph_neighborhood(snapshot, args),
            ),
            "get_references": (
                None,
                ("name",),
                lambda: _references(snapshot.source_index, args),
            ),
        }
        entry = dispatch.get(name)
        if entry is None:
            return self._tool_error(f"Unknown tool: {name}")
        capability, required, handler = entry
        missing = [field for field in required if field not in args]
        if missing:
            return self._tool_error(f"Missing required arguments: {', '.join(missing)}")
        if capability and not snapshot.features.supports(capability):
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
            properties: dict[str, dict[str, object]],
            capability: str | None,
            required: tuple[str, ...] | None = None,
        ) -> dict[str, Any]:
            return {
                "name": name,
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "required": list(required or properties),
                    "additionalProperties": False,
                },
                "outputSchema": {"type": ["object", "array", "null"]},
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
                "search_symbol",
                "Search source symbols; results are bounded and cursor-paginated",
                {
                    "query": string,
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                    "cursor": {"type": "integer", "minimum": 0},
                },
                None,
                required=("query",),
            ),
            tool(
                "get_symbol",
                "Get one source symbol by qualified or unambiguous short name",
                {"name": string},
                None,
            ),
            tool(
                "get_callgraph_neighborhood",
                "Bounded callers and callees around a function",
                {
                    "function": string,
                    "depth": {"type": "integer", "minimum": 1, "maximum": 10},
                    "max_nodes": {"type": "integer", "minimum": 1, "maximum": 500},
                },
                "callgraph",
                required=("function",),
            ),
            tool(
                "get_references",
                "Get bounded source references for a symbol",
                {
                    "name": string,
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    "cursor": {"type": "integer", "minimum": 0},
                },
                None,
                required=("name",),
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


def _serialize_type(result: Any) -> Any:
    return {"type": str(result)} if result is not None else None


def _serialize_alias(info: Any) -> dict[str, Any]:
    return {
        "variable": info.variable,
        "aliases": sorted(info.aliases),
        "is_aliased": info.is_aliased,
        "ref_count": info.ref_count,
        "is_escaped": info.is_escaped,
    }


def _serialize_profile(profile: Any) -> dict[str, Any]:
    return {
        "name": profile.name,
        "signature": profile.signature,
        "parameters": profile.parameters,
        "return_type": profile.return_type,
        "calls": profile.calls,
        "called_by": profile.called_by,
        "has_branches": profile.has_branches,
        "has_loops": profile.has_loops,
        "complexity": profile.complexity,
        "external_dependencies": profile.external_dependencies,
    }


def _symbol_data(symbol: Any) -> dict[str, Any]:
    return {
        "name": symbol.name,
        "qualifiedName": symbol.qualified_name,
        "kind": symbol.symbol_id.kind.value,
        "location": symbol.selection_range.location(),
        "symbolId": symbol.symbol_id.to_data(),
    }


def _bounded(value: Any, default: int, maximum: int) -> int:
    try:
        return max(1, min(int(value), maximum))
    except (TypeError, ValueError):
        return default


def _cursor(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _search_symbols(index: Any, args: dict[str, Any]) -> dict[str, Any]:
    limit = _bounded(args.get("limit"), 50, 200)
    cursor = _cursor(args.get("cursor", 0))
    symbols = index.workspace_symbols(str(args["query"]))
    page = symbols[cursor : cursor + limit]
    next_cursor = cursor + len(page)
    return {
        "symbols": [_symbol_data(symbol) for symbol in page],
        "nextCursor": next_cursor if next_cursor < len(symbols) else None,
    }


def _get_symbol(index: Any, name: str) -> dict[str, Any]:
    symbol = index.symbol_by_name(name)
    if symbol is None:
        raise ValueError(f"Unknown symbol: {name}")
    return _symbol_data(symbol)


def _references(index: Any, args: dict[str, Any]) -> dict[str, Any]:
    symbol = index.symbol_by_name(str(args["name"]))
    if symbol is None:
        raise ValueError(f"Unknown symbol: {args['name']}")
    limit = _bounded(args.get("limit"), 100, 500)
    cursor = _cursor(args.get("cursor", 0))
    ranges = [symbol.selection_range] + [
        reference.location
        for reference in index.references
        if reference.symbol_id == symbol.symbol_id
    ]
    page = ranges[cursor : cursor + limit]
    next_cursor = cursor + len(page)
    return {
        "symbol": _symbol_data(symbol),
        "references": [source_range.location() for source_range in page],
        "nextCursor": next_cursor if next_cursor < len(ranges) else None,
    }


def _callgraph_neighborhood(snapshot: Any, args: dict[str, Any]) -> dict[str, Any]:
    depth = _bounded(args.get("depth"), 1, 10)
    max_nodes = _bounded(args.get("max_nodes"), 100, 500)
    function = str(args["function"])
    call_graph = snapshot.queries.call_graph
    callers = call_graph.get_upstream_functions(function, max_depth=depth)
    callees = call_graph.get_downstream_functions(function, max_depth=depth)
    nodes = [function, *callers, *callees]
    unique_nodes = list(dict.fromkeys(nodes))[:max_nodes]
    graph = call_graph.get_callgraph_data()
    return {
        "function": function,
        "depth": depth,
        "nodes": unique_nodes,
        "edges": [
            {"from": caller, "to": callee}
            for caller, targets in graph.items()
            if caller in unique_nodes
            for callee in targets
            if callee in unique_nodes
        ],
        "truncated": len(nodes) > len(unique_nodes),
    }
