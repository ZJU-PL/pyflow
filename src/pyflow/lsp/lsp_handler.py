"""Language Server Protocol adapter for pyflow analysis snapshots."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Optional

from .server import PyflowAnalysisServer
from .transport import ErrorCodes, JsonRpcError, JsonRpcServer
from .workspace import SourceSymbol, uri_to_path

LOG = logging.getLogger(__name__)


class LspHandler:
    """Translate source-oriented LSP requests into pyflow queries."""

    def __init__(self, server: PyflowAnalysisServer):
        self._server = server
        self._capabilities: dict[str, Any] = {}
        self._shutdown = False

    def register_on(self, rpc: JsonRpcServer) -> None:
        rpc.register("initialize", self._handle_initialize)
        rpc.register("shutdown", self._handle_shutdown)
        rpc.register_notification("initialized", self._handle_initialized)
        rpc.register_notification("exit", self._handle_exit)

        rpc.register_notification("textDocument/didOpen", self._handle_did_open)
        rpc.register_notification("textDocument/didChange", self._handle_did_change)
        rpc.register_notification("textDocument/didClose", self._handle_did_close)

        rpc.register("textDocument/definition", self._handle_definition)
        rpc.register("textDocument/references", self._handle_references)
        rpc.register("textDocument/documentSymbol", self._handle_document_symbol)
        rpc.register("textDocument/completion", self._handle_completion)
        rpc.register("textDocument/hover", self._handle_hover)
        rpc.register(
            "textDocument/prepareCallHierarchy", self._handle_call_hierarchy_prepare
        )
        rpc.register(
            "callHierarchy/incomingCalls", self._handle_call_hierarchy_incoming
        )
        rpc.register(
            "callHierarchy/outgoingCalls", self._handle_call_hierarchy_outgoing
        )

        # Compatibility aliases for the early experimental protocol.
        rpc.register(
            "textDocument/callHierarchy/prepare", self._handle_call_hierarchy_prepare
        )
        rpc.register(
            "textDocument/callHierarchy/incomingCalls",
            self._handle_call_hierarchy_incoming,
        )
        rpc.register(
            "textDocument/callHierarchy/outgoingCalls",
            self._handle_call_hierarchy_outgoing,
        )

        rpc.register("workspace/symbol", self._handle_workspace_symbol)
        rpc.register("pyflow/getCallers", self._handle_pyflow_callers)
        rpc.register("pyflow/getCallees", self._handle_pyflow_callees)
        rpc.register("pyflow/getCallgraph", self._handle_pyflow_callgraph)
        rpc.register("pyflow/getType", self._handle_pyflow_type)
        rpc.register("pyflow/getAliases", self._handle_pyflow_aliases)

    async def _handle_initialize(self, params: Any) -> dict[str, Any]:
        if self._shutdown:
            raise JsonRpcError(ErrorCodes.InvalidRequest, "Server has shut down")
        params = params or {}
        root_uri = params.get("rootUri")
        if not root_uri:
            folders = params.get("workspaceFolders") or []
            root_uri = folders[0].get("uri") if folders else None
        if root_uri:
            root_path = uri_to_path(root_uri)
            try:
                if not self._server.is_loaded or self._server.root_path != root_path:
                    await asyncio.to_thread(self._server.load, root_path)
            except Exception as exc:
                raise JsonRpcError(
                    ErrorCodes.InternalError,
                    f"Unable to analyze workspace: {exc}",
                ) from exc

        self._capabilities = {
            "positionEncoding": "utf-16",
            "textDocumentSync": {"openClose": True, "change": 1, "save": False},
            "definitionProvider": True,
            "referencesProvider": True,
            "documentSymbolProvider": True,
            "completionProvider": {
                "triggerCharacters": ["."],
                "resolveProvider": False,
            },
            "hoverProvider": bool(
                self._server.is_loaded and self._server.supports("type_info")
            ),
            "callHierarchyProvider": True,
            "workspaceSymbolProvider": True,
        }
        return {
            "capabilities": self._capabilities,
            "serverInfo": {"name": "pyflow", "version": self._version()},
        }

    def _handle_initialized(self, params: Any) -> None:
        return None

    def _handle_shutdown(self, params: Any) -> None:
        self._shutdown = True
        self._server.close()
        return None

    def _handle_exit(self, params: Any) -> None:
        self._server.close()

    async def _handle_did_open(self, params: Any) -> None:
        document = (params or {}).get("textDocument", {})
        uri = document.get("uri")
        text = document.get("text")
        if not uri or text is None:
            return
        self._server.open_document(uri, text, document.get("version"))
        if self._server.is_loaded:
            await asyncio.to_thread(self._server.reload)
        else:
            await asyncio.to_thread(
                self._server.load, str(Path(uri_to_path(uri)).parent)
            )

    async def _handle_did_change(self, params: Any) -> None:
        params = params or {}
        document = params.get("textDocument", {})
        changes = params.get("contentChanges") or []
        if not document.get("uri") or not changes:
            return
        change = changes[-1]
        if "range" in change:
            raise JsonRpcError(
                ErrorCodes.InvalidParams,
                "Incremental changes are not supported; client must use full sync",
            )
        self._server.change_document(
            document["uri"], change.get("text", ""), document.get("version")
        )
        if self._server.is_loaded:
            await asyncio.to_thread(self._server.reload)

    async def _handle_did_close(self, params: Any) -> None:
        uri = ((params or {}).get("textDocument") or {}).get("uri")
        if not uri:
            return
        self._server.close_document(uri)
        if self._server.is_loaded:
            await asyncio.to_thread(self._server.reload)

    def _require_loaded(self) -> None:
        if not self._server.is_loaded:
            raise JsonRpcError(ErrorCodes.InvalidRequest, "Workspace is not loaded")

    @staticmethod
    def _position(params: Any) -> tuple[str, int, int]:
        params = params or {}
        uri = (params.get("textDocument") or {}).get("uri", "")
        position = params.get("position") or {}
        return uri, int(position.get("line", 0)), int(position.get("character", 0))

    def _handle_definition(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        uri, line, character = self._position(params)
        return [
            item.location()
            for item in self._server.source_index.definitions_at(uri, line, character)
        ]

    def _handle_references(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        uri, line, character = self._position(params)
        include = bool(((params or {}).get("context") or {}).get("includeDeclaration"))
        return [
            item.location()
            for item in self._server.source_index.references_at(
                uri, line, character, include_declaration=include
            )
        ]

    def _handle_document_symbol(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        uri = ((params or {}).get("textDocument") or {}).get("uri", "")
        return [
            symbol.document_symbol()
            for symbol in self._server.source_index.document_symbols(uri)
        ]

    def _handle_completion(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        uri, line, character = self._position(params)
        prefix = self._server.source_index.word_at(uri, line, character) or ""
        symbols = self._server.source_index.workspace_symbols(prefix)
        items = [
            {
                "label": symbol.name,
                "kind": 3 if symbol.kind in {6, 12} else 7,
                "detail": symbol.qualified_name,
            }
            for symbol in symbols[:200]
        ]
        return {"isIncomplete": len(symbols) > len(items), "items": items}

    def _handle_hover(self, params: Any) -> Optional[dict[str, Any]]:
        self._require_loaded()
        if not self._server.supports("type_info"):
            return None
        uri, line, character = self._position(params)
        module = self._server.source_index.module_for_uri(uri)
        if not module:
            return None
        column = self._server.source_index.python_column(uri, line, character)
        result = self._server.get_expression_type(module, line + 1, column)
        if result is None:
            return None
        return {
            "contents": {
                "kind": "markdown",
                "value": f"```python\n{result['type']}\n```",
            }
        }

    def _handle_call_hierarchy_prepare(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        uri, line, character = self._position(params)
        symbol = self._server.source_index.function_at(uri, line, character)
        return [self._call_item(symbol)] if symbol else []

    def _handle_call_hierarchy_incoming(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        item = (params or {}).get("item") or {}
        name = (item.get("data") or {}).get("qualifiedName", item.get("name", ""))
        return [
            {
                "from": self._call_item(symbol),
                "fromRanges": [location.to_lsp() for location in locations],
            }
            for symbol, locations in self._server.source_index.incoming_calls(name)
        ]

    def _handle_call_hierarchy_outgoing(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        item = (params or {}).get("item") or {}
        name = (item.get("data") or {}).get("qualifiedName", item.get("name", ""))
        return [
            {
                "to": self._call_item(symbol),
                "fromRanges": [location.to_lsp() for location in locations],
            }
            for symbol, locations in self._server.source_index.outgoing_calls(name)
        ]

    @staticmethod
    def _call_item(symbol: SourceSymbol) -> dict[str, Any]:
        return {
            "name": symbol.name,
            "detail": symbol.qualified_name,
            "kind": symbol.kind,
            "uri": symbol.full_range.uri,
            "range": symbol.full_range.to_lsp(),
            "selectionRange": symbol.selection_range.to_lsp(),
            "data": {"qualifiedName": symbol.qualified_name},
        }

    def _handle_workspace_symbol(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        query = (params or {}).get("query", "")
        return [
            symbol.symbol_information()
            for symbol in self._server.source_index.workspace_symbols(query)[:500]
        ]

    def _handle_pyflow_callers(self, params: Any) -> list[str]:
        self._require_loaded()
        return self._server.get_callers((params or {}).get("function", ""))

    def _handle_pyflow_callees(self, params: Any) -> list[str]:
        self._require_loaded()
        return self._server.get_callees((params or {}).get("function", ""))

    def _handle_pyflow_callgraph(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        return self._server.get_callgraph_data()

    def _handle_pyflow_type(self, params: Any) -> Optional[dict[str, Any]]:
        self._require_loaded()
        if not self._server.supports("type_info"):
            return None
        params = params or {}
        return self._server.get_expression_type(
            params.get("module", ""),
            int(params.get("line", 0)),
            int(params.get("column", 0)),
        )

    def _handle_pyflow_aliases(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        if not self._server.supports("aliases"):
            raise JsonRpcError(
                ErrorCodes.InvalidRequest,
                "Alias analysis requires ADVANCED server mode",
            )
        return self._server.get_aliases_for_variable((params or {}).get("variable", ""))

    @staticmethod
    def _version() -> str:
        try:
            from pyflow import __version__

            return __version__
        except ImportError:
            return "0.0.0"


__all__ = ["LspHandler"]
