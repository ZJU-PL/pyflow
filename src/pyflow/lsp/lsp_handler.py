"""Language Server Protocol adapter for pyflow analysis snapshots."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Optional

from .server import AnalysisManager
from .transport import ErrorCodes, JsonRpcError, JsonRpcServer
from .workspace import SourceSymbol, SymbolId, uri_to_path

LOG = logging.getLogger(__name__)


class LspHandler:
    """Translate source-oriented LSP requests into pyflow queries."""

    def __init__(self, server: AnalysisManager):
        self._server = server
        self._capabilities: dict[str, Any] = {}
        self._shutdown = False
        self._semantic_task: Optional[asyncio.Task[None]] = None
        self._semantic_dirty = False

    def register_on(self, rpc: JsonRpcServer) -> None:
        rpc.register("initialize", self._handle_initialize)
        rpc.register("shutdown", self._handle_shutdown)
        rpc.register_notification("initialized", self._handle_initialized)
        rpc.register_notification("exit", self._handle_exit)

        rpc.register_notification("textDocument/didOpen", self._handle_did_open)
        rpc.register_notification("textDocument/didChange", self._handle_did_change)
        rpc.register_notification("textDocument/didClose", self._handle_did_close)
        rpc.register_notification(
            "workspace/didChangeWatchedFiles", self._handle_watched_files
        )
        rpc.register_notification(
            "workspace/didChangeWorkspaceFolders",
            self._handle_workspace_folders_changed,
        )

        rpc.register("textDocument/definition", self._handle_definition)
        rpc.register("textDocument/references", self._handle_references)
        rpc.register("textDocument/documentSymbol", self._handle_document_symbol)
        rpc.register("textDocument/completion", self._handle_completion)
        rpc.register("textDocument/hover", self._handle_hover)
        rpc.register("textDocument/prepareRename", self._handle_prepare_rename)
        rpc.register("textDocument/rename", self._handle_rename)
        rpc.register("textDocument/diagnostic", self._handle_document_diagnostic)
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
        folders = params.get("workspaceFolders") or []
        workspace_paths = [
            uri_to_path(folder["uri"])
            for folder in folders
            if isinstance(folder, dict) and folder.get("uri")
        ]
        root_uri = params.get("rootUri")
        if not workspace_paths and root_uri:
            workspace_paths = [uri_to_path(root_uri)]
        if workspace_paths:
            try:
                if (
                    not self._server.is_loaded
                    or tuple(workspace_paths) != self._server.workspace_roots
                ):
                    await asyncio.to_thread(self._server.load_workspaces, workspace_paths)
            except Exception as exc:
                raise JsonRpcError(
                    ErrorCodes.InternalError,
                    f"Unable to analyze workspace: {exc}",
                ) from exc

        self._capabilities = {
            "positionEncoding": "utf-16",
            "textDocumentSync": {"openClose": True, "change": 2, "save": False},
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
            "renameProvider": {"prepareProvider": True},
            "diagnosticProvider": {
                "interFileDependencies": True,
                "workspaceDiagnostics": False,
            },
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
        self._stop_semantic_refresh()
        self._server.close()
        return None

    def _handle_exit(self, params: Any) -> None:
        self._stop_semantic_refresh()
        self._server.close()

    async def _handle_did_open(self, params: Any) -> None:
        document = (params or {}).get("textDocument", {})
        uri = document.get("uri")
        text = document.get("text")
        if not uri or text is None:
            return
        changed = self._server.open_document(uri, text, document.get("version"))
        if self._server.is_loaded:
            if changed:
                self._schedule_semantic_reload()
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
        try:
            changed = self._server.change_document(
                document["uri"], changes, document.get("version")
            )
        except ValueError as exc:
            raise JsonRpcError(ErrorCodes.InvalidParams, str(exc)) from exc
        if self._server.is_loaded and changed:
            self._schedule_semantic_reload()

    async def _handle_did_close(self, params: Any) -> None:
        uri = ((params or {}).get("textDocument") or {}).get("uri")
        if not uri:
            return
        if self._server.close_document(uri) and self._server.is_loaded:
            self._schedule_semantic_reload()

    async def _handle_watched_files(self, params: Any) -> None:
        if self._server.is_loaded and (params or {}).get("changes"):
            self._schedule_semantic_reload()

    async def _handle_workspace_folders_changed(self, params: Any) -> None:
        event = ((params or {}).get("event") or {})
        removed = {
            uri_to_path(folder["uri"])
            for folder in event.get("removed", [])
            if isinstance(folder, dict) and folder.get("uri")
        }
        roots = [root for root in self._server.workspace_roots if root not in removed]
        for folder in event.get("added", []):
            if not isinstance(folder, dict) or not folder.get("uri"):
                continue
            root = uri_to_path(folder["uri"])
            if root not in roots:
                roots.append(root)
        if not roots:
            self._server.close()
            return
        try:
            await asyncio.to_thread(self._server.load_workspaces, roots)
        except Exception:
            LOG.exception("Unable to reload changed workspace folders")

    def _schedule_semantic_reload(self) -> None:
        """Coalesce edits into one semantic worker and at most one rerun."""
        self._semantic_dirty = True
        if self._semantic_task is not None and not self._semantic_task.done():
            return
        self._semantic_task = asyncio.create_task(self._run_semantic_refresh())

    def _stop_semantic_refresh(self) -> None:
        self._semantic_dirty = False
        if self._semantic_task is not None:
            self._semantic_task.cancel()

    async def _run_semantic_refresh(self) -> None:
        try:
            while self._semantic_dirty and self._server.is_loaded:
                # Let a burst of incremental edits settle before starting the
                # expensive whole-workspace analysis.
                await asyncio.sleep(0.1)
                self._semantic_dirty = False
                source_revision = self._server.current_snapshot().source_revision
                await asyncio.to_thread(self._server.reload)
                snapshot = self._server.current_snapshot()
                if (
                    snapshot.source_revision != source_revision
                    or snapshot.semantic_stale
                ):
                    self._semantic_dirty = True
        except asyncio.CancelledError:
            self._semantic_dirty = False
            raise
        except GeneratorExit:
            self._semantic_dirty = False
            raise
        except Exception:
            LOG.exception("Background semantic refresh failed")
        finally:
            self._semantic_task = None
            # An edit can arrive after the loop's final condition but before
            # this task clears its reference. Keep that dirty signal alive.
            if self._semantic_dirty and self._server.is_loaded:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    # A test/client can close the event loop while this worker
                    # is being finalized. There is no remaining dispatcher to
                    # consume a refresh task in that case.
                    self._semantic_dirty = False
                else:
                    self._semantic_task = loop.create_task(self._run_semantic_refresh())

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
        source_index = self._server.current_snapshot().source_index
        return [
            item.location()
            for item in source_index.definitions_at(uri, line, character)
        ]

    def _handle_references(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        uri, line, character = self._position(params)
        include = bool(((params or {}).get("context") or {}).get("includeDeclaration"))
        source_index = self._server.current_snapshot().source_index
        return [
            item.location()
            for item in source_index.references_at(
                uri, line, character, include_declaration=include
            )
        ]

    def _handle_document_symbol(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        uri = ((params or {}).get("textDocument") or {}).get("uri", "")
        return [
            symbol.document_symbol()
            for symbol in self._server.current_snapshot().source_index.document_symbols(uri)
        ]

    def _handle_completion(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        uri, line, character = self._position(params)
        source_index = self._server.current_snapshot().source_index
        prefix = source_index.word_at(uri, line, character) or ""
        symbols = source_index.workspace_symbols(prefix)
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
        snapshot = self._server.current_snapshot()
        if snapshot.semantic_stale:
            return None
        module = snapshot.source_index.module_for_uri(uri)
        if not module:
            return None
        column = snapshot.source_index.python_column(uri, line, character)
        result = snapshot.queries.type_info.get_expression_type(
            module, line + 1, column
        )
        if result is None:
            return None
        return {
            "contents": {
                "kind": "markdown",
                "value": f"```python\n{result}\n```",
            }
        }

    def _handle_prepare_rename(self, params: Any) -> Optional[dict[str, Any]]:
        self._require_loaded()
        uri, line, character = self._position(params)
        symbol = self._server.current_snapshot().source_index.symbol_at(
            uri, line, character
        )
        return symbol.selection_range.to_lsp() if symbol else None

    def _handle_rename(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        new_name = str((params or {}).get("newName", ""))
        if not new_name.isidentifier():
            raise JsonRpcError(ErrorCodes.InvalidParams, "newName must be a Python identifier")
        uri, line, character = self._position(params)
        ranges = self._server.current_snapshot().source_index.rename_ranges_at(
            uri, line, character
        )
        if not ranges:
            raise JsonRpcError(ErrorCodes.InvalidParams, "No renameable symbol at position")
        changes: dict[str, list[dict[str, Any]]] = {}
        for source_range in ranges:
            changes.setdefault(source_range.uri, []).append(
                {"range": source_range.to_lsp(), "newText": new_name}
            )
        return {"changes": changes}

    def _handle_document_diagnostic(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        uri = ((params or {}).get("textDocument") or {}).get("uri", "")
        snapshot = self._server.current_snapshot()
        return {
            "kind": "full",
            "items": snapshot.source_index.diagnostics_for_uri(uri),
            "resultId": f"{snapshot.revision}:{snapshot.source_revision}",
        }

    def _handle_call_hierarchy_prepare(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        uri, line, character = self._position(params)
        symbol = self._server.current_snapshot().source_index.function_at(
            uri, line, character
        )
        return [self._call_item(symbol)] if symbol else []

    def _handle_call_hierarchy_incoming(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        item = (params or {}).get("item") or {}
        data = item.get("data") or {}
        name = SymbolId.from_data(data.get("symbolId")) or data.get(
            "qualifiedName", item.get("name", "")
        )
        return [
            {
                "from": self._call_item(symbol),
                "fromRanges": [location.to_lsp() for location in locations],
            }
            for symbol, locations in self._server.current_snapshot()
            .source_index.incoming_calls(name)
        ]

    def _handle_call_hierarchy_outgoing(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        item = (params or {}).get("item") or {}
        data = item.get("data") or {}
        name = SymbolId.from_data(data.get("symbolId")) or data.get(
            "qualifiedName", item.get("name", "")
        )
        return [
            {
                "to": self._call_item(symbol),
                "fromRanges": [location.to_lsp() for location in locations],
            }
            for symbol, locations in self._server.current_snapshot()
            .source_index.outgoing_calls(name)
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
            "data": {
                "qualifiedName": symbol.qualified_name,
                "symbolId": symbol.symbol_id.to_data(),
            },
        }

    def _handle_workspace_symbol(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        query = (params or {}).get("query", "")
        return [
            symbol.symbol_information()
            for symbol in self._server.current_snapshot()
            .source_index.workspace_symbols(query)[:500]
        ]

    def _handle_pyflow_callers(self, params: Any) -> list[str]:
        self._require_loaded()
        snapshot = self._fresh_semantic_snapshot()
        return snapshot.queries.call_graph.get_callers(
            (params or {}).get("function", "")
        )

    def _handle_pyflow_callees(self, params: Any) -> list[str]:
        self._require_loaded()
        snapshot = self._fresh_semantic_snapshot()
        return snapshot.queries.call_graph.get_callees(
            (params or {}).get("function", "")
        )

    def _handle_pyflow_callgraph(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        return self._fresh_semantic_snapshot().queries.call_graph.get_callgraph_data()

    def _handle_pyflow_type(self, params: Any) -> Optional[dict[str, Any]]:
        self._require_loaded()
        if not self._server.supports("type_info"):
            return None
        snapshot = self._server.current_snapshot()
        if snapshot.semantic_stale:
            return None
        params = params or {}
        result = snapshot.queries.type_info.get_expression_type(
            params.get("module", ""),
            int(params.get("line", 0)),
            int(params.get("column", 0)),
        )
        return {"type": str(result)} if result is not None else None

    def _handle_pyflow_aliases(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        if not self._server.supports("aliases"):
            raise JsonRpcError(
                ErrorCodes.InvalidRequest,
                "Alias analysis is unavailable in this analysis snapshot",
            )
        info = self._fresh_semantic_snapshot().queries.data_flow.get_aliases_for_variable(
            (params or {}).get("variable", "")
        )
        return {
            "variable": info.variable,
            "aliases": sorted(info.aliases),
            "is_aliased": info.is_aliased,
            "ref_count": info.ref_count,
            "is_escaped": info.is_escaped,
        }

    def _fresh_semantic_snapshot(self):
        snapshot = self._server.current_snapshot()
        if snapshot.semantic_stale:
            raise JsonRpcError(
                ErrorCodes.RequestCancelled,
                "Semantic analysis is refreshing for the current source revision",
            )
        try:
            return snapshot.require_fresh_semantics()
        except RuntimeError as exc:
            raise JsonRpcError(ErrorCodes.RequestCancelled, str(exc)) from exc

    @staticmethod
    def _version() -> str:
        try:
            from pyflow import __version__

            return __version__
        except ImportError:
            return "0.0.0"


__all__ = ["LspHandler"]
