"""Language Server Protocol adapter for pyflow analysis snapshots."""

from __future__ import annotations

import asyncio
import logging
import keyword
from pathlib import Path
from typing import Any, Optional

from .server import AnalysisManager
from .transport import ErrorCodes, JsonRpcError, JsonRpcServer
from .workspace import SourceIndex, SourceSymbol, SymbolId, uri_to_path

LOG = logging.getLogger(__name__)


class LspHandler:
    """Translate source-oriented LSP requests into pyflow queries."""

    def __init__(self, server: AnalysisManager):
        self._server = server
        self._capabilities: dict[str, Any] = {}
        self._shutdown = False
        self._semantic_task: Optional[asyncio.Task[None]] = None
        self._semantic_dirty = False
        self._initial_semantics = False
        self._diagnostic_lock = asyncio.Lock()
        self._rpc = None
        self._analysis_task = None

    def register_on(self, rpc: JsonRpcServer) -> None:
        self._rpc = rpc
        rpc.register("initialize", self._handle_initialize)
        rpc.register("shutdown", self._handle_shutdown)
        rpc.register("workspace/executeCommand", self._handle_execute_command)
        rpc.register_notification("initialized", self._handle_initialized)
        rpc.register_notification("exit", self._handle_exit)

        rpc.register_notification("textDocument/didOpen", self._handle_did_open)
        rpc.register_notification("textDocument/didChange", self._handle_did_change)
        rpc.register_notification("textDocument/didClose", self._handle_did_close)
        rpc.register_notification("workspace/didChangeWatchedFiles", self._handle_watched_files)
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
        rpc.register("textDocument/prepareCallHierarchy", self._handle_call_hierarchy_prepare)
        rpc.register("callHierarchy/incomingCalls", self._handle_call_hierarchy_incoming)
        rpc.register("callHierarchy/outgoingCalls", self._handle_call_hierarchy_outgoing)

        # Compatibility aliases for the early experimental protocol.
        rpc.register("textDocument/callHierarchy/prepare", self._handle_call_hierarchy_prepare)
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
        self._initial_semantics = bool(
            (params.get("initializationOptions") or {}).get("semanticAnalysis", False)
        )
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
                    await asyncio.to_thread(self._server.load_source_workspaces, workspace_paths)
            except Exception as exc:
                raise JsonRpcError(
                    ErrorCodes.InternalError,
                    f"Unable to analyze workspace: {exc}",
                ) from exc
        elif not self._server.is_loaded:
            await asyncio.to_thread(self._server.load_source_files, [])

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
            "hoverProvider": True,
            "executeCommandProvider": {"commands": ["pyflow.analyzeWorkspace"]},
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
        if self._initial_semantics and self._server.is_loaded:
            self._start_workspace_analysis()

    async def _handle_execute_command(self, params: Any):
        if (params or {}).get("command") != "pyflow.analyzeWorkspace":
            raise JsonRpcError(ErrorCodes.InvalidParams, "Unknown command")
        self._require_loaded()
        await asyncio.shield(self._start_workspace_analysis())
        return {"diagnostics": self._server.analysis_diagnostics}

    def _start_workspace_analysis(self):
        if self._analysis_task is None or self._analysis_task.done():
            self._analysis_task = asyncio.create_task(
                asyncio.to_thread(self._server.analyze_workspace)
            )
        return self._analysis_task

    def _handle_shutdown(self, params: Any) -> None:
        self._shutdown = True
        self._stop_semantic_refresh()
        self._server.close()
        return None

    def _handle_exit(self, params: Any) -> None:
        self._stop_semantic_refresh()
        self._server.close()
        if self._rpc is not None:
            self._rpc.stop()

    async def _handle_did_open(self, params: Any) -> None:
        document = (params or {}).get("textDocument", {})
        uri = document.get("uri")
        text = document.get("text")
        if not uri or text is None:
            return
        self._server.open_document(uri, text, document.get("version"))
        if not self._server.is_loaded:
            await asyncio.to_thread(self._server.load_source_files, [Path(uri_to_path(uri))])

    async def _handle_did_change(self, params: Any) -> None:
        params = params or {}
        document = params.get("textDocument", {})
        changes = params.get("contentChanges") or []
        if not document.get("uri") or not changes:
            return
        try:
            self._server.change_document(document["uri"], changes, document.get("version"))
        except ValueError as exc:
            raise JsonRpcError(ErrorCodes.InvalidParams, str(exc)) from exc
        # Source/type services already use the current overlay. Compiler
        # analysis is explicit, never a whole-project job per keystroke.

    async def _handle_did_close(self, params: Any) -> None:
        uri = ((params or {}).get("textDocument") or {}).get("uri")
        if not uri:
            return
        self._server.close_document(uri)

    async def _handle_watched_files(self, params: Any) -> None:
        if self._server.is_loaded and (params or {}).get("changes"):
            self._schedule_semantic_reload()

    async def _handle_workspace_folders_changed(self, params: Any) -> None:
        event = (params or {}).get("event") or {}
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
            await asyncio.to_thread(self._server.load_source_files, [])
            return
        try:
            await asyncio.to_thread(self._server.load_source_workspaces, roots)
        except Exception:
            LOG.exception("Unable to reload changed workspace folders")

    def _schedule_semantic_reload(self) -> None:
        """Coalesce filesystem notifications into one source-index refresh."""
        self._semantic_dirty = True
        if self._semantic_task is not None and not self._semantic_task.done():
            return
        self._semantic_task = asyncio.create_task(self._run_semantic_refresh())

    def _stop_semantic_refresh(self) -> None:
        self._semantic_dirty = False
        if self._semantic_task is not None:
            self._semantic_task.cancel()
        if self._analysis_task is not None:
            self._analysis_task.cancel()

    async def _run_semantic_refresh(self) -> None:
        try:
            while self._semantic_dirty and self._server.is_loaded:
                # Debounce filesystem bursts without running compiler passes.
                await asyncio.sleep(0.3)
                self._semantic_dirty = False
                source_revision = self._server.current_snapshot().source_revision
                await asyncio.to_thread(self._server.refresh_sources)
                snapshot = self._server.current_snapshot()
                if snapshot.source_revision != source_revision:
                    self._semantic_dirty = True
        except asyncio.CancelledError:
            self._semantic_dirty = False
            raise
        except GeneratorExit:
            self._semantic_dirty = False
            raise
        except Exception:
            LOG.exception("Background source refresh failed")
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
        return [item.location() for item in source_index.definitions_at(uri, line, character)]

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
        return self._server.current_snapshot().source_index.document_symbol_tree(uri)

    def _handle_completion(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        uri, line, character = self._position(params)
        source_index = self._server.current_snapshot().source_index
        items = source_index.completion_items(uri, line, character)
        return {"isIncomplete": len(items) > 200, "items": items[:200]}

    async def _handle_hover(self, params: Any) -> Optional[dict[str, Any]]:
        self._require_loaded()
        uri, line, character = self._position(params)
        snapshot = self._server.current_snapshot()
        if isinstance(snapshot.source_index, SourceIndex):
            declaration = snapshot.source_index.hover_at(uri, line, character)
            if declaration is not None:
                return declaration
        if isinstance(snapshot.source_index, SourceIndex):
            from .document_analysis import infer_document

            text = snapshot.source_index.text_for_uri(uri)
            module = snapshot.source_index.module_for_uri(uri)
            if text is not None and module:
                try:
                    inferred = await asyncio.to_thread(
                        infer_document, uri_to_path(uri), module, text
                    )
                    result = inferred.expression_type(
                        line + 1, snapshot.source_index.python_column(uri, line, character)
                    )
                    if result is not None:
                        if not self._document_is_current(snapshot, uri):
                            raise JsonRpcError(
                                ErrorCodes.RequestCancelled,
                                "Document changed during hover inference",
                            )
                        return {
                            "contents": {"kind": "markdown", "value": f"```python\n{result}\n```"}
                        }
                except JsonRpcError:
                    raise
                except Exception:
                    LOG.exception("Document hover inference failed")
            symbol = snapshot.source_index.symbol_at(uri, line, character)
            return (
                {
                    "contents": {
                        "kind": "markdown",
                        "value": f"```python\n{symbol.detail or symbol.name}\n```",
                    }
                }
                if symbol
                else None
            )
        if snapshot.semantic_stale or not self._server.supports("type_info"):
            return None
        module = snapshot.source_index.module_for_uri(uri)
        if not module:
            return None
        column = snapshot.source_index.python_column(uri, line, character)
        result = snapshot.queries.type_info.get_expression_type(module, line + 1, column)
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
        index = self._server.current_snapshot().source_index
        if not index.rename_ranges_at(uri, line, character):
            return None
        token = index.token_range_at(uri, line, character)
        return token.to_lsp() if token else None

    def _handle_rename(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        new_name = str((params or {}).get("newName", ""))
        if not new_name.isidentifier() or keyword.iskeyword(new_name):
            raise JsonRpcError(ErrorCodes.InvalidParams, "newName must be a Python identifier")
        uri, line, character = self._position(params)
        source_index = self._server.current_snapshot().source_index
        ranges = source_index.rename_ranges_at(uri, line, character)
        if not ranges:
            raise JsonRpcError(
                ErrorCodes.InvalidParams,
                "Rename is unavailable: the symbol or some member references cannot be resolved safely",
            )
        changes: dict[str, list[dict[str, Any]]] = {}
        for source_range in ranges:
            changes.setdefault(source_range.uri, []).append(
                {
                    "range": source_range.to_lsp(),
                    "newText": source_index.replacement_text(source_range, new_name),
                }
            )
        return {"changes": changes}

    def _document_is_current(self, snapshot, uri):
        try:
            return self._server.current_snapshot().source_index.text_for_uri(
                uri
            ) == snapshot.source_index.text_for_uri(uri)
        except RuntimeError:
            return False

    async def _handle_document_diagnostic(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        uri = ((params or {}).get("textDocument") or {}).get("uri", "")
        snapshot = self._server.current_snapshot()
        from .document_analysis import document_diagnostics

        await self._diagnostic_lock.acquire()
        if not self._document_is_current(snapshot, uri):
            self._diagnostic_lock.release()
            raise JsonRpcError(
                ErrorCodes.RequestCancelled, "Document changed before diagnostics started"
            )
        worker = asyncio.create_task(
            asyncio.to_thread(document_diagnostics, snapshot.source_index, uri)
        )

        def completed(task):
            self._diagnostic_lock.release()
            if not task.cancelled():
                task.exception()

        worker.add_done_callback(completed)
        items = await asyncio.shield(worker)
        if not self._document_is_current(snapshot, uri):
            raise JsonRpcError(
                ErrorCodes.RequestCancelled, "Document changed while diagnostics were running"
            )
        compiler_notes = [
            {
                "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}},
                "severity": 3,
                "source": "pyflow-compiler",
                "code": note.get("code", "analysis-failed"),
                "message": note["message"],
            }
            for note in getattr(self._server, "analysis_diagnostics", ())
        ]
        return {
            "kind": "full",
            "items": [*items, *compiler_notes],
            "resultId": f"{snapshot.revision}:{snapshot.source_revision}",
        }

    def _handle_call_hierarchy_prepare(self, params: Any) -> list[dict[str, Any]]:
        self._require_loaded()
        uri, line, character = self._position(params)
        symbol = self._server.current_snapshot().source_index.function_at(uri, line, character)
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
            for symbol, locations in self._server.current_snapshot().source_index.incoming_calls(
                name
            )
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
            for symbol, locations in self._server.current_snapshot().source_index.outgoing_calls(
                name
            )
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
            for symbol in self._server.current_snapshot().source_index.workspace_symbols(query)[
                :500
            ]
        ]

    def _handle_pyflow_callers(self, params: Any) -> list[str]:
        self._require_loaded()
        snapshot = self._fresh_semantic_snapshot("call_graph")
        return snapshot.queries.call_graph.get_callers((params or {}).get("function", ""))

    def _handle_pyflow_callees(self, params: Any) -> list[str]:
        self._require_loaded()
        snapshot = self._fresh_semantic_snapshot("call_graph")
        return snapshot.queries.call_graph.get_callees((params or {}).get("function", ""))

    def _handle_pyflow_callgraph(self, params: Any) -> dict[str, Any]:
        self._require_loaded()
        return self._fresh_semantic_snapshot("call_graph").queries.call_graph.get_callgraph_data()

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

    def _fresh_semantic_snapshot(self, capability=None):
        snapshot = self._server.current_snapshot()
        if capability and not self._server.supports(capability):
            raise JsonRpcError(
                ErrorCodes.InvalidRequest,
                "Compiler analysis is unavailable; execute pyflow.analyzeWorkspace first",
            )
        if snapshot.semantic_stale:
            raise JsonRpcError(
                ErrorCodes.RequestCancelled,
                "Compiler analysis is stale; execute pyflow.analyzeWorkspace to refresh it",
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
