"""
LSP protocol handler — makes pyflow available as a language server.

Maps LSP ``textDocument/*`` requests to pyflow's analysis capabilities,
using the JSON-RPC transport layer. Only requests that pyflow can answer
better than a generic LSP server are implemented — the focus is on
data-flow, call-graph, and alias analysis.
"""

import logging
import re
from typing import Any, Optional

from .transport import JsonRpcServer
from .server import PyflowAnalysisServer

LOG = logging.getLogger(__name__)

# Match 'source(/absolute/path/file.py:42)' in the origin list.
_SOURCE_PATTERN = re.compile(r"^source\((.+):(\d+)\)$")


class LspHandler:
    """Bridges pyflow's analysis engine to the LSP protocol.

    Registers ``textDocument/*`` and ``workspace/*`` handlers on a
    ``JsonRpcServer`` instance.  Each handler translates LSP parameters
    into pyflow's SemanticQueryService calls and maps results back into
    LSP response shapes.
    """

    def __init__(self, server: PyflowAnalysisServer):
        self._server = server
        self._capabilities: dict[str, Any] = {}

    def register_on(self, rpc: JsonRpcServer) -> None:
        """Register all LSP handlers on a JSON-RPC server."""
        # Lifecycle
        rpc.register("initialize", self._handle_initialize)
        rpc.register("shutdown", self._handle_shutdown)
        rpc.register_notification("initialized", self._handle_initialized)
        rpc.register_notification("exit", self._handle_exit)

        # Text document synchronisation (minimal — we read from disk)
        rpc.register_notification(
            "textDocument/didOpen", self._handle_did_open)
        rpc.register_notification(
            "textDocument/didChange", self._handle_did_change)
        rpc.register_notification(
            "textDocument/didClose", self._handle_did_close)

        # Pyflow's differentiators
        rpc.register(
            "textDocument/definition", self._handle_definition)
        rpc.register(
            "textDocument/references", self._handle_references)
        rpc.register(
            "textDocument/documentSymbol", self._handle_document_symbol)
        rpc.register(
            "textDocument/completion", self._handle_completion)
        rpc.register(
            "textDocument/hover", self._handle_hover)
        rpc.register(
            "textDocument/callHierarchy/prepare",
            self._handle_call_hierarchy_prepare)
        rpc.register(
            "textDocument/callHierarchy/incomingCalls",
            self._handle_call_hierarchy_incoming)
        rpc.register(
            "textDocument/callHierarchy/outgoingCalls",
            self._handle_call_hierarchy_outgoing)

        # Workspace
        rpc.register("workspace/symbol", self._handle_workspace_symbol)

        # Pyflow custom extensions
        rpc.register("pyflow/getCallers", self._handle_pyflow_callers)
        rpc.register("pyflow/getCallees", self._handle_pyflow_callees)
        rpc.register("pyflow/getCallgraph", self._handle_pyflow_callgraph)
        rpc.register("pyflow/getType", self._handle_pyflow_type)
        rpc.register("pyflow/getAliases", self._handle_pyflow_aliases)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _handle_initialize(self, params: Any) -> dict[str, Any]:
        root_uri = params.get("rootUri") if params else None
        if root_uri:
            root_path = root_uri.replace("file://", "")
            try:
                self._server.load(root_path)
            except Exception as exc:
                LOG.warning("Initial load failed (deferred): %s", exc)

        text_doc_sync = {"openClose": True, "change": 1}
        self._capabilities = {
            "textDocumentSync": text_doc_sync,
            "definitionProvider": True,
            "referencesProvider": True,
            "documentSymbolProvider": True,
            "completionProvider": {
                "triggerCharacters": [".", "'", '"'],
                "resolveProvider": False,
            },
            "hoverProvider": True,
            "callHierarchyProvider": True,
            "workspaceSymbolProvider": True,
        }
        return {"capabilities": self._capabilities}

    def _handle_initialized(self, params: Any) -> None:
        pass

    def _handle_shutdown(self, params: Any) -> Optional[None]:
        self._server.close()
        return None

    def _handle_exit(self, params: Any) -> None:
        self._server.close()

    # ------------------------------------------------------------------
    # Text document sync (no-op — pyflow reads from disk / IR)
    # ------------------------------------------------------------------

    def _handle_did_open(self, params: Any) -> None:
        pass

    def _handle_did_change(self, params: Any) -> None:
        pass

    def _handle_did_close(self, params: Any) -> None:
        pass

    # ------------------------------------------------------------------
    # LSP queries powered by pyflow
    # ------------------------------------------------------------------

    def _uri_to_path(self, uri: str) -> str:
        return uri.replace("file://", "")

    @staticmethod
    def _get_origin_file(code: Any) -> Optional[str]:
        """Extract origin file path from a liveCode annotation.

        pyflow stores origin as a list of strings, e.g.
        ``['converted_function(foo)', 'source(/path/file.py:1)']``.
        Returns the file path portion of the ``source(...)`` entry, or
        ``None`` when no source entry is found.
        """
        origin = LspHandler._get_origin_list(code)
        if origin is None:
            return None
        for entry in origin:
            m = _SOURCE_PATTERN.match(entry)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _get_origin_line(code: Any) -> Optional[int]:
        """Extract origin line number from a liveCode annotation.

        Returns the 1-based line number from ``source(FILE:LINE)``, or
        ``None`` if no source entry is present.
        """
        origin = LspHandler._get_origin_list(code)
        if origin is None:
            return None
        for entry in origin:
            m = _SOURCE_PATTERN.match(entry)
            if m:
                return int(m.group(2))
        return None

    @staticmethod
    def _get_origin_list(code: Any) -> Optional[list[str]]:
        """Extract the ``origin`` list from a code annotation."""
        ann = getattr(code, "annotation", None)
        if ann is None:
            return None
        origin = getattr(ann, "origin", None)
        if not isinstance(origin, list):
            return None
        return origin

    def _find_code_at(self, uri: str, line: int) -> Optional[dict[str, Any]]:
        """Find the function code object containing a source line.

        Returns a dict with keys: ``name``, ``filename``, ``line``, ``end_line``
        (all 1-based) or ``None`` if no match is found.
        """
        path = self._uri_to_path(uri)
        for code in getattr(self._server.program, "liveCode", []):
            fn_path = self._get_origin_file(code)
            if fn_path is None:
                continue
            if not path.endswith(fn_path) and fn_path not in path:
                continue
            fn_start = self._get_origin_line(code)
            if fn_start is None:
                continue
            # pyflow only provides the start line; use it for both.
            fn_end = fn_start
            if fn_start <= line + 1 <= fn_end:
                raw = getattr(code, "codeName", None)
                fn_name = str(raw() if callable(raw) else raw) if raw else None
                if fn_name:
                    return {
                        "name": fn_name,
                        "filename": fn_path,
                        "line": fn_start,
                        "end_line": fn_end,
                    }
        return None

    def _iter_functions(self) -> list[dict[str, Any]]:
        """Iterate liveCode and yield function metadata.

        Each entry has keys: ``name``, ``filename`` (or None),
        ``line_0based``, ``end_line_0based``.
        """
        result: list[dict[str, Any]] = []
        for code in getattr(self._server.program, "liveCode", []):
            raw = getattr(code, "codeName", None)
            name = str(raw() if callable(raw) else raw) if raw else str(getattr(code, "name", "?"))
            fn_path = self._get_origin_file(code)
            fn_start = self._get_origin_line(code)
            fn_end = fn_start or 0
            result.append({
                "name": name,
                "filename": fn_path,
                "line_0based": max(fn_start - 1, 0) if fn_start else 0,
                "end_line_0based": max(fn_end - 1, 0) if fn_end else 0,
            })
        return result

    def _handle_definition(self, params: Any) -> Optional[list[dict[str, Any]]]:
        """textDocument/definition — navigate to the function at the cursor."""
        if not self._server.is_loaded:
            return None
        uri = params.get("textDocument", {}).get("uri", "")
        line = params.get("position", {}).get("line", 0)
        info = self._find_code_at(uri, line)
        if info is None:
            return None
        return [{
            "uri": f"file://{info['filename']}",
            "range": {
                "start": {"line": info["line"] - 1, "character": 0},
                "end": {"line": info["end_line"] - 1, "character": 0},
            },
        }]

    def _handle_references(self, params: Any) -> Optional[list[dict[str, Any]]]:
        """textDocument/references — callers + callees of the function at cursor."""
        if not self._server.is_loaded:
            return None
        uri = params.get("textDocument", {}).get("uri", "")
        line = params.get("position", {}).get("line", 0)
        info = self._find_code_at(uri, line)
        if info is None:
            return None
        func = info["name"]
        callers = self._server.get_callers(func)
        callees = self._server.get_callees(func)
        all_refs = list(set(callers + callees))
        return [
            {"uri": f"file://{info['filename']}",
             "range": {"start": {"line": info["line"] - 1, "character": 0},
                       "end": {"line": info["end_line"] - 1, "character": 0}}}
            for _ in all_refs[:20]
        ]

    def _handle_document_symbol(self, params: Any) -> Optional[list[dict[str, Any]]]:
        """textDocument/documentSymbol — list functions from pyflow's program."""
        if not self._server.is_loaded:
            return None
        symbols: list[dict[str, Any]] = []
        for fn in self._iter_functions():
            uri = f"file://{fn['filename']}" if fn["filename"] else f"file:///{fn['name']}"
            rng = {"start": {"line": fn["line_0based"], "character": 0},
                   "end": {"line": fn["end_line_0based"], "character": 0}}
            symbols.append({
                "name": fn["name"],
                "kind": 12,
                "location": {"uri": uri, "range": rng},
                "range": rng,
                "selectionRange": rng,
            })
        return symbols

    def _handle_completion(self, params: Any) -> Optional[dict[str, Any]]:
        """textDocument/completion — returns known function names from pyflow."""
        if not self._server.is_loaded:
            return None
        items = [
            {"label": fn["name"], "kind": 3, "detail": "pyflow"}
            for fn in self._iter_functions()
        ]
        return {"isIncomplete": False, "items": items[:100]}

    def _handle_hover(self, params: Any) -> Optional[dict[str, Any]]:
        """textDocument/hover — type information from pyflow's type analysis."""
        if not self._server.is_loaded:
            return None
        uri = params.get("textDocument", {}).get("uri", "")
        line = params.get("position", {}).get("line", 0)
        col = params.get("position", {}).get("character", 0)

        info = self._find_code_at(uri, line)
        if info is None:
            return None
        mod = info["name"].rsplit(".", 1)[0] if "." in info["name"] else info["name"]
        t = self._server.get_expression_type(mod, line + 1, col)
        if t:
            return {"contents": {"kind": "markdown",
                                 "value": f"```python\n{t['type']}\n```"}}
        return None

    def _handle_call_hierarchy_prepare(self, params: Any) -> Optional[list[dict[str, Any]]]:
        """textDocument/prepareCallHierarchy — function at position."""
        if not self._server.is_loaded:
            return None
        uri = params.get("textDocument", {}).get("uri", "")
        line = params.get("position", {}).get("line", 0)
        info = self._find_code_at(uri, line)
        if info is None:
            return None
        return [{
            "name": info["name"],
            "kind": 12,
            "uri": f"file://{info['filename']}",
            "range": {"start": {"line": info["line"] - 1, "character": 0},
                      "end": {"line": info["end_line"] - 1, "character": 0}},
            "selectionRange": {"start": {"line": info["line"] - 1, "character": 0},
                               "end": {"line": info["end_line"] - 1, "character": 0}},
        }]

    def _handle_call_hierarchy_incoming(self, params: Any) -> Optional[list[dict[str, Any]]]:
        if not self._server.is_loaded:
            return None
        item = params.get("item", {})
        name = item.get("name", "")
        callers = self._server.get_callers(name)
        return [
            {"from": {
                "name": c, "kind": 12,
                "uri": item.get("uri", ""),
                "range": item.get("range", {"start": {"line": 0, "character": 0},
                                             "end": {"line": 0, "character": 0}}),
                "selectionRange": item.get("selectionRange", item.get("range", {})),
             },
             "fromRanges": [item.get("range", {})]}
            for c in callers[:20]
        ]

    def _handle_call_hierarchy_outgoing(self, params: Any) -> Optional[list[dict[str, Any]]]:
        if not self._server.is_loaded:
            return None
        item = params.get("item", {})
        name = item.get("name", "")
        callees = self._server.get_callees(name)
        return [
            {"to": {
                "name": c, "kind": 12,
                "uri": item.get("uri", ""),
                "range": item.get("range", {"start": {"line": 0, "character": 0},
                                             "end": {"line": 0, "character": 0}}),
                "selectionRange": item.get("selectionRange", item.get("range", {})),
             },
             "fromRanges": [item.get("range", {})]}
            for c in callees[:20]
        ]

    def _handle_workspace_symbol(self, params: Any) -> Optional[list[dict[str, Any]]]:
        if not self._server.is_loaded:
            return None
        query = (params or {}).get("query", "").lower()
        symbols: list[dict[str, Any]] = []
        for fn in self._iter_functions():
            if query and query not in fn["name"].lower():
                continue
            uri = f"file://{fn['filename']}" if fn["filename"] else f"file:///{fn['name']}"
            symbols.append({
                "name": fn["name"],
                "kind": 12,
                "location": {
                    "uri": uri,
                    "range": {"start": {"line": fn["line_0based"], "character": 0},
                              "end": {"line": fn["end_line_0based"], "character": 0}},
                },
            })
        return symbols

    # ------------------------------------------------------------------
    # Pyflow custom extensions — return analysis data directly
    # ------------------------------------------------------------------

    def _handle_pyflow_callers(self, params: Any) -> list[str]:
        function = (params or {}).get("function", "")
        return self._server.get_callers(function)

    def _handle_pyflow_callees(self, params: Any) -> list[str]:
        function = (params or {}).get("function", "")
        return self._server.get_callees(function)

    def _handle_pyflow_callgraph(self, params: Any) -> dict[str, Any]:
        return self._server.get_callgraph_data()

    def _handle_pyflow_type(self, params: Any) -> Optional[dict[str, Any]]:
        p = params or {}
        return self._server.get_expression_type(
            p.get("module", ""),
            p.get("line", 0),
            p.get("column", 0),
        )

    def _handle_pyflow_aliases(self, params: Any) -> dict[str, Any]:
        variable = (params or {}).get("variable", "")
        return self._server.get_aliases_for_variable(variable)
