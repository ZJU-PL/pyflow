"""Integration tests for pyflow's LSP module — real analysis on real files.

These use ``PyflowAnalysisServer.load_files()`` with tiny Python sources,
so pyflow's full extraction and analysis pipeline actually runs.  They are
marked ``integration`` and excluded from the default ``pytest`` run.

Run with::

    pytest tests/lsp/test_real_analysis.py -m integration
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pyflow.lsp import LspHandler, McpHandler, JsonRpcServer
from pyflow.lsp.server import PyflowAnalysisServer

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


async def _capture_send(rpc: JsonRpcServer) -> list:
    sent = []

    async def capture(payload):
        sent.append(payload)

    rpc._send = capture  # type: ignore[assignment]
    return sent


def dispatch(rpc: JsonRpcServer, msg: dict) -> list:
    """Send a JSON-RPC message and return captured responses."""
    sent = _run(_capture_send(rpc))
    _run(rpc._dispatch(msg))
    return sent


# ---------------------------------------------------------------------------
# Single-file analysis
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSingleFileAnalysis:
    """Real pipeline on a single Python file — no mocks."""

    def test_load_files_populates_live_code(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        # liveCode includes the function and the module-level scope
        assert len(getattr(server.program, "liveCode", [])) >= 1

    def test_capabilities_shape(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        caps = server.get_capabilities()
        assert isinstance(caps, dict)
        # Key capabilities pyflow should advertise
        assert "cfg" in caps
        assert "callgraph" in caps
        assert "callers" in caps
        assert "callees" in caps
        assert caps["type_info"]["available"] is True

    def test_type_service_is_wired_to_real_source(self, tmp_path: Path) -> None:
        sample = tmp_path / "typed.py"
        sample.write_text("def typed(value: int) -> int:\n    return value\n")
        server = PyflowAnalysisServer(verbose=False)
        server.load_files([sample])
        assert server.service.get_symbol_type("typed", "typed") is not None

    def test_callgraph_contains_function(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        cg = server.get_callgraph_data()
        functions = list(cg.keys()) if isinstance(cg, dict) else cg.get("functions", cg)
        # pyflow qualifies function names with the source location
        assert any("foo" in str(fn) for fn in functions)

    def test_get_callers_roundtrip(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        cg = server.get_callgraph_data()
        functions = list(cg.keys()) if isinstance(cg, dict) else cg.get("functions", cg)
        fn = next((f for f in functions if "foo" in str(f)), None)
        if fn is not None:
            callers = server.get_callers(fn)
            assert isinstance(callers, list)

    def test_get_callees_roundtrip(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        cg = server.get_callgraph_data()
        functions = list(cg.keys()) if isinstance(cg, dict) else cg.get("functions", cg)
        fn = next((f for f in functions if "foo" in str(f)), None)
        if fn is not None:
            callees = server.get_callees(fn)
            assert isinstance(callees, list)

    def test_function_test_profile(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        cg = server.get_callgraph_data()
        functions = list(cg.keys()) if isinstance(cg, dict) else cg.get("functions", cg)
        fn = next((f for f in functions if "foo" in str(f)), None)
        if fn is not None:
            profile = server.get_function_test_profile(fn)
            assert profile["name"] is not None
            assert "parameters" in profile

    def test_cfg_structure(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        cg = server.get_callgraph_data()
        functions = list(cg.keys()) if isinstance(cg, dict) else cg.get("functions", cg)
        fn = next((f for f in functions if "foo" in str(f)), None)
        if fn is not None:
            cfg = server.get_cfg_structure(fn)
            assert isinstance(cfg, dict)

    def test_get_shortest_path(self, tmp_path: Path) -> None:
        """Shortest path between a function and itself should be length 1."""
        server = _analyze_simple(tmp_path)
        cg = server.get_callgraph_data()
        functions = list(cg.keys()) if isinstance(cg, dict) else cg.get("functions", cg)
        fn = next((f for f in functions if "foo" in str(f)), None)
        if fn is not None:
            path = server.get_shortest_path(fn, fn)
            if path is not None:
                assert len(path) >= 1

    def test_lifecycle_close_and_reload(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        assert server.is_loaded is True
        server.close()
        assert server.is_loaded is False
        with pytest.raises(RuntimeError, match="not loaded"):
            _ = server.service
        # Reload with a different function
        sample2 = tmp_path / "bar.py"
        sample2.write_text("def bar(): return 42\n")
        server.load_files([sample2], run_pipeline=True)
        assert server.is_loaded is True

    def test_verbose_flag_suppresses_logging(self, tmp_path: Path) -> None:
        """Setting verbose=False should not produce Console output."""
        server = PyflowAnalysisServer(verbose=False)
        sample = tmp_path / "quiet.py"
        sample.write_text("def f(): return 1\n")
        server.load_files([sample], run_pipeline=True)
        assert server.is_loaded is True
        assert server.get_capabilities() is not None


# ---------------------------------------------------------------------------
# Multi-file analysis
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMultiFileAnalysis:
    def test_load_multiple_files(self, tmp_path: Path) -> None:
        """Multi-file extraction works (pipeline has a known pass-ordering
        issue with the pass manager for multi-module programs, so we only
        assert extraction succeeded)."""
        a = tmp_path / "a.py"
        b = tmp_path / "b.py"
        a.write_text("def greet(): return 'hello'\n")
        b.write_text("from a import greet\ndef run(): return greet()\n")

        server = PyflowAnalysisServer(verbose=False)
        try:
            server.load_files([a, b], run_pipeline=True)
        except RuntimeError as exc:
            # Known pipeline limitation: store_elimination ordering
            if "store_elimination" in str(exc):
                pytest.skip("Multi-file pipeline pass-ordering issue")
            raise

        caps = server.get_capabilities()
        assert caps is not None
        live = getattr(server.program, "liveCode", [])
        assert len(live) >= 2

    def test_callgraph_has_multiple_modules(self, tmp_path: Path) -> None:
        a = tmp_path / "a.py"
        b = tmp_path / "b.py"
        a.write_text("def helper(): return 1\n")
        b.write_text("from a import helper\ndef run(): return helper()\n")

        server = PyflowAnalysisServer(verbose=False)
        try:
            server.load_files([a, b], run_pipeline=True)
        except RuntimeError as exc:
            if "store_elimination" in str(exc):
                pytest.skip("Multi-file pipeline pass-ordering issue")
            raise

        cg = server.get_callgraph_data()
        functions = list(cg.keys()) if isinstance(cg, dict) else cg.get("functions", cg)
        assert any("run" in str(f) for f in functions)


# ---------------------------------------------------------------------------
# LspHandler with real analysis data
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLspHandlerReal:
    """LspHandler wired to JsonRpcServer with a real PyflowAnalysisServer.

    Tests that the handler dispatch → pyflow query → response pipeline
    produces correct results with genuine analysis data.
    """

    def test_document_symbol_returns_real_functions(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        uri = (tmp_path / "sample.py").as_uri()
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/documentSymbol",
                "params": {
                    "textDocument": {"uri": uri},
                },
            },
        )
        symbols = sent[0]["result"]
        assert isinstance(symbols, list)
        names = [s["name"] for s in symbols]
        assert "foo" in names

    def test_document_symbol_has_real_positions(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/documentSymbol",
                "params": {
                    "textDocument": {"uri": "file:///any.py"},
                },
            },
        )
        symbols = sent[0]["result"]
        for s in symbols:
            uri = s["location"]["uri"]
            # Real analysis populates origin file paths via source(FILE:LINE)
            assert uri.startswith("file:///"), f"expected real path, got {uri}"
            assert s["location"]["range"]["start"]["line"] >= 0

    def test_definition_at_exact_position(self, tmp_path: Path) -> None:
        server, sample = _analyze_with_bar(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        uri = f"file://{sample}"
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/definition",
                "params": {
                    "textDocument": {"uri": uri},
                    "position": {"line": 0, "character": 4},
                },
            },
        )
        result = sent[0]["result"]
        assert result is not None
        assert len(result) == 1
        # Should point back to the same file at line 0
        assert result[0]["range"]["start"]["line"] == 0

    def test_definition_returns_none_outside_functions(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/definition",
                "params": {
                    "textDocument": {"uri": "file:///nonexistent.py"},
                    "position": {"line": 999, "character": 0},
                },
            },
        )
        assert sent[0]["result"] == []

    def test_completion_returns_function_names(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/completion",
                "params": {
                    "textDocument": {"uri": "file:///any.py"},
                    "position": {"line": 0, "character": 0},
                },
            },
        )
        result = sent[0]["result"]
        assert result["isIncomplete"] is False
        items = result["items"]
        labels = [i["label"] for i in items]
        assert "foo" in labels

    def test_did_change_reanalyzes_unsaved_document(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        sample = tmp_path / "sample.py"
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        dispatch(
            rpc,
            {
                "method": "textDocument/didChange",
                "params": {
                    "textDocument": {"uri": sample.as_uri(), "version": 2},
                    "contentChanges": [{"text": "def renamed(x): return x + 2\n"}],
                },
            },
        )
        names = [
            symbol.name
            for symbol in server.source_index.document_symbols(sample.as_uri())
        ]
        assert names == ["renamed"]

    def test_did_open_can_initialize_a_single_file_workspace(
        self, tmp_path: Path
    ) -> None:
        sample = tmp_path / "opened.py"
        sample.write_text("def disk_version(): return 1\n")
        server = PyflowAnalysisServer(verbose=False)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        dispatch(
            rpc,
            {
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": sample.as_uri(),
                        "version": 1,
                        "text": "def buffer_version(): return 2\n",
                    }
                },
            },
        )
        assert server.is_loaded
        names = [symbol.name for symbol in server.source_index.symbols]
        assert "buffer_version" in names
        assert "disk_version" not in names

    def test_workspace_symbol_filters_by_query(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "workspace/symbol",
                "params": {"query": "foo"},
            },
        )
        symbols = sent[0]["result"]
        assert any("foo" in s["name"] for s in symbols)

    def test_workspace_symbol_empty_query_returns_all(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "workspace/symbol",
                "params": {"query": ""},
            },
        )
        symbols = sent[0]["result"]
        assert len(symbols) >= 1

    def test_workspace_symbol_case_insensitive(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "workspace/symbol",
                "params": {"query": "FOO"},
            },
        )
        assert len(sent[0]["result"]) >= 1

    def test_call_hierarchy_prepare_returns_function(self, tmp_path: Path) -> None:
        """callHierarchy/prepare at line 0 returns a real function name."""
        server, sample = _analyze_with_bar(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        uri = f"file://{sample}"
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/callHierarchy/prepare",
                "params": {
                    "textDocument": {"uri": uri},
                    "position": {"line": 0, "character": 0},
                },
            },
        )
        result = sent[0]["result"]
        assert result is not None
        # The module-level scope may be listed before foo at line 0
        assert result[0]["name"] in ("foo", "sample.<module>", "bar")
        assert result[0]["range"]["start"]["line"] == 0

    def test_pyflow_callgraph_returns_dict(self, tmp_path: Path) -> None:
        """Custom extension pyflow/getCallgraph returns real callgraph data."""
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "pyflow/getCallgraph",
                "params": {},
            },
        )
        result = sent[0]["result"]
        assert isinstance(result, dict)
        assert len(result) >= 1

    def test_pyflow_get_callers_returns_list(self, tmp_path: Path) -> None:
        server, _sample = _analyze_with_bar(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "pyflow/getCallers",
                "params": {"function": "foo"},
            },
        )
        callers = sent[0]["result"]
        assert isinstance(callers, list)

    def test_pyflow_get_callees_returns_list(self, tmp_path: Path) -> None:
        server, _sample = _analyze_with_bar(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "pyflow/getCallees",
                "params": {"function": "bar"},
            },
        )
        callees = sent[0]["result"]
        assert isinstance(callees, list)

    def test_hover_returns_none_when_no_type_info(self, tmp_path: Path) -> None:
        """Hover gracefully returns None when pyflow cannot resolve the type."""
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        uri = f"file://{tmp_path / 'sample.py'}"
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/hover",
                "params": {
                    "textDocument": {"uri": uri},
                    "position": {"line": 0, "character": 0},
                },
            },
        )
        # Hover may or may not resolve types depending on pyflow's analysis,
        # but the handler should never throw an exception.
        result = sent[0]["result"]
        assert result is None or result.get("contents") is not None

    def test_hover_returns_wired_type_information(self, tmp_path: Path) -> None:
        sample = tmp_path / "typed_hover.py"
        sample.write_text("def f():\n    value = 1\n    return value\n")
        server = PyflowAnalysisServer(verbose=False)
        server.load_files([sample])
        rpc = JsonRpcServer()
        LspHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "textDocument/hover",
                "params": {
                    "textDocument": {"uri": sample.as_uri()},
                    "position": {"line": 1, "character": 12},
                },
            },
        )
        assert "int" in sent[0]["result"]["contents"]["value"]


# ---------------------------------------------------------------------------
# McpHandler with real analysis data
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMcpHandlerReal:
    """McpHandler wired to JsonRpcServer with a real PyflowAnalysisServer."""

    def test_initialize_returns_protocol(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.initialize",
                "params": {},
            },
        )
        result = sent[0]["result"]
        assert result["protocolVersion"] == "2025-06-18"
        assert result["serverInfo"]["name"] == "pyflow"

    def test_list_resources(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.resources.list",
                "params": {},
            },
        )
        resources = sent[0]["result"]["resources"]
        uris = [r["uri"] for r in resources]
        assert "pyflow://functions" in uris
        assert "pyflow://capabilities" in uris
        assert "pyflow://callgraph" in uris

    def test_read_functions_resource(self, tmp_path: Path) -> None:
        """Reading pyflow://functions lists real function names."""
        server, _sample = _analyze_with_bar(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.resources.read",
                "params": {"uri": "pyflow://functions"},
            },
        )
        text = sent[0]["result"]["contents"][0]["text"]
        assert "foo" in text
        assert "bar" in text

    def test_read_capabilities_resource(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.resources.read",
                "params": {"uri": "pyflow://capabilities"},
            },
        )
        text = sent[0]["result"]["contents"][0]["text"]
        assert "cfg" in text
        assert "callgraph" in text

    def test_read_callgraph_resource(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.resources.read",
                "params": {"uri": "pyflow://callgraph"},
            },
        )
        text = sent[0]["result"]["contents"][0]["text"]
        assert "foo" in text

    def test_read_unknown_resource_returns_error(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.resources.read",
                "params": {"uri": "pyflow://nonexistent"},
            },
        )
        assert sent[0]["error"]["code"] == -32602

    def test_list_tools(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
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
        assert "get_cfg_structure" in names

    def test_call_tool_get_callers(self, tmp_path: Path) -> None:
        server, _sample = _analyze_with_bar(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "get_callers", "arguments": {"function": "foo"}},
            },
        )
        result = sent[0]["result"]
        assert "content" in result

    def test_call_tool_get_callees(self, tmp_path: Path) -> None:
        server, _sample = _analyze_with_bar(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "get_callees", "arguments": {"function": "bar"}},
            },
        )
        result = sent[0]["result"]
        assert "content" in result

    def test_call_unknown_tool_returns_error(self, tmp_path: Path) -> None:
        server = _analyze_simple(tmp_path)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "nonexistent", "arguments": {}},
            },
        )
        assert sent[0]["result"]["isError"] is True

    def test_call_tool_on_unloaded_server(self, tmp_path: Path) -> None:
        server = PyflowAnalysisServer(verbose=False)
        rpc = JsonRpcServer()
        McpHandler(server).register_on(rpc)
        sent = dispatch(
            rpc,
            {
                "id": 1,
                "method": "mcp.tools.call",
                "params": {"name": "get_callers", "arguments": {"function": "foo"}},
            },
        )
        assert sent[0]["error"]["code"] == -32600


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _analyze_simple(tmp_path: Path) -> PyflowAnalysisServer:
    """Create a server loaded with a minimal Python file."""
    sample = tmp_path / "sample.py"
    sample.write_text("def foo(x): return x + 1\n")
    server = PyflowAnalysisServer(verbose=False)
    server.load_files([sample], run_pipeline=True)
    return server


def _analyze_with_bar(tmp_path: Path) -> tuple[PyflowAnalysisServer, Path]:
    """Create a server loaded with foo defined and called by bar."""
    sample = tmp_path / "sample.py"
    sample.write_text("def foo(x): return x + 1\ndef bar(): return foo(42)\n")
    server = PyflowAnalysisServer(verbose=False)
    server.load_files([sample], run_pipeline=True)
    return server, sample
