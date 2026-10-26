"""
CLI commands for pyflow's LSP/MCP server and query interface.
"""

import asyncio
import json
import sys
import logging
from contextlib import redirect_stdout
from pathlib import Path

from pyflow.lsp import (
    JsonLineRpcServer,
    JsonRpcServer,
    AnalysisManager,
    LspHandler,
    McpHandler,
)
from pyflow.lsp.workspace import SourceIndex
from pyflow.analysis.callgraph.constraint_based import extract_call_graph_constraint
from pyflow.lsp.mcp_config import MCPServerMode, analysis_config_for_mode

from pyflow.frontend.entry_discovery import detect_entry_file

LOG = logging.getLogger(__name__)


# One-shot queries intentionally avoid the IPA/CPA pipeline. Function listing
# uses the lightweight AST index, while call queries use the dedicated
# constraint-based callgraph analysis.
_QUERY_REQUIRED_PASSES: dict[str, tuple[str, ...]] = {
    "list_functions": (),
    "get_cfg": (),
    "get_type": (),
    "get_callgraph": (),
    "get_callers": (),
    "get_callees": (),
    "get_aliases": ("heap",),
}

_SOURCE_QUERY_FLAGS = {
    "list_functions",
}

_CALLGRAPH_QUERY_FLAGS = {
    "get_callgraph",
    "get_callers",
    "get_callees",
}

_IGNORED_DIRECTORY_NAMES = {
    "site-packages",
    "node_modules",
    "build",
    "dist",
    "__pycache__",
    "venv",
}


def _compute_required_passes(args) -> list[str]:
    """Return the minimal pass targets needed for the requested queries."""
    passes: list[str] = []
    for attr_name, required in _QUERY_REQUIRED_PASSES.items():
        if getattr(args, attr_name, None):
            for p in required:
                if p not in passes:
                    passes.append(p)
    return passes


def _source_query_index(input_path: Path) -> SourceIndex:
    """Build the lightweight AST index used by source-only queries."""
    if input_path.is_file():
        root = input_path.parent
        python_files = [input_path]
    else:
        root = input_path
        python_files = sorted(
            path
            for path in root.rglob("*.py")
            if not any(part.startswith(".") for part in path.relative_to(root).parts)
            and not set(path.parts).intersection(_IGNORED_DIRECTORY_NAMES)
        )
    from pyflow.ir.mir.lowering import _default_root

    root = _default_root(root / "__init__.py")
    source_files = {str(path.absolute()): path.read_text(encoding="utf-8") for path in python_files}
    return SourceIndex(source_files, (root.absolute(),))


def _dispatch_source_query(index: SourceIndex, args) -> object:
    """Dispatch queries that can be answered directly from Python source."""
    stale = sorted(
        path for path, shard in index._file_indices.items() if getattr(shard, "syntax_stale", False)
    )
    if stale:
        import ast

        from pyflow.language.source_compat import normalize_legacy_python_syntax

        single_file = len(index.source_files) == 1
        for path in stale:
            try:
                ast.parse(
                    normalize_legacy_python_syntax(index.source_files[path]),
                    filename=path,
                )
            except (SyntaxError, ValueError, RecursionError) as exc:
                label = "Error" if single_file else "Warning"
                print(f"{label}: Could not parse {path}: {exc}", file=sys.stderr)
        if single_file:
            sys.exit(1)
    return sorted(symbol.qualified_name for symbol in index.symbols if symbol.kind in {6, 12})


def _uses_source_index(args) -> bool:
    return any(getattr(args, name, None) for name in _SOURCE_QUERY_FLAGS)


def _uses_callgraph_analysis(args) -> bool:
    return any(getattr(args, name, None) for name in _CALLGRAPH_QUERY_FLAGS)


def _callgraph_entry(input_path: Path) -> Path:
    if input_path.is_file():
        return input_path
    entry = detect_entry_file(input_path)
    if entry is None:
        raise ValueError(
            f"No callgraph entry point detected in '{input_path}'. "
            "Use the 'pyflow callgraph' command with --entry for this project."
        )
    return input_path / str(entry)


def _run_callgraph_analysis(input_path: Path) -> dict[str, list[str]]:
    """Run the dedicated callgraph analysis without IPA or CPA."""
    entry = _callgraph_entry(input_path).resolve()
    try:
        source = entry.read_text(encoding="utf-8")
        callgraph = extract_call_graph_constraint(
            source,
            source_path=str(entry),
            allocation_site_sensitive_instances=False,
            skip_stdlib_modules=True,
            canonical_entry_names=True,
            additional_sources=_source_query_index(input_path).source_files,
        )
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise ValueError(f"Could not analyze {entry}: {exc}") from exc
    return {caller: sorted(callees) for caller, callees in sorted(callgraph.get().items())}


def _resolve_callgraph_node(
    graph: dict[str, list[str]], name: str, entry_module: str | None = None
) -> str:
    if name in graph:
        return name
    # Accept the old entry namespace as an alias for canonical module names.
    if entry_module and name.startswith("main."):
        entry_name = entry_module + name[4:]
        if entry_name in graph:
            return entry_name
    matches = sorted(node for node in graph if node == name or node.endswith(f".{name}"))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(f"Function name '{name}' is ambiguous: {', '.join(matches[:5])}")
    raise ValueError(f"Function '{name}' not found in the call graph")


def _dispatch_callgraph_query(
    graph: dict[str, list[str]], args, entry_module: str | None = None
) -> object:
    if args.get_callers:
        target = _resolve_callgraph_node(graph, args.get_callers, entry_module)
        return sorted(caller for caller, callees in graph.items() if target in callees)
    if args.get_callees:
        source = _resolve_callgraph_node(graph, args.get_callees, entry_module)
        return graph[source]
    return graph


def _add_mode_argument(parser):
    parser.add_argument(
        "--mode",
        choices=[mode.value for mode in MCPServerMode],
        default=MCPServerMode.FULL.value,
        help="Analysis depth: basic, full, or advanced",
    )


def add_lsp_parser(subparsers):
    p = subparsers.add_parser("lsp", help="Run pyflow as a Language Server Protocol server")
    p.add_argument(
        "--root",
        "-r",
        type=Path,
        help="Project root directory",
    )
    _add_mode_argument(p)
    p.set_defaults(func=run_lsp)


def add_mcp_parser(subparsers):
    p = subparsers.add_parser("mcp", help="Run pyflow as a Model Context Protocol server")
    p.add_argument(
        "--root",
        "-r",
        type=Path,
        help="Project root directory",
    )
    _add_mode_argument(p)
    p.set_defaults(func=run_mcp)


def add_query_parser(subparsers):
    p = subparsers.add_parser("query", help="Query pyflow analysis results (one-shot)")
    p.add_argument(
        "input_path",
        type=Path,
        help="Python file or project directory to analyze",
    )
    _add_mode_argument(p)
    p.add_argument(
        "--get-callers",
        type=str,
        metavar="FUNCTION",
        help="List callers of a function",
    )
    p.add_argument(
        "--get-callees",
        type=str,
        metavar="FUNCTION",
        help="List callees of a function",
    )
    p.add_argument(
        "--get-callgraph",
        action="store_true",
        help="Return the full call graph",
    )
    p.add_argument(
        "--get-type",
        nargs=3,
        metavar=("MODULE", "LINE", "COL"),
        help=(
            "Get type at source position (MODULE is a module name such as "
            "'pkg.mod'; LINE is 1-based; COL is a 0-based column)"
        ),
    )
    p.add_argument(
        "--include-diagnostics",
        action="store_true",
        help="Include type-analysis status and structured diagnostics in --get-type JSON",
    )
    p.add_argument(
        "--get-cfg",
        type=str,
        metavar="FUNCTION",
        help="Get CFG for a qualified function or an unambiguous short name (e.g. Class.method)",
    )
    p.add_argument(
        "--get-aliases",
        type=str,
        metavar="VARIABLE",
        help="Get alias information for a variable",
    )
    p.add_argument(
        "--list-functions",
        action="store_true",
        help="List all known functions",
    )
    p.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Write output to file instead of stdout",
    )
    p.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    p.set_defaults(func=run_query)


def _run_server(args, handler_cls):
    """Run a JSON-RPC server (LSP or MCP) over stdio."""
    mode = MCPServerMode(getattr(args, "mode", MCPServerMode.FULL.value))
    server = AnalysisManager(analysis_config=analysis_config_for_mode(mode))

    # Capture the protocol stream before redirecting all incidental prints,
    # including background compiler output, for the entire server lifetime.
    rpc_type = JsonLineRpcServer if handler_cls is McpHandler else JsonRpcServer
    rpc = rpc_type(output_stream=sys.stdout.buffer)
    with redirect_stdout(sys.stderr):
        if getattr(args, "root", None):
            try:
                if handler_cls is LspHandler:
                    server.load_source_workspaces([str(args.root)])
                else:
                    server.load(str(args.root))
                LOG.info("Loaded project: %s", args.root)
            except Exception as exc:
                LOG.warning("Deferred load failed: %s", exc)
        handler_cls(server).register_on(rpc)
        asyncio.run(rpc.run())


def run_lsp(args):
    """Run pyflow as an LSP server over stdio."""
    _run_server(args, LspHandler)


def run_mcp(args):
    """Run pyflow as an MCP server over stdio."""
    _run_server(args, McpHandler)


def run_query(args):
    from pyflow.model.errors import TemporaryLimitation

    try:
        return _run_query(args)
    except (TemporaryLimitation, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


def _run_query(args):
    """Run a one-shot analysis query."""
    input_path = args.input_path

    if not input_path.exists():
        print(f"Error: '{input_path}' not found", file=sys.stderr)
        sys.exit(1)

    if _uses_source_index(args):
        result = _dispatch_source_query(_source_query_index(input_path), args)
        _write_query_result(result, args)
        return

    if _uses_callgraph_analysis(args):
        try:
            graph = _run_callgraph_analysis(input_path)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        _write_query_result(
            _dispatch_callgraph_query(graph, args, _callgraph_entry(input_path).stem), args
        )
        return

    mode = MCPServerMode(getattr(args, "mode", MCPServerMode.FULL.value))
    server = AnalysisManager(analysis_config=analysis_config_for_mode(mode))

    required_passes = _compute_required_passes(args)
    run_pipeline = bool(required_passes)

    # Keep progress from the extraction pipeline out of the JSON result stream.
    with redirect_stdout(sys.stderr):
        if input_path.is_dir():
            server.load(
                str(input_path),
                run_pipeline=run_pipeline,
                passes=required_passes,
            )
        elif input_path.is_file():
            server.load_files(
                [input_path],
                run_pipeline=run_pipeline,
                passes=required_passes,
            )
        else:
            print(f"Error: '{input_path}' not found", file=sys.stderr)
            sys.exit(1)

    _fail_on_unparsed_input(server.program, input_path)
    result = _dispatch_query(server, args)

    _write_query_result(result, args)


def _fail_on_unparsed_input(program, input_path: Path) -> None:
    """Report parse failures for a single-file query instead of empty results."""
    if not input_path.is_file():
        return
    failures = [
        diagnostic
        for diagnostic in getattr(program, "frontend_diagnostics", ())
        if getattr(diagnostic, "stage", None) == "parse"
    ]
    if not failures:
        return
    for diagnostic in failures:
        print(
            f"Error: Could not parse {diagnostic.filename}: "
            f"{diagnostic.exception_type}: {diagnostic.message}",
            file=sys.stderr,
        )
    sys.exit(1)


def _write_query_result(result: object, args) -> None:
    indent = 2 if args.pretty else None
    output = json.dumps(result, indent=indent, default=str)

    if hasattr(args, "output") and args.output:
        args.output.write_text(output)
    else:
        print(output)


def _dispatch_query(server: AnalysisManager, args) -> object:
    snapshot = server.current_snapshot()
    if args.get_callers:
        return snapshot.queries.call_graph.get_callers(args.get_callers)
    if args.get_callees:
        return snapshot.queries.call_graph.get_callees(args.get_callees)
    if args.get_callgraph:
        return snapshot.queries.call_graph.get_callgraph_data()
    if args.get_type:
        module, line, col = args.get_type
        result = snapshot.queries.type_info.get_expression_type(module, int(line), int(col))
        status = snapshot.queries.type_info.get_analysis_status(module)
        diagnostics = snapshot.queries.type_info.get_diagnostics()
        if getattr(args, "include_diagnostics", False):
            from dataclasses import asdict

            return {
                "type": str(result) if result is not None else None,
                "status": status,
                "diagnostics": [asdict(item) for item in diagnostics],
            }
        if status == "partial":
            print(
                f"Warning: type analysis for {module!r} is partial; "
                "use --include-diagnostics for details",
                file=sys.stderr,
            )
        return {"type": str(result)} if result is not None else None
    if args.get_cfg:
        return snapshot.queries.control_flow.get_cfg_structure(args.get_cfg)
    if args.get_aliases:
        info = snapshot.queries.data_flow.get_aliases_for_variable(args.get_aliases)
        return {
            "variable": info.variable,
            "aliases": sorted(info.aliases),
            "is_aliased": info.is_aliased,
            "ref_count": info.ref_count,
            "is_escaped": info.is_escaped,
        }
    if args.list_functions:
        from pyflow.api.queries.context import QueryContext

        return sorted(
            (
                getattr(code, "codeName", lambda: "?")()
                if hasattr(code, "codeName") and callable(getattr(code, "codeName", None))
                else str(getattr(code, "name", "?"))
            )
            for code in QueryContext(None, server.program).function_codes()
        )
    return snapshot.features.__dict__
