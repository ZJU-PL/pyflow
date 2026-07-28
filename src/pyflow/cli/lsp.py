"""
CLI commands for pyflow's LSP/MCP server and query interface.
"""

import asyncio
import json
import sys
import logging
from pathlib import Path

from pyflow.lsp import (
    JsonLineRpcServer,
    JsonRpcServer,
    PyflowAnalysisServer,
    LspHandler,
    McpHandler,
)
from pyflow.api.queries import MCPServerMode

LOG = logging.getLogger(__name__)


def _add_mode_argument(parser):
    parser.add_argument(
        "--mode",
        choices=[mode.value for mode in MCPServerMode],
        default=MCPServerMode.FULL.value,
        help="Analysis depth: basic, full, or advanced",
    )


def add_lsp_parser(subparsers):
    p = subparsers.add_parser(
        "lsp", help="Run pyflow as a Language Server Protocol server"
    )
    p.add_argument(
        "--root",
        "-r",
        type=Path,
        help="Project root directory",
    )
    _add_mode_argument(p)
    p.set_defaults(func=run_lsp)


def add_mcp_parser(subparsers):
    p = subparsers.add_parser(
        "mcp", help="Run pyflow as a Model Context Protocol server"
    )
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
        help="Get type at source position",
    )
    p.add_argument(
        "--get-cfg",
        type=str,
        metavar="FUNCTION",
        help="Get CFG structure for a function",
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
    server = PyflowAnalysisServer(server_mode=mode)

    if hasattr(args, "root") and args.root:
        try:
            server.load(str(args.root))
            LOG.info("Loaded project: %s", args.root)
        except Exception as exc:
            LOG.warning("Deferred load failed: %s", exc)

    rpc = JsonLineRpcServer() if handler_cls is McpHandler else JsonRpcServer()
    handler_cls(server).register_on(rpc)
    asyncio.run(rpc.run())


def run_lsp(args):
    """Run pyflow as an LSP server over stdio."""
    _run_server(args, LspHandler)


def run_mcp(args):
    """Run pyflow as an MCP server over stdio."""
    _run_server(args, McpHandler)


def run_query(args):
    """Run a one-shot analysis query."""
    mode = MCPServerMode(getattr(args, "mode", MCPServerMode.FULL.value))
    server = PyflowAnalysisServer(server_mode=mode)
    input_path = args.input_path

    if input_path.is_dir():
        server.load(str(input_path))
    elif input_path.is_file():
        server.load_files([input_path])
    else:
        print(f"Error: '{input_path}' not found", file=sys.stderr)
        sys.exit(1)

    result = _dispatch_query(server, args)
    indent = 2 if args.pretty else None
    output = json.dumps(result, indent=indent, default=str)

    if hasattr(args, "output") and args.output:
        args.output.write_text(output)
    else:
        print(output)


def _dispatch_query(server: PyflowAnalysisServer, args) -> object:
    if args.get_callers:
        return server.get_callers(args.get_callers)
    if args.get_callees:
        return server.get_callees(args.get_callees)
    if args.get_callgraph:
        return server.get_callgraph_data()
    if args.get_type:
        module, line, col = args.get_type
        return server.get_expression_type(module, int(line), int(col))
    if args.get_cfg:
        return server.get_cfg_structure(args.get_cfg)
    if args.get_aliases:
        return server.get_aliases_for_variable(args.get_aliases)
    if args.list_functions:
        return sorted(
            (
                getattr(code, "codeName", lambda: "?")()
                if hasattr(code, "codeName")
                and callable(getattr(code, "codeName", None))
                else str(getattr(code, "name", "?"))
            )
            for code in getattr(server.program, "liveCode", [])
        )
    return server.get_capabilities()
