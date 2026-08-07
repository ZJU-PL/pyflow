"""Main CLI dispatcher for PyFlow.

This module provides the main command-line interface for PyFlow, dispatching
commands to appropriate sub-modules for optimization, analysis, and other
operations.
"""

import sys
import argparse
import gc
from pathlib import Path


def _bootstrap_src_path() -> None:
    """Allow running this file directly without mutating sys.path on import."""
    if __package__:
        return

    src_root = str(Path(__file__).resolve().parents[2])
    if src_root not in sys.path:
        sys.path.insert(0, src_root)


_bootstrap_src_path()

from .optimize import run_analysis, list_optimization_passes, add_optimize_parser
from .ir import run_ir_dump, add_ir_parser
from .security import run_security, add_security_parser
from . import callgraph
from .alias import run_alias_analysis, add_alias_parser
from .supply_chain import add_supply_chain_parser, run_supply_chain
from .lsp import add_lsp_parser, add_mcp_parser, add_query_parser, run_lsp, run_mcp, run_query


def main():
    """Main entry point for the PyFlow CLI.

    Parses command-line arguments and dispatches to appropriate sub-commands.
    """
    parser = argparse.ArgumentParser(
        description="PyFlow - A static compiler for Python", prog="pyflow"
    )

    from pyflow import __version__
    parser.add_argument("--version", action="version", version=f"PyFlow {__version__}")

    subparsers = parser.add_subparsers(
        dest="command", help="Available commands", required=True
    )

    # Optimization command
    add_optimize_parser(subparsers)

    # Call graph command
    callgraph.add_callgraph_parser(subparsers)

    # IR dumping command
    add_ir_parser(subparsers)

    add_alias_parser(subparsers)

    # Unified security analysis command
    add_security_parser(subparsers)

    # Supply-chain analysis command
    add_supply_chain_parser(subparsers)

    # LSP / MCP / Query commands
    add_lsp_parser(subparsers)
    add_mcp_parser(subparsers)
    add_query_parser(subparsers)

    args = parser.parse_args()

    # Handle special commands that don't require input
    if (
        args.command == "optimize"
        and hasattr(args, "list_opt_passes")
        and args.list_opt_passes
    ):
        list_optimization_passes()
        return 0

    # Get input path based on command
    if args.command == "optimize":
        if args.input_path is None:
            print("Error: input_path is required for optimization", file=sys.stderr)
            sys.exit(1)
        input_path = Path(args.input_path)
    elif args.command == "callgraph":
        input_path = Path(args.input)
    elif args.command == "ir":
        if args.input_path is None:
            print("Error: input_path is required for IR dumping", file=sys.stderr)
            sys.exit(1)
        input_path = Path(args.input_path)
    elif args.command == "security":
        input_path = None
    elif args.command == "supply-chain":
        input_path = None
    elif args.command == "alias":
        input_path = Path(args.input_path)
    else:
        input_path = None

    # Validate input path
    if input_path and not input_path.exists():
        print(f"Error: Path '{input_path}' not found", file=sys.stderr)
        return 1

    # Dispatch to appropriate command
    if args.command == "optimize":
        run_analysis(input_path, args)
        return 0
    elif args.command == "callgraph":
        return callgraph.run_callgraph(input_path, args)
    elif args.command == "ir":
        run_ir_dump(input_path, args)
        return 0
    elif args.command == "alias":
        return run_alias_analysis(args.input_path, args)
    elif args.command == "security":
        return run_security(args)
    elif args.command == "supply-chain":
        return run_supply_chain(args)
    elif args.command == "lsp":
        run_lsp(args)
        return 0
    elif args.command == "mcp":
        run_mcp(args)
        return 0
    elif args.command == "query":
        run_query(args)
        return 0
    else:
        parser.print_help()
        return 1


def entrypoint():
    """Console-script entry point with fast process teardown.

    Large CPG scans can leave a substantial cyclic IR object graph for the
    interpreter's shutdown collector.  The operating system is about to
    reclaim the whole process, so freezing tracked objects after command
    completion avoids redundant traversal without affecting embedded users of
    :func:`main`.
    """

    exit_code = main()
    gc.freeze()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
