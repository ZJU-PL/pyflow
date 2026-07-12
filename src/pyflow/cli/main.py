"""Main CLI dispatcher for PyFlow.

This module provides the main command-line interface for PyFlow, dispatching
commands to appropriate sub-modules for optimization, analysis, and other
operations.
"""

import sys
import argparse
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
from .heap import run_heap_analysis, add_heap_parser


def main():
    """Main entry point for the PyFlow CLI.

    Parses command-line arguments and dispatches to appropriate sub-commands.
    """
    parser = argparse.ArgumentParser(
        description="PyFlow - A static compiler for Python", prog="pyflow"
    )

    parser.add_argument("--version", action="version", version="PyFlow 0.1.0")

    subparsers = parser.add_subparsers(
        dest="command", help="Available commands", required=True
    )

    # Optimization command
    add_optimize_parser(subparsers)

    # Call graph command
    callgraph.add_callgraph_parser(subparsers)

    # IR dumping command
    add_ir_parser(subparsers)

    # Heap analysis command
    add_heap_parser(subparsers)

    # Unified security analysis command
    add_security_parser(subparsers)

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
    elif args.command == "heap":
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
    elif args.command == "heap":
        return run_heap_analysis(args.input_path, args)
    elif args.command == "security":
        return run_security(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
