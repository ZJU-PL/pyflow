"""Main CLI dispatcher for PyFlow.

This module provides the main command-line interface for PyFlow, dispatching
commands to appropriate sub-modules for optimization, analysis, and other
operations.
"""

import sys
import argparse
from pathlib import Path

# Add the src directory to the path so we can import pyflow modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from .optimize import run_analysis, list_optimization_passes, add_optimize_parser
from .ir import run_ir_dump, add_ir_parser
from .security import run_security_analysis, add_security_parser
from . import callgraph



def main():
    """Main entry point for the PyFlow CLI.
    
    Parses command-line arguments and dispatches to appropriate sub-commands
    for optimization, call graph analysis, IR dumping, and security analysis.
    
    Returns:
        int: Exit code (0 for success, non-zero for error).
    """
    parser = argparse.ArgumentParser(
        description="PyFlow - A static compiler for Python", prog="pyflow"
    )

    parser.add_argument("--version", action="version", version="PyFlow 0.1.0")

    subparsers = parser.add_subparsers(
        dest="command", help="Available commands", required=True
    )

    # Optimization command - use the modular parser
    add_optimize_parser(subparsers)

    # Call graph command - use the modular parser
    callgraph.add_callgraph_parser(subparsers)
    
    # IR dumping command - use the modular parser
    add_ir_parser(subparsers)
    
    # Security analysis command - use the modular parser
    add_security_parser(subparsers)

    args = parser.parse_args()

    # Handle special commands that don't require input
    if args.command == "optimize" and hasattr(args, "list_opt_passes") and args.list_opt_passes:
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
        # Security command handles its own targets
        input_path = None
    else:
        input_path = None

    # Validate input path
    if input_path and not input_path.exists():
        print(f"Error: Path '{input_path}' not found", file=sys.stderr)
        sys.exit(1)

    # Dispatch to appropriate command
    if args.command == "optimize":
        run_analysis(input_path, args)
    elif args.command == "callgraph":
        return callgraph.run_callgraph(input_path, args)
    elif args.command == "ir":
        run_ir_dump(input_path, args)
    elif args.command == "security":
        return run_security_analysis(args.targets, args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
