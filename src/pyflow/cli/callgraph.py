"""
CLI functionality for call graph analysis.
"""

import sys
from pathlib import Path

from pyflow.analysis.callgraph.simple import analyze_file as analyze_file_simple
from pyflow.analysis.callgraph.pycg_based import analyze_file_pycg


def run_callgraph(input_path, args):
    """Build and visualize call graphs from Python code."""
    try:
        if not input_path.exists() or input_path.suffix != ".py":
            print(f"Error: '{input_path}' is not a valid Python file", file=sys.stderr)
            return 1

        # Generate call graph analysis based on selected algorithm
        if args.algorithm == "simple":
            output = analyze_file_simple(str(input_path))
        elif args.algorithm == "pycg":
            # Use the PyCG-based algorithm
            try:
                output = analyze_file_pycg(str(input_path), args.verbose)
            except ImportError:
                print("Error: PyCG algorithm not available. Install pycg package.", file=sys.stderr)
                return 1
        else:
            print(f"Error: Unknown algorithm '{args.algorithm}'", file=sys.stderr)
            return 1

        # Write output
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            if args.verbose:
                print(f"Call graph written to {args.output}")
        else:
            print(output)

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def add_callgraph_parser(subparsers):
    """Add call graph subcommand to the argument parser."""
    parser = subparsers.add_parser(
        "callgraph", help="Extract call graphs from Python code"
    )

    parser.add_argument("input", type=Path, help="Python file to analyze")

    parser.add_argument(
        "--algorithm",
        "-a",
        choices=["simple", "pycg"],
        default="simple",
        help="Call graph algorithm to use (default: simple)",
    )

    parser.add_argument(
        "--output", "-o", type=Path, help="Output file (default: stdout)"
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.set_defaults(func=run_callgraph)
