"""
CLI functionality for call graph analysis.
"""

import sys
from pathlib import Path

from pyflow.analysis.callgraph.algorithms.registry import registry
from pyflow.analysis.callgraph.formats import generate_text_output, generate_dot_output, generate_json_output


def run_callgraph(input_path, args):
    """Build and visualize call graphs from Python code."""
    try:
        # Handle list algorithms option
        if args.list_algorithms:
            print("Available call graph algorithms:")
            print("=" * 40)
            for name, info in registry.list_all_info().items():
                print(f"{name}: {info['description']}")
            return 0

        if not input_path.exists() or input_path.suffix != ".py":
            print(f"Error: '{input_path}' is not a valid Python file", file=sys.stderr)
            return 1

        with open(input_path, "r") as f:
            source_code = f.read()

        # Try to use the selected algorithm
        try:
            algorithm_class = registry.get_algorithm(args.algorithm)
            extractor = algorithm_class(verbose=args.verbose)
            call_graph = extractor.extract_from_source(source_code, args)

            format_generators = {
                "text": generate_text_output,
                "dot": generate_dot_output,
                "json": generate_json_output,
            }

            if args.format not in format_generators:
                print(f"Error: Unknown format '{args.format}'", file=sys.stderr)
                return 1

            output = format_generators[args.format](call_graph, args)

        except (ImportError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
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
        "callgraph", help="Build and visualize call graphs from Python code"
    )

    parser.add_argument("input", type=Path, help="Python file to analyze")

    # Algorithm selection
    available_algorithms = registry.list_algorithms()
    parser.add_argument(
        "--algorithm",
        "-a",
        choices=available_algorithms,
        default=available_algorithms[0] if available_algorithms else "ast",
        help=f"Call graph algorithm to use (default: {available_algorithms[0] if available_algorithms else 'ast'})",
    )

    parser.add_argument(
        "--list-algorithms",
        action="store_true",
        help="List all available algorithms and exit",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "dot", "json"],
        default="text",
        help="Output format (default: text)",
    )

    parser.add_argument(
        "--output", "-o", type=Path, help="Output file (default: stdout)"
    )

    parser.add_argument(
        "--max-depth", "-d", type=int, help="Maximum call depth to analyze"
    )

    parser.add_argument(
        "--show-cycles",
        action="store_true",
        help="Detect and show cycles in the call graph",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.set_defaults(func=run_callgraph)
