"""Main CLI dispatcher for PyFlow."""

import sys
import argparse
from pathlib import Path

# Add the src directory to the path so we can import pyflow modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from .optimize import run_analysis
from pyflow.analysis.callgraph import run_callgraph, add_callgraph_parser


def list_optimization_passes():
    """List all available optimization passes."""
    print("Available optimization passes:")
    print()

    passes = [
        ("methodcall", "Fuse method calls and optimize method dispatch"),
        ("lifetime", "Lifetime analysis for variables and objects"),
        ("simplify", "Constant folding and dead code elimination"),
        ("clone", "Separate different invocations of the same code"),
        (
            "argumentnormalization",
            "Normalize function arguments (eliminate *args, **kwargs)",
        ),
        ("inlining", "Inline function calls where beneficial"),
        ("cullprogram", "Remove dead functions and contexts"),
        ("loadelimination", "Eliminate redundant load operations"),
        ("storeelimination", "Eliminate redundant store operations"),
        ("dce", "Dead code elimination"),
    ]

    for pass_name, description in passes:
        print(f"  {pass_name:<25} - {description}")

    print()
    print("Usage examples:")
    print("  pyflow optimize --passes methodcall inlining")
    print("  pyflow optimize --passes simplify dce --no-passes")
    print("  pyflow optimize --passes all  # Run all passes (default)")


def main():
    """Main entry point for the PyFlow CLI."""
    parser = argparse.ArgumentParser(
        description="PyFlow - A static compiler for Python", prog="pyflow"
    )

    parser.add_argument("--version", action="version", version="PyFlow 0.1.0")

    subparsers = parser.add_subparsers(
        dest="command", help="Available commands", required=True
    )

    # Optimization command
    analysis_parser = subparsers.add_parser(
        "optimize", help="Run static analysis and optimization on Python code"
    )
    analysis_parser.add_argument(
        "input_path", nargs="?", help="Python file, directory, or library to optimize"
    )
    analysis_parser.add_argument("--output", "-o", help="Output file for results")
    analysis_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    analysis_parser.add_argument(
        "--analysis",
        "-a",
        choices=["all", "cpa", "ipa", "shape", "lifetime"],
        default="all",
        help="Type of analysis to run (default: all)",
    )
    analysis_parser.add_argument(
        "--dump", "-d", action="store_true", help="Dump analysis results to files"
    )
    analysis_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively analyze subdirectories",
    )
    analysis_parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="Patterns to exclude from analysis (e.g., 'test_*', '__pycache__')",
    )
    analysis_parser.add_argument(
        "--include",
        nargs="*",
        default=["*.py"],
        help="File patterns to include in analysis (default: *.py)",
    )

    # AST and CFG dumping options
    analysis_parser.add_argument(
        "--dump-ast",
        metavar="FUNCTION",
        help="Dump AST for the specified function name",
    )
    analysis_parser.add_argument(
        "--dump-cfg",
        metavar="FUNCTION",
        help="Dump CFG for the specified function name",
    )
    analysis_parser.add_argument(
        "--dump-format",
        choices=["text", "dot", "json"],
        default="text",
        help="Format for AST/CFG dumps (default: text)",
    )
    analysis_parser.add_argument(
        "--dump-output",
        help="Output directory for AST/CFG dumps (default: current directory)",
    )

    # Optimization passes selection
    analysis_parser.add_argument(
        "--opt-passes",
        nargs="*",
        help="Specific optimization passes to run (e.g., 'methodcall', 'inlining', 'dce')",
    )
    analysis_parser.add_argument(
        "--list-opt-passes",
        action="store_true",
        help="List all available optimization passes",
    )
    analysis_parser.add_argument(
        "--no-opt-passes",
        action="store_true",
        help="Skip all optimization passes (analysis only)",
    )

    # Call graph command - use the modular parser
    add_callgraph_parser(subparsers)

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
        return run_callgraph(input_path, args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
