"""
CLI functionality for call graph analysis.
"""

import json
import sys
from pathlib import Path

from pyflow.analysis.callgraph.ast_based import analyze_file as analyze_file_ast
from pyflow.analysis.callgraph.constraint_based import (
    analyze_file_constraint,
    extract_value_flow_graph_constraint,
)
from pyflow.analysis.callgraph.pycg_based import analyze_file_pycg


def _validate_algorithm_options(args) -> bool:
    if args.algorithm == "constraint":
        return True

    incompatible_flags = []
    if getattr(args, "context_sensitive", False):
        incompatible_flags.append("--context-sensitive")
    if getattr(args, "context_depth", 1) != 1:
        incompatible_flags.append("--context-depth")
    if getattr(args, "fixpoint_max_iterations", None) is not None:
        incompatible_flags.append("--fixpoint-max-iterations")
    if getattr(args, "no_fixpoint_warning", False):
        incompatible_flags.append("--no-fixpoint-warning")
    if getattr(args, "allocation_site_sensitive_instances", False):
        incompatible_flags.append("--allocation-site-sensitive-instances")
    if getattr(args, "as_graph_output", None):
        incompatible_flags.append("--as-graph-output")

    if incompatible_flags:
        joined = ", ".join(incompatible_flags)
        print(
            "Error: "
            f"{joined} are only supported with --algorithm constraint",
            file=sys.stderr,
        )
        return False
    return True


def run_callgraph(input_path, args):
    """Build and visualize call graphs from Python code."""
    try:
        if not input_path.exists() or input_path.suffix != ".py":
            print(f"Error: '{input_path}' is not a valid Python file", file=sys.stderr)
            return 1

        if not _validate_algorithm_options(args):
            return 1

        # Generate call graph analysis based on selected algorithm
        if args.algorithm == "simple":
            output = analyze_file_ast(str(input_path))
        elif args.algorithm == "constraint":
            output = analyze_file_constraint(
                str(input_path),
                verbose=args.verbose,
                context_sensitive=args.context_sensitive,
                context_depth=args.context_depth,
                fixpoint_max_iterations=args.fixpoint_max_iterations,
                warn_on_fixpoint_truncation=not args.no_fixpoint_warning,
                allocation_site_sensitive_instances=args.allocation_site_sensitive_instances,
            )
        elif args.algorithm == "pycg":
            # Use the PyCG-based algorithm
            try:
                output = analyze_file_pycg(str(input_path), args.verbose)
            except ImportError:
                print(
                    "Error: PyCG algorithm not available. Install pycg package.",
                    file=sys.stderr,
                )
                return 1
        else:
            print(f"Error: Unknown algorithm '{args.algorithm}'", file=sys.stderr)
            return 1

        if args.as_graph_output:
            if args.algorithm != "constraint":
                print(
                    "Error: --as-graph-output is currently supported only with --algorithm constraint",
                    file=sys.stderr,
                )
                return 1
            with open(input_path, "r", encoding="utf-8") as handle:
                source = handle.read()
            as_graph = extract_value_flow_graph_constraint(
                source_code=source,
                source_path=str(input_path),
                verbose=args.verbose,
                context_sensitive=args.context_sensitive,
                context_depth=args.context_depth,
                fixpoint_max_iterations=args.fixpoint_max_iterations,
                warn_on_fixpoint_truncation=not args.no_fixpoint_warning,
                allocation_site_sensitive_instances=args.allocation_site_sensitive_instances,
            )
            with open(args.as_graph_output, "w", encoding="utf-8") as handle:
                json.dump(as_graph, handle, indent=2, sort_keys=True)
            if args.verbose:
                print(f"Value-flow graph written to {args.as_graph_output}")

        # Write output
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
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
        choices=["simple", "constraint", "pycg"],
        default="simple",
        help="Call graph algorithm to use (default: simple)",
    )

    parser.add_argument(
        "--output", "-o", type=Path, help="Output file (default: stdout)"
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "--context-sensitive",
        action="store_true",
        help="Enable call-site context sensitivity (constraint algorithm only)",
    )
    parser.add_argument(
        "--context-depth",
        type=int,
        default=1,
        help="Call-string depth when --context-sensitive is enabled",
    )
    parser.add_argument(
        "--fixpoint-max-iterations",
        type=int,
        default=None,
        help="Cap fixpoint iterations (constraint algorithm only)",
    )
    parser.add_argument(
        "--no-fixpoint-warning",
        action="store_true",
        help="Disable warning when fixpoint cap is hit (constraint algorithm only)",
    )
    parser.add_argument(
        "--allocation-site-sensitive-instances",
        action="store_true",
        help="Track per-allocation instance identities (constraint algorithm only)",
    )
    parser.add_argument(
        "--as-graph-output",
        type=Path,
        default=None,
        help="Write constraint value-flow assignment graph JSON (debug output)",
    )

    parser.set_defaults(func=run_callgraph)
