"""CLI support for Py-Conbyte-inspired concolic input generation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pyflow.concolic.engine import ConcolicError, explore_file


def add_concolic_parser(subparsers):
    """Register the ``concolic`` command."""
    parser = subparsers.add_parser(
        "concolic",
        help="Generate integer test inputs by concolically exploring a function",
    )
    parser.add_argument("input_path", help="Python file containing the target function")
    parser.add_argument(
        "--entry", default="main", help="Function to explore (default: main)"
    )
    parser.add_argument(
        "--inputs",
        help=(
            "Initial scalar/list/dictionary arguments as a JSON array "
            "(default: zero for each parameter)"
        ),
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=50,
        help="Maximum executions (default: 50)",
    )
    parser.add_argument(
        "--max-loop-iterations",
        type=int,
        default=100,
        help="Maximum concrete iterations of one while loop (default: 100)",
    )
    parser.add_argument(
        "--check-contracts",
        action="store_true",
        help="Check supported PEP 316 postconditions and report counterexamples",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON"
    )
    return parser


def run_concolic(args) -> int:
    """Run concolic exploration and print generated inputs."""
    initial_inputs = None
    if args.inputs is not None:
        try:
            initial_inputs = json.loads(args.inputs)
        except json.JSONDecodeError as error:
            print(f"Error: --inputs must be a JSON array: {error.msg}", file=sys.stderr)
            return 2
        if not isinstance(initial_inputs, list):
            print("Error: --inputs must be a JSON array", file=sys.stderr)
            return 2

    try:
        result = explore_file(
            Path(args.input_path),
            entry=args.entry,
            initial_inputs=initial_inputs,
            max_iterations=args.max_iterations,
            max_loop_iterations=args.max_loop_iterations,
            check_contracts=getattr(args, "check_contracts", False),
        )
    except (ConcolicError, OSError, SyntaxError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        parameters = ", ".join(result.parameter_names)
        print(
            f"Explored {len(result.runs)} execution(s) of {result.entry}({parameters})"
        )
        print("Generated inputs:")
        for run in result.runs:
            print(f"  {list(run.inputs)} -> {run.result!r}")
        if result.unsatisfiable_paths:
            print(f"Unsatisfiable path flips: {result.unsatisfiable_paths}")
        if result.counterexamples:
            print("Contract counterexamples:")
            for counterexample in result.counterexamples:
                print(
                    f"  {counterexample.clause!r}: "
                    f"{list(counterexample.inputs)} -> {counterexample.result!r}"
                )
    return 0
