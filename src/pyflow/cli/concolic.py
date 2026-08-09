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
        help="Generate test inputs by concolically exploring a function",
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
        "--max-resume-steps",
        type=int,
        default=1000,
        help="Maximum iterator/generator resume operations (default: 1000)",
    )
    parser.add_argument(
        "--scheduler",
        choices=("fifo", "nondeterministic"),
        default="fifo",
        help="Async task scheduling policy (default: fifo)",
    )
    parser.add_argument(
        "--max-task-switches",
        type=int,
        default=1000,
        help="Maximum async task scheduling steps (default: 1000)",
    )
    parser.add_argument(
        "--max-schedule-states",
        type=int,
        default=1000,
        help="Maximum nondeterministic schedule prefixes per input (default: 1000)",
    )
    parser.add_argument(
        "--search-strategy",
        choices=("fifo", "coverage"),
        default="coverage",
        help="Pending-state selection strategy (default: coverage)",
    )
    parser.add_argument(
        "--max-uninteresting-iterations",
        type=int,
        help="Stop after this many executions without new AST coverage",
    )
    parser.add_argument(
        "--total-timeout",
        type=float,
        help="Maximum wall-clock seconds for the complete exploration",
    )
    parser.add_argument(
        "--per-run-timeout",
        type=float,
        help="Maximum wall-clock seconds for one concrete execution",
    )
    parser.add_argument(
        "--solver-timeout",
        type=float,
        help="Maximum wall-clock seconds for one solver query",
    )
    parser.add_argument(
        "--max-solver-calls",
        type=int,
        help="Maximum number of solver queries",
    )
    parser.add_argument(
        "--max-pending-states",
        type=int,
        default=10000,
        help="Maximum queued exploration states (default: 10000)",
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
            max_resume_steps=getattr(args, "max_resume_steps", 1000),
            scheduler=getattr(args, "scheduler", "fifo"),
            max_task_switches=getattr(args, "max_task_switches", 1000),
            max_schedule_states=getattr(args, "max_schedule_states", 1000),
            search_strategy=getattr(args, "search_strategy", "coverage"),
            max_uninteresting_iterations=getattr(
                args, "max_uninteresting_iterations", None
            ),
            total_timeout=getattr(args, "total_timeout", None),
            per_run_timeout=getattr(args, "per_run_timeout", None),
            solver_timeout=getattr(args, "solver_timeout", None),
            max_solver_calls=getattr(args, "max_solver_calls", None),
            max_pending_states=getattr(args, "max_pending_states", 10000),
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
            schedule = f" schedule={list(run.schedule)}" if run.schedule else ""
            outcome = run.outcome.kind.value
            print(
                f"  {list(run.inputs)} -> {run.result!r} "
                f"outcome={outcome}{schedule}"
            )
        print(
            "Coverage: "
            f"{len(result.coverage.nodes)} AST node(s), "
            f"{len(result.coverage.branches)} branch edge(s)"
        )
        if result.statistics is not None:
            print(
                "Search: "
                f"{result.statistics.executions} execution(s), "
                f"{result.statistics.solver_calls} solver call(s), "
                f"{result.statistics.total_seconds:.3f}s total, "
                f"stop={result.statistics.stop_reason}"
            )
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
