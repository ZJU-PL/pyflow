"""CLI support for Py-Conbyte-inspired concolic input generation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pyflow.concolic import ConcolicError, explore_file, generate_pytest, scan_project


def add_concolic_parser(subparsers):
    """Register the ``concolic`` command."""
    parser = subparsers.add_parser(
        "concolic",
        help="Generate test inputs by concolically exploring a function",
    )
    parser.add_argument("input_path", help="Python file containing the target function")
    parser.add_argument(
        "--scan-project",
        action="store_true",
        help="Discover and measure functions beneath input_path",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        help="Maximum discovered functions to include in a project scan",
    )
    parser.add_argument(
        "--input-complexity",
        type=int,
        default=2,
        help="Maximum deterministic input synthesis tier (default: 2)",
    )
    parser.add_argument(
        "--function-timeout",
        type=float,
        default=10.0,
        help="Worker timeout in seconds for each scan attempt (default: 10)",
    )
    parser.add_argument(
        "--allow-side-effects",
        action="store_true",
        help="Scan functions statically flagged for external side effects",
    )
    parser.add_argument(
        "--include-private",
        action="store_true",
        help="Include underscore-prefixed functions in project discovery",
    )
    parser.add_argument(
        "--json-output",
        metavar="PATH",
        help="Also write machine-readable output to this path",
    )
    parser.add_argument("--entry", default="main", help="Function to explore (default: main)")
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
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--emit-pytest",
        metavar="PATH",
        help="Write a minimized, CPython-replay-validated pytest module",
    )
    return parser


def run_concolic(args) -> int:
    """Run concolic exploration and print generated inputs."""
    if getattr(args, "scan_project", False):
        return _run_project_scan(args)

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
            max_uninteresting_iterations=getattr(args, "max_uninteresting_iterations", None),
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

    generation = None
    pytest_path = getattr(args, "emit_pytest", None)
    if pytest_path is not None:
        output_path = Path(pytest_path)
        if output_path.resolve() == Path(args.input_path).resolve():
            print("Error: --emit-pytest cannot overwrite the input file", file=sys.stderr)
            return 2
        try:
            generation = generate_pytest(Path(args.input_path), result)
            output_path.write_text(generation.source, encoding="utf-8")
        except (OSError, ValueError) as error:
            print(f"Error: could not emit pytest: {error}", file=sys.stderr)
            return 1

    if args.json:
        payload = result.to_dict()
        if generation is not None:
            assert pytest_path is not None
            payload["pytest_generation"] = {
                "path": str(Path(pytest_path)),
                **generation.to_dict(),
            }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        parameters = ", ".join(result.parameter_names)
        print(f"Explored {len(result.runs)} execution(s) of {result.entry}({parameters})")
        print("Generated inputs:")
        for run in result.runs:
            schedule = f" schedule={list(run.schedule)}" if run.schedule else ""
            outcome = run.outcome.kind.value
            print(f"  {list(run.inputs)} -> {run.result!r} " f"outcome={outcome}{schedule}")
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
        if generation is not None:
            print(f"Generated {len(generation.emitted_runs)} pytest test(s) " f"at {pytest_path}")
            for skipped in generation.skipped:
                print(f"  skipped: {skipped}")
    return 0


def _run_project_scan(args) -> int:
    options = {
        "max_iterations": args.max_iterations,
        "max_loop_iterations": args.max_loop_iterations,
        "max_resume_steps": getattr(args, "max_resume_steps", 1000),
        "scheduler": getattr(args, "scheduler", "fifo"),
        "max_task_switches": getattr(args, "max_task_switches", 1000),
        "max_schedule_states": getattr(args, "max_schedule_states", 1000),
        "search_strategy": getattr(args, "search_strategy", "coverage"),
        "max_uninteresting_iterations": getattr(args, "max_uninteresting_iterations", None),
        "total_timeout": getattr(args, "total_timeout", None),
        "per_run_timeout": getattr(args, "per_run_timeout", None),
        "solver_timeout": getattr(args, "solver_timeout", None),
        "max_solver_calls": getattr(args, "max_solver_calls", None),
        "max_pending_states": getattr(args, "max_pending_states", 10000),
        "check_contracts": getattr(args, "check_contracts", False),
    }
    try:
        result = scan_project(
            args.input_path,
            max_functions=getattr(args, "max_functions", None),
            input_complexity=getattr(args, "input_complexity", 2),
            function_timeout=getattr(args, "function_timeout", 10.0),
            allow_side_effects=getattr(args, "allow_side_effects", False),
            include_private=getattr(args, "include_private", False),
            exploration_options=options,
        )
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    payload = result.to_dict()
    output_path = getattr(args, "json_output", None)
    if output_path:
        report_path = Path(output_path)
        input_path = Path(args.input_path)
        if input_path.is_file() and report_path.resolve() == input_path.resolve():
            print(
                "Error: --json-output cannot overwrite the input file",
                file=sys.stderr,
            )
            return 2
        try:
            report_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError as error:
            print(f"Error: could not write scan report: {error}", file=sys.stderr)
            return 1

    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            f"Scanned {summary['discovered']} function(s) with "
            f"{summary['attempts']} isolated attempt(s) in "
            f"{summary['seconds']:.3f}s"
        )
        for status, count in summary["statuses"].items():
            print(f"  {status}: {count}")
        if output_path:
            print(f"JSON report: {output_path}")
    return 0
