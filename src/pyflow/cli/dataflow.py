"""CLI entrypoints for IFDS/IDE-backed dataflow analyses."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pyflow.analysis.ifds.api import run_taint_analysis


def add_dataflow_parser(subparsers):
    """Add the dataflow subcommand parser."""
    parser = subparsers.add_parser(
        "dataflow",
        help="Run IFDS/IDE-backed dataflow analyses",
    )
    parser.add_argument("input_path", help="Python file or directory to analyze")
    parser.add_argument(
        "--function",
        required=True,
        help="Entry function to analyze",
    )
    parser.add_argument(
        "--analysis",
        choices=["taint"],
        default="taint",
        help="Concrete analysis to run",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        required=True,
        help="Function names treated as taint sources",
    )
    parser.add_argument(
        "--sinks",
        nargs="+",
        required=True,
        help="Function names treated as taint sinks",
    )
    parser.add_argument(
        "--sanitizers",
        nargs="*",
        default=[],
        help="Function names treated as taint sanitizers",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively analyze Python files in a directory",
    )
    parser.add_argument(
        "--dependency-strategy",
        choices=["auto", "stubs", "noop", "strict", "ast_only"],
        default="auto",
        help="Dependency handling strategy",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return parser


def _discover_python_files(input_path: Path, recursive: bool) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    if input_path.is_dir():
        pattern = "**/*.py" if recursive else "*.py"
        return sorted(path for path in input_path.glob(pattern) if path.is_file())
    raise FileNotFoundError(f"Path not found: {input_path}")


def _format_text(result) -> str:
    lines = [
        f"Function: {result.function}",
        f"Findings: {len(result.findings)}",
        "Statistics:",
    ]
    for key, value in sorted(result.statistics.items()):
        lines.append(f"  {key}: {value}")
    if result.findings:
        lines.append("Taint Findings:")
    for finding in result.findings:
        args = ", ".join(finding["tainted_arguments"]) or "<none>"
        lines.append(
            f"  sink={finding['sink_name']} procedure={finding['procedure']} args=[{args}]"
        )
    return "\n".join(lines)


def run_dataflow_analysis(input_path, args):
    """Run the selected IFDS/IDE-backed dataflow analysis."""
    files = _discover_python_files(Path(input_path), getattr(args, "recursive", False))
    if not files:
        print("No Python files found to analyze", file=sys.stderr)
        return 1

    if args.analysis != "taint":
        print(f"Unsupported analysis: {args.analysis}", file=sys.stderr)
        return 1

    session, taint_result = run_taint_analysis(
        files,
        function=args.function,
        source_names=args.sources,
        sink_names=args.sinks,
        sanitizer_names=args.sanitizers,
        verbose=getattr(args, "verbose", False),
        dependency_strategy=getattr(args, "dependency_strategy", "auto"),
    )
    report = session.program.get_queries(session.compiler).get_interprocedural_taint(
        args.function,
        source_names=set(args.sources),
        sink_names=set(args.sinks),
        sanitizer_names=set(args.sanitizers),
    )
    if args.format == "json":
        print(json.dumps(report.__dict__, indent=2, sort_keys=True))
    else:
        print(_format_text(report))
    return 1 if taint_result.findings else 0
