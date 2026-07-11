"""CLI entrypoints for IFDS/IDE-backed dataflow analyses."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
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
        default=[],
        help="Function names treated as taint sources",
    )
    parser.add_argument(
        "--sinks",
        nargs="+",
        default=[],
        help="Function names treated as taint sinks",
    )
    parser.add_argument(
        "--sanitizers",
        nargs="*",
        default=[],
        help="Function names treated as taint sanitizers",
    )
    parser.add_argument(
        "--registry",
        action="store_true",
        help="Activate all framework rule packs (sources, sinks, sanitizers)",
    )
    parser.add_argument(
        "--framework",
        nargs="*",
        default=[],
        metavar="FRAMEWORK",
        help="Activate specific framework rule packs (e.g. flask django)",
    )
    parser.add_argument(
        "--collection-mutators",
        nargs="*",
        default=None,
        help=(
            "Collection mutator names modeled as writing value arguments into "
            "container wildcard elements"
        ),
    )
    parser.add_argument(
        "--collection-accessors",
        nargs="*",
        default=None,
        help=(
            "Collection accessor names modeled as reading keyed or wildcard "
            "container elements"
        ),
    )
    parser.add_argument(
        "--conservative-unresolved-calls",
        action="store_true",
        help="Conservatively propagate taint through unresolved calls",
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


def _code_name(code) -> str:
    if hasattr(code, "codeName"):
        return code.codeName()
    if hasattr(code, "__name__"):
        return code.__name__
    return str(code)


def _serialize_statistics(statistics) -> dict:
    if is_dataclass(statistics):
        return asdict(statistics)
    if hasattr(statistics, "__dict__"):
        return dict(vars(statistics))
    return dict(statistics)


def _taint_report_from_result(function: str, taint_result, diagnostics=()) -> dict:
    findings = []
    for finding in taint_result.findings:
        tainted_arguments = [local.name for local in finding.tainted_arguments]
        if not tainted_arguments:
            tainted_arguments = list(finding.tainted_argument_labels)

        explanations = []
        if finding.tainted_arguments:
            fact = taint_result.fact_for_local(
                finding.sink, finding.tainted_arguments[0]
            )
            if fact is not None:
                for edge, traces in taint_result.explain_fact(finding.sink, fact).items():
                    explanations.append(
                        {
                            "source": getattr(
                                edge.source_node.procedure.code, "name", None
                            ),
                            "target_kind": edge.node.kind,
                            "trace": [
                                {
                                    "kind": step.kind,
                                    "note": step.note,
                                }
                                for step in traces
                            ],
                        }
                    )

        findings.append(
            {
                "sink_name": finding.sink_name,
                "procedure": _code_name(finding.sink.procedure.code),
                "block_kind": finding.sink.kind,
                "tainted_arguments": tainted_arguments,
                "explanations": explanations,
            }
        )

    return {
        "function": function,
        "findings": findings,
        "diagnostics": list(diagnostics),
        "statistics": _serialize_statistics(taint_result.statistics),
    }


def _format_text(report: dict) -> str:
    lines = [
        f"Function: {report['function']}",
        f"Findings: {len(report['findings'])}",
        "Statistics:",
    ]
    for key, value in sorted(report["statistics"].items()):
        lines.append(f"  {key}: {value}")
    if report["diagnostics"]:
        lines.append("Diagnostics:")
        for diagnostic in report["diagnostics"]:
            lines.append(f"  {diagnostic}")
    if report["findings"]:
        lines.append("Taint Findings:")
    for finding in report["findings"]:
        args = ", ".join(finding["tainted_arguments"]) or "<none>"
        lines.append(
            f"  sink={finding['sink_name']} procedure={finding['procedure']} args=[{args}]"
        )
    return "\n".join(lines)


def _merge_registry(args) -> tuple[list[str], list[str], list[str]]:
    """Merge framework registry models with CLI-provided names."""
    sources = list(args.sources or [])
    sinks = list(args.sinks or [])
    sanitizers = list(args.sanitizers or [])

    use_registry = getattr(args, "registry", False)
    frameworks = getattr(args, "framework", []) or []

    if not use_registry and not frameworks:
        return sources, sinks, sanitizers

    from pyflow.analysis.ifds.clients.registry import load_registry

    registry = load_registry()
    if use_registry:
        registry.activate_all()
    else:
        registry.activate(*frameworks)

    models = registry.active_models()
    mapping = models.as_mapping()
    for name, model in mapping.items():
        if model.taint_source:
            sources.append(name)
        if model.taint_sink:
            sinks.append(name)
        if model.taint_sanitizer:
            sanitizers.append(name)

    return list(dict.fromkeys(sources)), list(dict.fromkeys(sinks)), list(dict.fromkeys(sanitizers))


def run_dataflow_analysis(input_path, args):
    """Run the selected IFDS/IDE-backed dataflow analysis."""
    files = _discover_python_files(Path(input_path), getattr(args, "recursive", False))
    if not files:
        print("No Python files found to analyze", file=sys.stderr)
        return 1

    if args.analysis != "taint":
        print(f"Unsupported analysis: {args.analysis}", file=sys.stderr)
        return 1

    sources, sinks, sanitizers = _merge_registry(args)

    if not sources and not sinks:
        print(
            "No sources or sinks specified. Use --registry, --framework, "
            "or --sources/--sinks flags.",
            file=sys.stderr,
        )
        return 1

    session, taint_result = run_taint_analysis(
        files,
        function=args.function,
        source_names=sources,
        sink_names=sinks,
        sanitizer_names=sanitizers,
        collection_mutator_names=getattr(args, "collection_mutators", None),
        collection_accessor_names=getattr(args, "collection_accessors", None),
        conservative_unresolved_call_side_effects=getattr(
            args,
            "conservative_unresolved_calls",
            False,
        ),
        verbose=getattr(args, "verbose", False),
        dependency_strategy=getattr(args, "dependency_strategy", "auto"),
    )
    report = _taint_report_from_result(
        args.function,
        taint_result,
        diagnostics=getattr(session, "diagnostics", ()),
    )
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_format_text(report))
    return 1 if report["findings"] else 0
