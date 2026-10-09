"""CLI for defensive, pointer-based capability analysis."""

from __future__ import annotations

import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

from pyflow.checker.capability import (
    CapabilityRegistry,
    DefensiveCapabilityAnalysis,
    default_capability_registry,
)
from pyflow.frontend.entry_discovery import resolve_entry_file
from pyflow.checker.formatters.capability import capability_sarif


def add_capabilities_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "capabilities",
        help="Report security-sensitive capabilities used by Python code",
    )
    parser.add_argument("input_path", help="Python entry file or project directory")
    parser.add_argument("--entry", help="Entry file relative to a project directory")
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Analyze all project Python files instead of choosing one entry file",
    )
    parser.add_argument("--context-depth", type=int, choices=(0, 1, 2, 3), default=1)
    parser.add_argument(
        "--context-policy",
        choices=(
            "0-cfa",
            "1-cfa",
            "2-cfa",
            "3-cfa",
            "1-obj",
            "2-obj",
            "3-obj",
            "1-type",
            "2-type",
            "3-type",
            "1-rcv",
            "2-rcv",
            "3-rcv",
            "1-param",
            "2-param",
            "3-param",
            "1c1o",
            "2c1o",
            "1c2o",
        ),
        help="Context sensitivity policy (overrides --context-depth)",
    )
    parser.add_argument("--import-depth", type=int, default=-1)
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument(
        "--exit-code-policy",
        choices=("report", "findings"),
        default="report",
        help="Return zero for reports (default), or nonzero for findings/partial analysis",
    )
    parser.add_argument(
        "--capability-model",
        action="append",
        type=Path,
        default=[],
        help="Append patterns from a versioned capability-model JSON file",
    )
    parser.add_argument(
        "--no-public-exports",
        action="store_true",
        help="Do not report sensitive values exposed as public module globals",
    )
    parser.add_argument(
        "--report-callable-boundaries",
        action="store_true",
        help="Include potential transfers through returns, yields, and exceptions (default: off)",
    )


def run_capabilities(args) -> int:
    target = Path(args.input_path).resolve()
    if target.is_dir():
        if getattr(args, "recursive", False):
            from pyflow.frontend.file_selection import (
                discover_python_files,
                SECURITY_DEFAULT_EXCLUDES,
            )

            entries = discover_python_files(
                target, recursive=True, exclude=SECURITY_DEFAULT_EXCLUDES
            )
            entry = entries[0] if entries else None
        else:
            entry = resolve_entry_file(target, args.entry)
            entries = [entry] if entry is not None else []
        if entry is None:
            print(
                "Error: could not determine a unique project entry file; use --entry",
                file=sys.stderr,
            )
            return 2
        project_root = target
    elif target.is_file() and target.suffix == ".py":
        entry = target
        entries = [entry]
        project_root = target.parent
    else:
        print(f"Error: expected a Python file or project directory: {target}", file=sys.stderr)
        return 2

    registry = default_capability_registry()
    try:
        for path in getattr(args, "capability_model", ()):
            registry = registry.extended(CapabilityRegistry.from_json(path))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Error: invalid capability model: {exc}", file=sys.stderr)
        return 2
    analysis = DefensiveCapabilityAnalysis(
        registry,
        k=args.context_depth,
        context_policy=getattr(args, "context_policy", None),
        report_public_exports=not getattr(args, "no_public_exports", False),
        report_callable_boundaries=getattr(args, "report_callable_boundaries", False),
    )
    from pyflow.checker.capability.model import CapabilityAnalysisResult

    result = CapabilityAnalysisResult()
    with redirect_stdout(sys.stderr):
        for entry in entries:
            analyzed = analysis.analyze_project(
                entry, project_path=project_root, import_level=args.import_depth
            )
            result.findings.extend(analyzed.findings)
            result.diagnostics.extend(analyzed.diagnostics)
            if analyzed.status != "complete":
                result.status = analyzed.status
    result.finalize()
    if args.format == "json":
        rendered = json.dumps(result.to_dict(), indent=2, sort_keys=True)
    elif args.format == "sarif":
        rendered = json.dumps(capability_sarif(result), indent=2, sort_keys=True)
    else:
        rendered = _to_text(result)

    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    if result.status in {"invalid", "failed"}:
        return 2
    if getattr(args, "exit_code_policy", "report") == "findings":
        return 1 if result.findings or result.status != "complete" else 0
    return 0


def _to_text(result) -> str:
    lines = [f"Capability analysis: {result.status}"]
    for finding in result.findings:
        loc = finding.location
        lines.append(
            f"{loc.filename}:{loc.line}:{loc.column + 1}: "
            f"{finding.report_kind.value} {finding.capability} "
            f"({finding.access_path})"
        )
    for diagnostic in result.diagnostics:
        lines.append(f"diagnostic[{diagnostic.kind}]: {diagnostic.message}")
    lines.append(
        f"{result.statistics.get('findings', 0)} finding(s), "
        f"{result.statistics.get('diagnostics', 0)} diagnostic(s)"
    )
    return "\n".join(lines)
