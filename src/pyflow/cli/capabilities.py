"""CLI for defensive, pointer-based capability analysis."""

from __future__ import annotations

import ast
import json
import sys
from argparse import ArgumentTypeError
from contextlib import redirect_stdout
from pathlib import Path

from pyflow.checker.capability import (
    CapabilityRegistry,
    DefensiveCapabilityAnalysis,
    default_capability_registry,
)
from pyflow.frontend.entry_discovery import resolve_entry_file
from pyflow.checker.formatters.capability import capability_sarif
from pyflow.cli.analysis_budget import (
    AnalysisBudgetExceeded,
    analysis_time_budget,
    positive_seconds,
    positive_iterations,
)


def import_depth(value: str) -> int:
    """Parse the import-depth option, allowing ``-1`` for unlimited."""
    try:
        depth = int(value)
    except ValueError as exc:
        raise ArgumentTypeError(f"invalid import depth: {value!r}") from exc
    if depth < -1:
        raise ArgumentTypeError("import depth must be -1 (unlimited) or greater")
    return depth


def _project_root_for_file(path: Path) -> Path:
    """Find the import root for a source file.

    For ``pkg/sub/module.py`` the import root is the parent of ``pkg`` rather
    than the file's immediate directory.  Otherwise relative imports such as
    ``from ..sibling import name`` cannot be resolved when the CLI is invoked
    on a single file inside a package.

    PEP 420 namespace packages have no ``__init__.py``, so the walk above stops
    too early (``pkg/mod.py`` -> root ``pkg/``, where ``import pkg.util`` cannot
    resolve) and the analysis silently lost cross-module facts.  When that
    happens, use the file's absolute imports to pick the shallowest ancestor
    under which they resolve.
    """
    root = path.parent
    while (root / "__init__.py").is_file():
        root = root.parent
    names = _absolute_import_roots(path)
    if not names:
        return root
    best, best_score = root, _resolved_import_count(root, names)
    candidate = root.parent
    for _ in range(4):
        if candidate == candidate.parent:
            break
        score = _resolved_import_count(candidate, names)
        if score > best_score:
            best, best_score = candidate, score
        candidate = candidate.parent
    return best


def _absolute_import_roots(path: Path) -> set[str]:
    """Return top-level names of absolute imports in ``path``."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, UnicodeError):
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".", 1)[0])
    return names


def _resolved_import_count(root: Path, names: set[str]) -> int:
    """Count imported top-level names that exist as a package or module."""
    return sum(
        1
        for name in names
        if (root / name).is_dir() or (root / f"{name}.py").is_file()
    )


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
    parser.add_argument(
        "--import-depth",
        type=import_depth,
        default=-1,
        help="Maximum transitive import depth (-1 = unlimited, 0 = entry only)",
    )
    parser.add_argument(
        "--max-iterations",
        type=positive_iterations,
        default=20000,
        help="Pointer work-item budget per entry (default: 20000; reports partial)",
    )
    parser.add_argument(
        "--max-seconds",
        type=positive_seconds,
        default=30.0,
        help="Wall-clock budget for the entire analysis (default: 30; reports partial)",
    )
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument(
        "--verbose", action="store_true", help="Show individual resolver diagnostics"
    )
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
    import_level = getattr(args, "import_depth", -1)
    if import_level < -1:
        print(
            "Error: --import-depth must be -1 (unlimited) or greater",
            file=sys.stderr,
        )
        return 2
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
            try:
                entry = resolve_entry_file(target, args.entry)
            except ValueError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2
            entries = [entry] if entry is not None else []
        if entry is None:
            from pyflow.frontend.entry_discovery import discover_entry_files

            if getattr(args, "recursive", False):
                print(
                    "Error: no Python source files found in project directory",
                    file=sys.stderr,
                )
                return 2
            candidates = discover_entry_files(target)
            print(
                "Error: could not determine a unique project entry file; use --entry or -r",
                file=sys.stderr,
            )
            for candidate in candidates:
                print(f"  {candidate.path} [{candidate.source}]", file=sys.stderr)
            return 2
        project_root = target
    elif target.is_file() and target.suffix == ".py":
        entry = target
        entries = [entry]
        project_root = _project_root_for_file(target)
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
        k=None if getattr(args, "context_policy", None) else args.context_depth,
        context_policy=getattr(args, "context_policy", None),
        report_public_exports=not getattr(args, "no_public_exports", False),
        report_callable_boundaries=getattr(args, "report_callable_boundaries", False),
        max_iterations=getattr(args, "max_iterations", 20000),
    )
    from pyflow.checker.capability.model import CapabilityAnalysisResult

    result = CapabilityAnalysisResult()
    analyzed_entries = 0
    failed_entries = 0
    try:
        with analysis_time_budget(getattr(args, "max_seconds", 30.0)), redirect_stdout(sys.stderr):
            for entry in entries:
                try:
                    analyzed = analysis.analyze_project(
                        entry, project_path=project_root, import_level=import_level
                    )
                except (OSError, SyntaxError, UnicodeError, AssertionError, ValueError) as exc:
                    from pyflow.checker.capability.model import (
                        CapabilityDiagnostic,
                        SourceLocation,
                    )

                    failed_entries += 1
                    result.diagnostics.append(
                        CapabilityDiagnostic(
                            kind="unsupported",
                            message=(f"Could not analyze {entry}: " f"{type(exc).__name__}: {exc}"),
                            location=SourceLocation(
                                str(entry),
                                line=getattr(exc, "lineno", 0) or 0,
                            ),
                        )
                    )
                    continue
                analyzed_entries += 1
                result.findings.extend(analyzed.findings)
                result.diagnostics.extend(analyzed.diagnostics)
                if analyzed.status != "complete":
                    result.status = analyzed.status
    except AnalysisBudgetExceeded as exc:
        from pyflow.checker.capability.model import CapabilityDiagnostic

        result.diagnostics.append(CapabilityDiagnostic(kind="budget", message=str(exc)))
        result.status = "partial"
    processed = analyzed_entries + failed_entries
    result.coverage.update(
        {
            "entries_total": len(entries),
            "entries_analyzed": analyzed_entries,
            "entries_failed": failed_entries,
            "entries_skipped": max(len(entries) - processed, 0),
            "recursive": bool(getattr(args, "recursive", False)),
        }
    )
    result.finalize()
    if failed_entries and not analyzed_entries:
        result.status = "failed"
    if args.format == "json":
        rendered = json.dumps(result.to_dict(), indent=2, sort_keys=True)
    elif args.format == "sarif":
        rendered = json.dumps(capability_sarif(result), indent=2, sort_keys=True)
    else:
        rendered = _to_text(result, verbose=getattr(args, "verbose", False))

    if args.output:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Error: could not write {args.output}: {exc}", file=sys.stderr)
            return 2
    else:
        print(rendered)
    if result.status in {"invalid", "failed"}:
        return 2
    if getattr(args, "exit_code_policy", "report") == "findings":
        return 1 if result.findings or result.status != "complete" else 0
    return 0


def _to_text(result, *, verbose=False) -> str:
    lines = [f"Capability analysis: {result.status}"]
    coverage = result.coverage or {}
    total = coverage.get("entries_total")
    if total and total > 1:
        lines.append(
            f"entries: {coverage.get('entries_analyzed', 0)}/{total} analyzed, "
            f"{coverage.get('entries_failed', 0)} failed, "
            f"{coverage.get('entries_skipped', 0)} skipped"
        )
    if coverage and not coverage.get("solver_complete", True):
        lines.append(
            "solver coverage: "
            f"fixpoint={coverage.get('fixpoint_complete')} "
            f"frontend={coverage.get('frontend_complete')} "
            f"semantic={coverage.get('semantic_complete')} "
            f"stop={coverage.get('stop_reason')}"
        )
    for finding in result.findings:
        loc = finding.location
        details = []
        if finding.escape_kind:
            details.append(f"escape={finding.escape_kind}")
        if finding.boundary:
            details.append(f"boundary={finding.boundary}")
        suffix = f" [{', '.join(details)}]" if details else ""
        lines.append(
            f"{loc.filename}:{loc.line}:{loc.column + 1}: "
            f"{finding.report_kind.value} {finding.operation.value} "
            f"{finding.capability} "
            f"({finding.access_path}){suffix}"
        )
    hidden = 0
    notes = 0
    for diagnostic in result.diagnostics:
        if diagnostic.kind == "note":
            notes += 1
        if diagnostic.kind in {"unknown", "note"} and not verbose:
            hidden += 1
        else:
            lines.append(f"diagnostic[{diagnostic.kind}]: {diagnostic.message}")
    if hidden:
        lines.append(
            f"{hidden} unresolved-operation diagnostics; use --verbose or --format json for details"
        )
    lines.append(
        f"{result.statistics.get('findings', 0)} finding(s), "
        f"{result.statistics.get('diagnostics', 0)} diagnostic(s)"
    )
    return "\n".join(lines)
