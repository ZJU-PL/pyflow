"""
Unified taint analysis CLI — ``pyflow taint``.

Dispatches to one of four engine backends:

- ``ast-scanner`` — fast AST pattern matching (Bandit-style), no analysis pipeline
- ``cpa`` — PyFlow pipeline + CPA-backed taint propagation on the AST
- ``ifds`` — IFDS solver over CFG supergraphs (interprocedural, flow-sensitive)
- ``cpg`` — CPG-based context-sensitive taint with heap-aware alias tracking
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pyflow.checker.pattern.core.manager import SecurityManager
from pyflow.checker.pattern.core.config import SecurityConfig
from pyflow.checker.pattern.core import constants as b_constants
from pyflow.checker.semantic import BugFinderConfig, SemanticManager
from pyflow.checker.formatters import text as text_formatter
from pyflow.checker.formatters import json as json_formatter
from pyflow.checker.formatters import sarif as sarif_formatter


# ── Parser ────────────────────────────────────────────────────────────────


def add_taint_parser(subparsers):
    """Add the unified ``pyflow taint`` subcommand parser."""
    p = subparsers.add_parser(
        "taint",
        help="Run taint analysis on Python files",
        description=(
            "Run taint analysis using one of four engines. "
            "Use --engine to choose: 'ast-scanner' (fast AST matching, default), "
            "'cpa' (CPA-backed analysis), 'ifds' (interprocedural dataflow, "
            "requires --function), or 'cpg' (CPG-based context-sensitive analysis)."
        ),
    )
    p.add_argument(
        "targets",
        nargs="*",
        help="Files or directories to analyze (default: current directory)",
    )
    p.add_argument(
        "--engine",
        choices=["ast-scanner", "cpa", "ifds", "cpg"],
        default="ast-scanner",
        help="Taint analysis engine to use",
    )
    p.add_argument(
        "--sources",
        nargs="+",
        default=[],
        help="Taint source function names (repeatable, e.g. 'request.args' 'input')",
    )
    p.add_argument(
        "--sinks",
        nargs="+",
        default=[],
        help="Taint sink function names (repeatable, e.g. 'eval' 'subprocess.run')",
    )
    p.add_argument(
        "--sanitizers",
        nargs="+",
        default=[],
        help="Taint sanitizer function names (repeatable)",
    )
    # IFDS-specific
    p.add_argument(
        "--function",
        help="Entry function name (required for --engine ifds)",
    )
    # CPG-specific
    p.add_argument(
        "--framework",
        nargs="*",
        default=[],
        metavar="FRAMEWORK",
        choices=[
            "django", "flask", "fastapi", "sqlalchemy", "stdlib",
            "cloud", "injection", "network", "nosql", "requests", "sql",
        ],
        help="Framework rule pack(s) for CPG engine (repeatable; auto-detect if omitted)",
    )
    p.add_argument(
        "--registry",
        action="store_true",
        help="Activate all framework rule packs (only for --engine ifds)",
    )
    # Common flags
    p.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Scan directories recursively",
    )
    p.add_argument(
        "--exclude",
        help="Comma-separated paths to exclude",
    )
    p.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format",
    )
    p.add_argument(
        "--output", "-o",
        type=Path,
        help="Output file (default: stdout)",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--debug", "-d", action="store_true", help="Debug output")


# ── Engine dispatchers ────────────────────────────────────────────────────


def _run_ast_scanner(
    targets: List[str],
    args,
    *,
    exclude: str = "",
    recursive: bool = False,
) -> SecurityManager:
    """Run the fast AST pattern-matching scanner (was 'pattern')."""
    config = SecurityConfig()
    manager = SecurityManager(
        config=config,
        debug=getattr(args, "debug", False),
        verbose=getattr(args, "verbose", False),
        quiet=False,
    )
    manager.discover_files(
        targets,
        recursive=recursive,
        excluded_paths=",".join(_parse_exclude_tuple(exclude)),
    )
    manager.run_tests()
    return manager


def _run_cpa(
    targets: List[str],
    args,
    *,
    exclude: str = "",
    recursive: bool = False,
) -> SemanticManager:
    """Run the CPA-backed semantic taint analysis (was 'semantic')."""
    config = BugFinderConfig(
        verbose=getattr(args, "verbose", False),
        recursive=recursive,
        exclude=_parse_exclude_tuple(exclude),
        taint_engine=getattr(args, "taint_engine", "ast"),
    )
    manager = SemanticManager(
        config=config,
        debug=getattr(args, "debug", False),
        verbose=getattr(args, "verbose", False),
        quiet=False,
    )
    manager.analyze(targets)
    return manager


def _run_ifds(targets: List[str], args) -> Dict[str, Any]:
    """Run the IFDS-backed interprocedural taint analysis."""
    from pyflow.analysis.ifds.api import run_taint_analysis

    files = _discover_python_files(targets, getattr(args, "recursive", False))
    if not files:
        print("No Python files found to analyze", file=sys.stderr)
        return {"function": args.function or "<unknown>", "findings": [], "diagnostics": []}

    sources, sinks, sanitizers = _merge_taint_specs(args)

    if not sources and not sinks:
        print(
            "No sources or sinks specified. Use --sources/--sinks flags or --registry.",
            file=sys.stderr,
        )
        return {"function": args.function or "<unknown>", "findings": [], "diagnostics": []}

    try:
        _session, taint_result, _shadow_matches = run_taint_analysis(
            files,
            function=args.function or "",
            source_names=sources,
            sink_names=sinks,
            sanitizer_names=sanitizers,
            collection_mutator_names=getattr(args, "collection_mutators", None),
            collection_accessor_names=getattr(args, "collection_accessors", None),
            conservative_unresolved_call_side_effects=getattr(
                args, "conservative_unresolved_calls", False
            ),
            dependency_strategy=getattr(args, "dependency_strategy", "auto"),
            verbose=getattr(args, "verbose", False),
        )
    except Exception as e:
        print(f"IFDS analysis failed: {e}", file=sys.stderr)
        return {"function": args.function or "<unknown>", "findings": [], "diagnostics": [str(e)]}

    result = _ifds_result_to_dict(args.function or "<unknown>", taint_result)
    result["diagnostics"] = list(getattr(_session, "diagnostics", ()))
    return result


def _run_cpg(targets: List[str], args) -> List[Dict[str, Any]]:
    """Run the CPG-based context-sensitive taint analysis."""
    from pyflow.analysis.cpg.build import build_cpg, build_cpg_from_directory
    from pyflow.analysis.cpg.taint import CPGTaintEngine
    from pyflow.analysis.cpg.rules import load_rules, detect_frameworks

    findings: List = []

    for target in targets:
        path = Path(target)
        if not path.exists():
            print(f"Error: '{target}' not found", file=sys.stderr)
            continue

        if path.is_dir():
            cpg = build_cpg_from_directory(
                str(target), recursive=getattr(args, "recursive", False)
            )
        else:
            source = path.read_text(encoding="utf-8", errors="replace")
            cpg = build_cpg(source, filename=str(target))

        if len(cpg.functions) == 0:
            continue

        cpg.build()
        engine = CPGTaintEngine(cpg)

        for src in getattr(args, "sources", []) or []:
            engine.add_source(src)
        for snk in getattr(args, "sinks", []) or []:
            engine.add_sink(snk)
        for san in getattr(args, "sanitizers", []) or []:
            engine.add_sanitizer(san)

        frameworks: Optional[List[str]] = getattr(args, "framework", None) or None
        if frameworks is not None and len(frameworks) == 0:
            frameworks = None
        if frameworks is None and path.is_file():
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                frameworks = detect_frameworks(source)
            except OSError:
                pass
        load_rules(engine, frameworks=frameworks)

        result = engine.find_taint_paths()
        findings.extend(f.to_dict() for f in result)

    return findings


# ── Output helpers ────────────────────────────────────────────────────────


def _format_output_text(engine: str, result) -> str:
    """Format analysis results as human-readable text."""
    if engine == "ast-scanner":
        # The text formatter prints directly; we collect a summary
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        if not issues:
            return "No issues found."
        lines = [f"Found {len(issues)} issue(s):\n"]
        for iss in issues:
            lines.append(
                f"  [{iss.test_id}] {iss.text}"
            )
            lines.append(f"       Severity: {iss.severity}  Confidence: {iss.confidence}")
            lines.append(f"       File: {iss.fname}:{iss.lineno}")
            lines.append("")
        return "\n".join(lines)

    if engine == "cpa":
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        if not issues:
            return "No issues found."
        lines = [f"Found {len(issues)} issue(s):\n"]
        for iss in issues:
            lines.append(
                f"  [{iss.test_id}] {iss.text}"
            )
            lines.append(f"       Severity: {iss.severity}  Confidence: {iss.confidence}")
            lines.append(f"       File: {iss.fname}:{iss.lineno}")
            lines.append("")
        return "\n".join(lines)

    if engine == "ifds":
        report = result
        lines = [
            f"Function: {report.get('function', '<unknown>')}",
            f"Findings: {len(report.get('findings', []))}",
        ]
        stats = report.get("statistics", {})
        if stats:
            lines.append("Statistics:")
            for key, value in sorted(stats.items()):
                lines.append(f"  {key}: {value}")
        diags = report.get("diagnostics", [])
        if diags:
            lines.append("Diagnostics:")
            for diagnostic in diags:
                lines.append(f"  {diagnostic}")
        for finding in report.get("findings", []):
            args_str = ", ".join(finding.get("tainted_arguments", [])) or "<none>"
            lines.append(
                f"  sink={finding.get('sink_name', '?')} "
                f"procedure={finding.get('procedure', '?')} "
                f"args=[{args_str}]"
            )
        return "\n".join(lines)

    if engine == "cpg":
        findings = result
        if not findings:
            return "No taint findings."
        lines = [f"\n{len(findings)} taint finding(s):\n"]
        for i, f in enumerate(findings, 1):
            conf = f.get("confidence", 0)
            bar = "█" * int(conf * 10) + "░" * (10 - int(conf * 10))
            lines.append(
                f"  [{i}] {f.get('cwe', '?')} [{f.get('severity', '?')}] "
                f"confidence={conf:.0%} [{bar}]"
            )
            lines.append(f"      source: {f.get('source_label', '?')} (line {f.get('source_line', 0)})")
            lines.append(f"      sink:   {f.get('sink_label', '?')} (line {f.get('sink_line', 0)})")
            lines.append("")
        return "\n".join(lines)

    return ""


def _output_results(engine: str, result, args) -> None:
    """Write analysis results in the requested format."""
    fmt = getattr(args, "format", "text")

    out_file = None
    try:
        if getattr(args, "output", None):
            out_file = open(args.output, "w", encoding="utf-8")
        output = out_file or sys.stdout

        if fmt == "text":
            output.write(_format_output_text(engine, result))
            output.write("\n")
        elif fmt == "json":
            json.dump(_result_to_json(engine, result), output, indent=2)
            output.write("\n")
        elif fmt == "sarif":
            sarif_doc = _result_to_sarif(engine, result, args)
            json.dump(sarif_doc, output, indent=2)
            output.write("\n")
    finally:
        if out_file:
            out_file.close()


def _result_to_json(engine: str, result) -> Any:
    """Normalize engine results to a JSON-compatible structure."""
    if engine == "ast-scanner":
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        return {
            "engine": "ast-scanner",
            "results": [
                {
                    "test_id": iss.test_id,
                    "text": iss.text,
                    "severity": iss.severity,
                    "confidence": iss.confidence,
                    "filename": iss.fname,
                    "line": iss.lineno,
                }
                for iss in issues
            ],
        }
    if engine == "cpa":
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        return {
            "engine": "cpa",
            "results": [
                {
                    "test_id": iss.test_id,
                    "text": iss.text,
                    "severity": iss.severity,
                    "confidence": iss.confidence,
                    "filename": iss.fname,
                    "line": iss.lineno,
                }
                for iss in issues
            ],
        }
    if engine == "ifds":
        return {"engine": "ifds", **result}
    if engine == "cpg":
        return {"engine": "cpg", "results": result}
    return {}


def _result_to_sarif(engine: str, result, args) -> Dict[str, Any]:
    """Convert engine results to SARIF v2.1.0 format."""
    if engine == "cpg":
        from pyflow.analysis.cpg.taint import CPGTaintEngine
        findings = result
        artifact_uri = (
            str(args.targets[0]) if getattr(args, "targets", None) else ""
        ) if hasattr(CPGTaintEngine, "deduplicate") else ""
        # Build minimal SARIF from CPG findings
        rules: List[Dict[str, Any]] = []
        results_list: List[Dict[str, Any]] = []
        seen_rules: Dict[str, int] = {}
        for f in findings:
            rule_id = f.get("rule_id", f.get("cwe", "CPG-TAINT"))
            if rule_id not in seen_rules:
                seen_rules[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": f.get("rule", {}).get("name", rule_id),
                    "shortDescription": {"text": f.get("rule", {}).get("short_description", "")},
                })
            results_list.append({
                "ruleId": rule_id,
                "ruleIndex": seen_rules[rule_id],
                "level": "error" if f.get("severity") in ("critical", "high") else "warning",
                "message": {"text": f"Tainted data from {f.get('source_label', '?')} reaches {f.get('sink_label', '?')}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                        "region": {"startLine": f.get("source_line", 0)},
                    }
                }],
            })
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "pyflow-taint-cpg", "rules": rules}}, "results": results_list}],
        }

    # Default: generic SARIF wrapper
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": f"pyflow-taint-{engine}"}},
                "results": [],
            }
        ],
    }


# ── Shared helpers ────────────────────────────────────────────────────────


def _parse_exclude_tuple(exclude: str) -> tuple:
    if not exclude:
        return ()
    return tuple(p.strip() for p in exclude.split(",") if p.strip())


def _discover_python_files(
    targets: Sequence[str], recursive: bool
) -> list[Path]:
    files: list[Path] = []
    for t in targets:
        path = Path(t)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            pattern = "**/*.py" if recursive else "*.py"
            files.extend(sorted(path.glob(pattern)))
    return files


def _merge_taint_specs(args) -> tuple[list[str], list[str], list[str]]:
    """Merge CLI-provided sources/sinks/sanitizers with optional framework registry."""
    sources = list(getattr(args, "sources", []) or [])
    sinks = list(getattr(args, "sinks", []) or [])
    sanitizers = list(getattr(args, "sanitizers", []) or [])

    use_registry = getattr(args, "registry", False)
    if not use_registry:
        return sources, sinks, sanitizers

    try:
        from pyflow.analysis.ifds.clients.registry import load_registry
        registry = load_registry()
        registry.activate_all()
        models = registry.active_models()
        mapping = models.as_mapping()
        for name, model in mapping.items():
            if model.taint_source:
                sources.append(name)
            if model.taint_sink:
                sinks.append(name)
            if model.taint_sanitizer:
                sanitizers.append(name)
    except ImportError:
        pass

    return list(dict.fromkeys(sources)), list(dict.fromkeys(sinks)), list(dict.fromkeys(sanitizers))


def _code_name(code) -> str:
    if hasattr(code, "codeName"):
        return code.codeName()
    if hasattr(code, "__name__"):
        return code.__name__
    return str(code)


def _ifds_result_to_dict(function: str, taint_result) -> Dict[str, Any]:
    """Convert an IFDS TaintAnalysisResult to a JSON-compatible dict."""
    from dataclasses import asdict, is_dataclass

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
                for edge, traces in taint_result.explain_fact(
                    finding.sink, fact
                ).items():
                    explanations.append(
                        {
                            "source": getattr(
                                edge.source_node.procedure.code, "name", None
                            ),
                            "target_kind": edge.node.kind,
                            "trace": [
                                {"kind": step.kind, "note": step.note}
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

    statistics = {}
    if is_dataclass(taint_result.statistics):
        statistics = asdict(taint_result.statistics)
    elif hasattr(taint_result.statistics, "__dict__"):
        statistics = dict(vars(taint_result.statistics))
    else:
        statistics = dict(taint_result.statistics)

    return {
        "function": function,
        "findings": findings,
        "statistics": statistics,
    }


# ── Main entry point ──────────────────────────────────────────────────────


def run_taint(args) -> int:
    """Dispatch to the selected taint engine and output results."""
    # Set up logging
    level = (
        logging.DEBUG
        if getattr(args, "debug", False)
        else logging.INFO
        if getattr(args, "verbose", False)
        else logging.WARNING
    )
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    engine = args.engine
    targets = args.targets or ["."]
    recursive = getattr(args, "recursive", False)
    exclude = getattr(args, "exclude", "") or ""

    if engine == "ast-scanner":
        result = _run_ast_scanner(targets, args, exclude=exclude, recursive=recursive)
        _output_results(engine, result, args)
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        return 1 if issues else 0

    elif engine == "cpa":
        result = _run_cpa(targets, args, exclude=exclude, recursive=recursive)
        _output_results(engine, result, args)
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        return 1 if issues else 0

    elif engine == "ifds":
        if not args.function:
            print(
                "Error: --function is required for 'ifds' engine",
                file=sys.stderr,
            )
            return 1
        result = _run_ifds(targets, args)
        _output_results(engine, result, args)
        return 1 if result.get("findings") else 0

    elif engine == "cpg":
        result = _run_cpg(targets, args)
        _output_results(engine, result, args)
        return 1 if result else 0

    else:
        print(f"Unknown engine: {engine}", file=sys.stderr)
        return 1
