"""
Unified security analysis CLI — ``pyflow security``.

Dispatches to one of four engine backends:

- ``ast-scanner`` — fast AST pattern matching (Bandit-style), no analysis pipeline
- ``cpa`` — PyFlow pipeline + CPA-backed security checks on the AST
- ``ifds`` — IFDS solver over CFG supergraphs (interprocedural, flow-sensitive)
- ``cpg`` — CPG-based context-sensitive security analysis with heap-aware alias tracking
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


def add_security_parser(subparsers):
    """Add the unified ``pyflow security`` subcommand parser."""
    p = subparsers.add_parser(
        "security",
        help="Run security analysis on Python files",
        description=(
            "Run security analysis using one of four engines. "
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
        help="Security analysis engine to use",
    )
    p.add_argument(
        "--analysis",
        choices=["taint", "nullness", "typestate"],
        default="taint",
        help="IFDS analysis to run when --engine ifds is selected",
    )
    p.add_argument(
        "--sources",
        nargs="+",
        default=[],
        help=(
            "Source function names for taint-style checks "
            "(repeatable, e.g. 'request.args' 'input')"
        ),
    )
    p.add_argument(
        "--sinks",
        nargs="+",
        default=[],
        help=(
            "Sink function names for taint-style checks "
            "(repeatable, e.g. 'eval' 'subprocess.run')"
        ),
    )
    p.add_argument(
        "--sanitizers",
        nargs="+",
        default=[],
        help="Sanitizer function names for taint-style checks (repeatable)",
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
            "django",
            "flask",
            "fastapi",
            "sqlalchemy",
            "stdlib",
            "cloud",
            "injection",
            "network",
            "nosql",
            "requests",
            "sql",
        ],
        help="Framework rule pack(s) for CPG engine (repeatable; auto-detect if omitted)",
    )
    p.add_argument(
        "--registry",
        action="store_true",
        help="Activate all framework rule packs (only for --engine ifds)",
    )
    p.add_argument(
        "--ifds-mode",
        choices=["strict", "best-effort"],
        default="best-effort",
        help="Fail on preparation gaps or continue with explicit partial status",
    )
    p.add_argument("--ifds-max-seconds", type=float)
    p.add_argument("--ifds-max-path-edges", type=int)
    p.add_argument("--ifds-max-queue-size", type=int)
    p.add_argument("--ifds-max-incoming-records", type=int)
    p.add_argument("--ifds-max-summary-entries", type=int)
    p.add_argument("--ifds-max-facts-per-node", type=int)
    p.add_argument("--ifds-max-contexts-per-procedure", type=int)
    p.add_argument("--ifds-max-memory-bytes", type=int)
    p.add_argument("--ifds-context-depth", type=int, default=3)
    p.add_argument(
        "--ifds-trace-mode",
        choices=["none", "findings", "all"],
        default="findings",
    )
    p.add_argument(
        "--typestate-protocol",
        action="append",
        default=[],
        metavar="PROTOCOLS",
        help=(
            "Typestate protocols for --analysis typestate. May be repeated "
            "or comma-separated; supports resource, python-builtins, file, "
            "socket, lock, transaction."
        ),
    )
    # Common flags
    p.add_argument(
        "--recursive",
        "-r",
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
        "--output",
        "-o",
        type=Path,
        help="Output file (default: stdout)",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--debug", "-d", action="store_true", help="Debug output")


# ── Engine dispatchers ────────────────────────────────────────────────────


def _ifds_solver_options(args):
    from pyflow.analysis.ifds.solver import SolverOptions

    return SolverOptions(
        max_propagated_path_edges=getattr(args, "ifds_max_path_edges", None),
        max_seconds=getattr(args, "ifds_max_seconds", None),
        max_queue_size=getattr(args, "ifds_max_queue_size", None),
        max_incoming_records=getattr(args, "ifds_max_incoming_records", None),
        max_summary_entries=getattr(args, "ifds_max_summary_entries", None),
        max_facts_per_node=getattr(args, "ifds_max_facts_per_node", None),
        max_contexts_per_procedure=getattr(
            args, "ifds_max_contexts_per_procedure", None
        ),
        max_memory_bytes=getattr(args, "ifds_max_memory_bytes", None),
        max_call_string_depth=getattr(args, "ifds_context_depth", 3),
        trace_mode=getattr(args, "ifds_trace_mode", "findings"),
        limit_behavior="partial",
    )


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
    """Run the CPA-backed semantic security analysis (was 'semantic')."""
    config = BugFinderConfig(
        verbose=getattr(args, "verbose", False),
        recursive=recursive,
        exclude=_parse_exclude_tuple(exclude),
        taint_engine=getattr(args, "taint_engine", "ast"),
        sources=tuple(getattr(args, "sources", ()) or ()),
        sinks=tuple(getattr(args, "sinks", ()) or ()),
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
    """Run the IFDS-backed interprocedural security analysis."""
    from pyflow.analysis.ifds.api import (
        run_nullness_analysis,
        run_taint_analysis,
        run_typestate_analysis,
    )
    from pyflow.analysis.ifds.preparation import PreparationMode

    solver_options = _ifds_solver_options(args)
    preparation_mode = (
        PreparationMode.STRICT
        if getattr(args, "ifds_mode", "best-effort") == "strict"
        else PreparationMode.BEST_EFFORT
    )

    files = _discover_python_files(targets, getattr(args, "recursive", False))
    if not files:
        print("No Python files found to analyze", file=sys.stderr)
        return {
            "function": args.function or "<unknown>",
            "findings": [],
            "diagnostics": [],
            "status": "failed",
            "termination_reason": "No Python files found to analyze",
        }

    if getattr(args, "analysis", "taint") == "typestate":
        try:
            _session, typestate_result = run_typestate_analysis(
                files,
                function=args.function or "",
                enabled_protocols=_parse_typestate_protocols(args),
                registry=getattr(args, "registry", False),
                registry_frameworks=getattr(args, "framework", ()) or (),
                collection_mutator_names=getattr(args, "collection_mutators", None),
                collection_accessor_names=getattr(args, "collection_accessors", None),
                dependency_strategy=getattr(args, "dependency_strategy", "auto"),
                verbose=getattr(args, "verbose", False),
                solver_options=solver_options,
                preparation_mode=preparation_mode,
            )
        except Exception as e:
            print(f"IFDS analysis failed: {e}", file=sys.stderr)
            return {
                "function": args.function or "<unknown>",
                "analysis": "typestate",
                "findings": [],
                "diagnostics": [str(e)],
                "status": "failed",
                "termination_reason": str(e),
            }
        result = _typestate_result_to_dict(
            args.function or "<unknown>", typestate_result
        )
        return _apply_session_diagnostics(result, _session)

    if getattr(args, "analysis", "taint") == "nullness":
        try:
            _session, nullness_result = run_nullness_analysis(
                files,
                function=args.function or "",
                dependency_strategy=getattr(args, "dependency_strategy", "auto"),
                verbose=getattr(args, "verbose", False),
                solver_options=solver_options,
                preparation_mode=preparation_mode,
            )
        except Exception as e:
            print(f"IFDS analysis failed: {e}", file=sys.stderr)
            return {
                "function": args.function or "<unknown>",
                "analysis": "nullness",
                "findings": [],
                "diagnostics": [str(e)],
                "status": "failed",
                "termination_reason": str(e),
            }
        result = _nullness_result_to_dict(args.function or "<unknown>", nullness_result)
        return _apply_session_diagnostics(result, _session)

    sources, sinks, sanitizers = _merge_taint_specs(args)

    if not sources and not sinks:
        print(
            "No sources or sinks specified. Use --sources/--sinks flags or --registry.",
            file=sys.stderr,
        )
        return {
            "function": args.function or "<unknown>",
            "findings": [],
            "diagnostics": [],
            "status": "invalid",
            "termination_reason": "No taint sources or sinks configured",
        }

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
            solver_options=solver_options,
            preparation_mode=preparation_mode,
        )
    except Exception as e:
        print(f"IFDS analysis failed: {e}", file=sys.stderr)
        return {
            "function": args.function or "<unknown>",
            "findings": [],
            "diagnostics": [str(e)],
            "status": "failed",
            "termination_reason": str(e),
        }

    result = _ifds_result_to_dict(args.function or "<unknown>", taint_result)
    return _apply_session_diagnostics(result, _session)


def _diagnostics_to_dicts(diagnostics) -> list[Any]:
    from dataclasses import asdict, is_dataclass

    return [
        (asdict(diagnostic) if is_dataclass(diagnostic) else str(diagnostic))
        for diagnostic in diagnostics
    ]


def _apply_session_diagnostics(result: Dict[str, Any], session) -> Dict[str, Any]:
    diagnostics = tuple(getattr(session, "diagnostics", ()))
    result["diagnostics"] = _diagnostics_to_dicts(diagnostics)
    if result.get("status") == "complete" and any(
        getattr(diagnostic, "affects_completeness", False) for diagnostic in diagnostics
    ):
        result["status"] = "partial"
        result["termination_reason"] = (
            "Analysis preparation recovered from one or more incomplete stages"
        )
    return result


def _run_cpg(targets: List[str], args) -> List[Dict[str, Any]]:
    """Run the CPG-based context-sensitive security analysis."""
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
            lines.append(f"  [{iss.test_id}] {iss.text}")
            lines.append(
                f"       Severity: {iss.severity}  Confidence: {iss.confidence}"
            )
            lines.append(f"       File: {iss.fname}:{iss.lineno}")
            lines.append("")
        return "\n".join(lines)

    if engine == "cpa":
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        if not issues:
            return "No issues found."
        lines = [f"Found {len(issues)} issue(s):\n"]
        for iss in issues:
            lines.append(f"  [{iss.test_id}] {iss.text}")
            lines.append(
                f"       Severity: {iss.severity}  Confidence: {iss.confidence}"
            )
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
            if "kind" in finding:
                lines.append(
                    f"  typestate={finding.get('kind', '?')} "
                    f"protocol={finding.get('protocol', '?')} "
                    f"state={finding.get('state', '?')} "
                    f"resource={finding.get('resource_label', '?')} "
                    f"operation={finding.get('operation_name', '?')}"
                )
                continue
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
            return "No security findings."
        lines = [f"\n{len(findings)} security finding(s):\n"]
        for i, f in enumerate(findings, 1):
            conf = f.get("confidence", 0)
            bar = "█" * int(conf * 10) + "░" * (10 - int(conf * 10))
            lines.append(
                f"  [{i}] {f.get('cwe', '?')} [{f.get('severity', '?')}] "
                f"confidence={conf:.0%} [{bar}]"
            )
            lines.append(
                f"      source: {f.get('source_label', '?')} "
                f"(line {f.get('source_line', 0)})"
            )
            lines.append(
                f"      sink:   {f.get('sink_label', '?')} (line {f.get('sink_line', 0)})"
            )
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
    if engine == "ifds":
        findings = result.get("findings", [])
        rules: List[Dict[str, Any]] = []
        rule_indexes: Dict[str, int] = {}
        sarif_results: List[Dict[str, Any]] = []

        def physical_location(span):
            if not span:
                return None
            region = {"startLine": max(int(span.get("start_line", 1)), 1)}
            if span.get("start_column") is not None:
                region["startColumn"] = max(int(span["start_column"]) + 1, 1)
            if span.get("end_line") is not None:
                region["endLine"] = int(span["end_line"])
            if span.get("end_column") is not None:
                region["endColumn"] = int(span["end_column"]) + 1
            return {
                "physicalLocation": {
                    "artifactLocation": {"uri": span.get("uri", "")},
                    "region": region,
                }
            }

        for finding in findings:
            rule_id = finding.get("rule_id") or "PYFLOW-IFDS"
            if rule_id not in rule_indexes:
                rule_indexes[rule_id] = len(rules)
                rule = {
                    "id": rule_id,
                    "shortDescription": {"text": finding.get("message", rule_id)},
                    "properties": {
                        "tags": [
                            value
                            for value in (finding.get("cwe"), finding.get("kind"))
                            if value
                        ]
                    },
                }
                if finding.get("suggestion"):
                    rule["help"] = {"text": finding["suggestion"]}
                rules.append(rule)

            locations = []
            primary = physical_location(finding.get("primary_location"))
            if primary is not None:
                locations.append(primary)

            thread_flow_locations = []
            for index, step in enumerate(finding.get("code_flow", []), 1):
                location = physical_location(step.get("location"))
                if location is None:
                    continue
                location["message"] = {
                    "text": step.get("message", step.get("kind", "flow"))
                }
                location["properties"] = {
                    "kind": step.get("kind"),
                    "nodeId": step.get("node_id"),
                    "procedureId": step.get("procedure_id"),
                }
                location["nestingLevel"] = index - 1
                thread_flow_locations.append({"location": location})

            sarif_result = {
                "ruleId": rule_id,
                "ruleIndex": rule_indexes[rule_id],
                "level": _sarif_level(finding.get("severity")),
                "message": {"text": finding.get("message", rule_id)},
                "locations": locations,
                "partialFingerprints": {"pyflow/v1": finding.get("fingerprint", "")},
                "properties": {
                    "confidence": finding.get("confidence"),
                    "analysisStatus": result.get("status", "complete"),
                    **(finding.get("properties") or {}),
                },
            }
            if thread_flow_locations:
                sarif_result["codeFlows"] = [
                    {"threadFlows": [{"locations": thread_flow_locations}]}
                ]
            sarif_results.append(sarif_result)

        invocation = {
            "executionSuccessful": result.get("status") == "complete",
            "properties": {"analysisStatus": result.get("status", "complete")},
        }
        if result.get("termination_reason"):
            invocation["toolExecutionNotifications"] = [
                {
                    "level": "warning",
                    "message": {"text": result["termination_reason"]},
                }
            ]
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "pyflow-security-ifds", "rules": rules}
                    },
                    "invocations": [invocation],
                    "results": sarif_results,
                }
            ],
        }

    if engine == "cpg":
        from pyflow.analysis.cpg.taint import CPGTaintEngine

        findings = result
        artifact_uri = (
            (str(args.targets[0]) if getattr(args, "targets", None) else "")
            if hasattr(CPGTaintEngine, "deduplicate")
            else ""
        )
        # Build minimal SARIF from CPG findings
        rules: List[Dict[str, Any]] = []
        results_list: List[Dict[str, Any]] = []
        seen_rules: Dict[str, int] = {}
        for f in findings:
            rule_id = f.get("rule_id", f.get("cwe", "CPG-TAINT"))
            if rule_id not in seen_rules:
                seen_rules[rule_id] = len(rules)
                rules.append(
                    {
                        "id": rule_id,
                        "name": f.get("rule", {}).get("name", rule_id),
                        "shortDescription": {
                            "text": f.get("rule", {}).get("short_description", "")
                        },
                    }
                )
            results_list.append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": seen_rules[rule_id],
                    "level": (
                        "error"
                        if f.get("severity") in ("critical", "high")
                        else "warning"
                    ),
                    "message": {
                        "text": (
                            f"Tainted data from {f.get('source_label', '?')} "
                            f"reaches {f.get('sink_label', '?')}"
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": artifact_uri},
                                "region": {"startLine": f.get("source_line", 0)},
                            }
                        }
                    ],
                }
            )
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "pyflow-security-cpg", "rules": rules}},
                    "results": results_list,
                }
            ],
        }

    # Default: generic SARIF wrapper
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": f"pyflow-security-{engine}"}},
                "results": [],
            }
        ],
    }


def _sarif_level(severity: str | None) -> str:
    normalized = (severity or "warning").lower()
    if normalized in {"critical", "high", "error"}:
        return "error"
    if normalized in {"low", "note", "info", "informational"}:
        return "note"
    return "warning"


# ── Shared helpers ────────────────────────────────────────────────────────


def _parse_exclude_tuple(exclude: str) -> tuple:
    if not exclude:
        return ()
    return tuple(p.strip() for p in exclude.split(",") if p.strip())


def _discover_python_files(targets: Sequence[str], recursive: bool) -> list[Path]:
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

    return (
        list(dict.fromkeys(sources)),
        list(dict.fromkeys(sinks)),
        list(dict.fromkeys(sanitizers)),
    )


def _parse_typestate_protocols(args) -> list[str]:
    raw = getattr(args, "typestate_protocol", None) or []
    protocols: list[str] = []
    for item in raw:
        for part in str(item).split(","):
            name = part.strip()
            if name:
                protocols.append(name)
    if not protocols:
        protocols.append("resource")
    return list(dict.fromkeys(protocols))


def _code_name(code) -> str:
    if hasattr(code, "codeName"):
        return code.codeName()
    if hasattr(code, "__name__"):
        return code.__name__
    return str(code)


def _result_status(result) -> tuple[str, str | None]:
    status = getattr(result, "status", "complete")
    return getattr(status, "value", str(status)), getattr(
        result, "termination_reason", None
    )


def _statistics_to_dict(statistics) -> dict[str, Any]:
    from dataclasses import asdict, is_dataclass

    if is_dataclass(statistics):
        return asdict(statistics)
    if hasattr(statistics, "__dict__"):
        return dict(vars(statistics))
    return dict(statistics)


def _ifds_result_to_dict(function: str, taint_result) -> Dict[str, Any]:
    """Convert an IFDS TaintAnalysisResult to a JSON-compatible dict."""
    from collections import defaultdict, deque
    from pyflow.analysis.ifds.reporting import normalized_taint_findings

    problem = getattr(taint_result, "_problem", None)
    adapter = getattr(problem, "adapter", None)
    enriched = adapter is not None
    normalized = defaultdict(deque)
    if enriched:
        for finding in normalized_taint_findings(taint_result):
            normalized[
                (
                    finding.node_id,
                    tuple(finding.properties.get("tainted_arguments", ())),
                )
            ].append(finding)
    findings = []
    for finding in taint_result.findings:
        tainted_arguments = [
            local.name or "<local>" for local in finding.tainted_arguments
        ]
        if not tainted_arguments:
            tainted_arguments = list(finding.tainted_argument_labels)

        if enriched:
            node_id = adapter.supergraph.node_id(finding.sink)
            normalized_finding = (
                normalized[(node_id, tuple(tainted_arguments))].popleft().to_dict()
            )
        else:
            normalized_finding = {}
        normalized_finding.update(
            {
                "sink_name": finding.sink_name,
                "procedure": _code_name(finding.sink.procedure.code),
                "block_kind": finding.sink.kind,
                "tainted_arguments": tainted_arguments,
                "explanations": normalized_finding.get("code_flow", []),
            }
        )
        findings.append(normalized_finding)

    statistics = _statistics_to_dict(taint_result.statistics)

    status, termination_reason = _result_status(taint_result)
    return {
        "function": function,
        "analysis": "taint",
        "findings": findings,
        "statistics": statistics,
        "status": status,
        "termination_reason": termination_reason,
    }


def _typestate_result_to_dict(function: str, typestate_result) -> Dict[str, Any]:
    """Convert an IFDS TypestateAnalysisResult to a JSON-compatible dict."""
    from pyflow.analysis.ifds.reporting import normalized_typestate_findings

    problem = getattr(typestate_result, "_problem", None)
    adapter = getattr(problem, "adapter", None)
    enriched = adapter is not None
    normalized = (
        {
            (
                finding.node_id,
                finding.kind,
                finding.properties.get("resource"),
                finding.properties.get("protocol"),
                finding.properties.get("state"),
            ): finding
            for finding in normalized_typestate_findings(typestate_result)
        }
        if enriched
        else {}
    )
    findings = []
    for finding in typestate_result.findings:
        if enriched:
            node_id = adapter.supergraph.node_id(finding.node)
            item = normalized[
                (
                    node_id,
                    finding.kind,
                    finding.resource_label,
                    finding.protocol,
                    finding.state,
                )
            ].to_dict()
        else:
            item = {}
        item.update(
            {
                "kind": finding.kind,
                "operation_name": finding.operation_name,
                "resource_label": finding.resource_label,
                "protocol": finding.protocol,
                "state": finding.state,
                "procedure": _code_name(finding.node.procedure.code),
                "block_kind": finding.node.kind,
            }
        )
        findings.append(item)

    statistics = _statistics_to_dict(typestate_result.statistics)

    status, termination_reason = _result_status(typestate_result)
    return {
        "function": function,
        "analysis": "typestate",
        "findings": findings,
        "statistics": statistics,
        "status": status,
        "termination_reason": termination_reason,
    }


def _nullness_result_to_dict(function: str, nullness_result) -> Dict[str, Any]:
    """Convert an IFDS nullness result to a JSON-compatible dictionary."""
    from pyflow.analysis.ifds.reporting import normalized_nullness_findings

    problem = getattr(nullness_result, "_problem", None)
    adapter = getattr(problem, "adapter", None)
    enriched = adapter is not None
    normalized = (
        {
            (
                finding.node_id,
                finding.kind,
                finding.properties.get("expression"),
            ): finding
            for finding in normalized_nullness_findings(nullness_result)
        }
        if enriched
        else {}
    )
    findings = []
    for finding in nullness_result.findings:
        if enriched:
            node_id = adapter.supergraph.node_id(finding.node)
            item = normalized[
                (node_id, finding.kind, finding.expression_label)
            ].to_dict()
        else:
            item = {}
        item.update(
            {
                "kind": finding.kind,
                "expression_label": finding.expression_label,
                "procedure": _code_name(finding.node.procedure.code),
                "block_kind": finding.node.kind,
            }
        )
        findings.append(item)
    status, termination_reason = _result_status(nullness_result)
    return {
        "function": function,
        "analysis": "nullness",
        "findings": findings,
        "statistics": _statistics_to_dict(nullness_result.statistics),
        "status": status,
        "termination_reason": termination_reason,
    }


# ── Main entry point ──────────────────────────────────────────────────────


def run_security(args) -> int:
    """Dispatch to the selected security engine and output results."""
    # Set up logging
    level = (
        logging.DEBUG
        if getattr(args, "debug", False)
        else logging.INFO if getattr(args, "verbose", False) else logging.WARNING
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
            return 2
        result = _run_ifds(targets, args)
        _output_results(engine, result, args)
        status = result.get("status", "complete")
        if status == "invalid":
            return 2
        if status in {"partial", "cancelled"}:
            return 3
        if status == "failed":
            return 4
        return 1 if result.get("findings") else 0

    elif engine == "cpg":
        result = _run_cpg(targets, args)
        _output_results(engine, result, args)
        return 1 if result else 0

    else:
        print(f"Unknown engine: {engine}", file=sys.stderr)
        return 1
