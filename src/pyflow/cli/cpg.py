"""
CPG CLI — ``pyflow cpg scan`` command for running CPG-based taint analysis.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from pyflow.analysis.cpg.build import build_cpg, build_cpg_from_directory
from pyflow.analysis.cpg.taint import CPGTaintEngine
from pyflow.analysis.cpg.rules import load_rules, detect_frameworks


def add_cpg_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "cpg",
        help="Code Property Graph analysis commands",
    )
    sub = parser.add_subparsers(dest="cpg_command", required=True)

    scan = sub.add_parser("scan", help="Run taint analysis via CPG")
    scan.add_argument(
        "target",
        help="Python file or directory to analyze",
    )
    scan.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recurse into subdirectories (for directory targets)",
    )
    scan.add_argument(
        "--framework", "-f",
        action="append",
        default=[],
        choices=["django", "flask", "fastapi", "sqlalchemy", "stdlib",
                 "cloud", "injection", "network", "nosql", "requests", "sql"],
        help="Framework rule pack to load (repeatable; auto-detect if omitted)",
    )
    scan.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )
    scan.add_argument(
        "--sarif", type=str, metavar="FILE",
        help="Write SARIF v2.1.0 report to FILE",
    )
    scan.add_argument(
        "--dedup", action="store_true", default=True,
        help="Deduplicate similar findings (default: on)",
    )
    scan.add_argument(
        "--no-dedup", dest="dedup", action="store_false",
        help="Disable deduplication",
    )
    scan.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-error output"
    )
    scan.add_argument(
        "--source", action="append", default=[],
        help="Additional taint source name (repeatable)",
    )
    scan.add_argument(
        "--sink", action="append", default=[],
        help="Additional taint sink name (repeatable)",
    )
    scan.add_argument(
        "--sanitizer", action="append", default=[],
        help="Additional sanitizer name (repeatable)",
    )


def run_cpg(args) -> int:
    if args.cpg_command != "scan":
        print(f"Unknown CPG command: {args.cpg_command}", file=sys.stderr)
        return 1

    target = Path(args.target)
    if not target.exists():
        print(f"Error: '{target}' not found", file=sys.stderr)
        return 1

    if target.is_dir():
        cpg = build_cpg_from_directory(
            str(target), recursive=args.recursive
        )
    else:
        source = target.read_text(encoding="utf-8", errors="replace")
        cpg = build_cpg(source, filename=str(target))

    if len(cpg.functions) == 0:
        if not args.quiet:
            print("No functions found to analyze.", file=sys.stderr)
        return 1

    cpg.build()
    engine = CPGTaintEngine(cpg)

    for src in getattr(args, "source", []) or []:
        engine.add_source(src)
    for snk in getattr(args, "sink", []) or []:
        engine.add_sink(snk)
    for san in getattr(args, "sanitizer", []) or []:
        engine.add_sanitizer(san)

    frameworks: Optional[List[str]] = getattr(args, "framework", None) or None
    if frameworks and len(frameworks) == 0:
        frameworks = None
    if frameworks is None and not target.is_dir():
        try:
            source = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            source = ""
        frameworks = detect_frameworks(source)
    load_rules(engine, frameworks=frameworks)

    findings = engine.find_taint_paths()
    if getattr(args, "dedup", True):
        findings = CPGTaintEngine.deduplicate(findings)

    if args.sarif:
        doc = CPGTaintEngine.to_sarif(
            findings, artifact_uri=str(target)
        )
        Path(args.sarif).write_text(json.dumps(doc, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"SARIF report written to {args.sarif}", file=sys.stderr)

    if args.json:
        print(CPGTaintEngine.to_json(findings))
    else:
        _print_text_report(findings, quiet=args.quiet or bool(args.sarif))

    return 0


def _print_text_report(findings, *, quiet: bool = False) -> None:
    if quiet:
        return
    if not findings:
        print("No taint findings.")
        return
    print(f"\n{len(findings)} taint finding(s):\n")
    for i, f in enumerate(findings, 1):
        conf = f.confidence
        bar = "█" * int(conf * 10) + "░" * (10 - int(conf * 10))
        print(
            f"  [{i}] {f.cwe} [{f.severity}] "
            f"confidence={conf:.0%} [{bar}]"
        )
        print(f"      source: {f.source_label} (line {f.source_line})")
        print(f"      sink:   {f.sink_label} (line {f.sink_line})")
        print(f"      path:   {f.path_length} nodes, "
              f"tags={sorted(f.tags)}, sanitizers={sorted(f.sanitizers)}")
        print()