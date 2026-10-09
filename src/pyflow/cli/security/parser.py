"""Argument parser for the unified security-analysis command."""

from __future__ import annotations

import argparse
from pathlib import Path


def add_security_parser(subparsers):
    """Add the unified ``pyflow security`` subcommand parser."""
    p = subparsers.add_parser(
        "security",
        help="Run security analysis on Python files",
        description=(
            "Run security analysis using one of four engines. "
            "Use --engine to choose: 'ast-scanner' (fast AST matching, default), "
            "'ast-dataflow' (taint dataflow over the Python AST), "
            "'ifds' (interprocedural dataflow over discovered entries), or "
            "'cpg' (CPG-based context-sensitive analysis)."
        ),
    )
    p.add_argument(
        "targets",
        nargs="*",
        help="Files or directories to analyze (default: current directory)",
    )
    p.add_argument(
        "--engine",
        choices=["ast-scanner", "ast-dataflow", "ifds", "cpg"],
        default="ast-scanner",
        help="Security analysis engine to use",
    )
    p.add_argument(
        "--config",
        type=Path,
        help="JSON config file for IFDS parameters (default: project pyflow.json)",
    )
    p.add_argument(
        "--analysis",
        choices=["taint", "nullness", "typestate", "class-pollution"],
        default=argparse.SUPPRESS,
        help="IFDS analysis to run when --engine ifds is selected",
    )
    p.add_argument(
        "--sources",
        nargs="+",
        default=argparse.SUPPRESS,
        help=(
            "Source function names for taint-style checks "
            "(repeatable, e.g. 'request.args' 'input')"
        ),
    )
    p.add_argument(
        "--sinks",
        nargs="+",
        default=argparse.SUPPRESS,
        help=(
            "Sink function names for taint-style checks "
            "(repeatable, e.g. 'eval' 'subprocess.run')"
        ),
    )
    p.add_argument(
        "--sanitizers",
        nargs="+",
        default=argparse.SUPPRESS,
        help="Sanitizer function names for taint-style checks (repeatable)",
    )
    p.add_argument(
        "--entry",
        type=Path,
        action="append",
        default=argparse.SUPPRESS,
        help=(
            "Entry point file relative to the project root for --engine ifds "
            "(repeatable; all discovered directory entries are analyzed by default)"
        ),
    )
    p.add_argument(
        "--framework",
        nargs="*",
        default=argparse.SUPPRESS,
        metavar="FRAMEWORK",
        choices=[
            "aiohttp",
            "cloud",
            "concurrency",
            "django",
            "falcon",
            "fastapi",
            "flask",
            "injection",
            "network",
            "nosql",
            "pandas",
            "pyramid",
            "requests",
            "sanic",
            "serialization",
            "sql",
            "sqlalchemy",
            "stdlib",
            "tornado",
            "bottle",
            "wtforms",
            "xml",
        ],
        help=(
            "Framework rule pack(s) for taint sources/sinks/sanitizers "
            "(supports both --engine cpg and --engine ifds).  Default: stdlib "
            "(covers Python builtins: open(), eval(), subprocess, …).  "
            "Pass --framework with no values to auto-detect packs from imports "
            "in the target source.  Available: aiohttp, cloud, concurrency, "
            "django, falcon, fastapi, flask, injection, network, nosql, "
            "pandas, requests, serialization, sql, sqlalchemy, stdlib, tornado, "
            "wtforms, xml."
        ),
    )
    p.add_argument(
        "--registry-path",
        nargs="+",
        default=argparse.SUPPRESS,
        metavar="PATH",
        help=(
            "Load custom rule-pack JSON file(s) or directory(ies) of JSON "
            "rule-packs (both engines).  Each file must follow the same schema "
            "as the bundled rule-packs under pyflow/config/."
        ),
    )
    p.add_argument("--ifds-max-seconds", type=_positive_float, default=argparse.SUPPRESS)
    p.add_argument("--ifds-max-path-edges", type=_positive_int, default=argparse.SUPPRESS)
    p.add_argument("--ifds-max-queue-size", type=_positive_int, default=argparse.SUPPRESS)
    p.add_argument("--ifds-max-incoming-records", type=_positive_int, default=argparse.SUPPRESS)
    p.add_argument("--ifds-max-summary-entries", type=_positive_int, default=argparse.SUPPRESS)
    p.add_argument("--ifds-max-facts-per-node", type=_positive_int, default=argparse.SUPPRESS)
    p.add_argument(
        "--ifds-max-contexts-per-procedure", type=_positive_int, default=argparse.SUPPRESS
    )
    p.add_argument("--ifds-max-memory-bytes", type=_positive_int, default=argparse.SUPPRESS)
    p.add_argument(
        "--ifds-callgraph-max-iterations",
        type=_positive_int,
        default=argparse.SUPPRESS,
        help=(
            "Maximum constraint-callgraph worklist states before retaining "
            "partial edges and using the direct-call fallback (default: 256)."
        ),
    )
    p.add_argument("--ifds-context-depth", type=_non_negative_int, default=argparse.SUPPRESS)
    p.add_argument(
        "--ifds-trace-mode",
        choices=["none", "findings", "all"],
        default=argparse.SUPPRESS,
    )
    p.add_argument(
        "--ifds-unknown-call-policy",
        choices=["drop", "preserve", "havoc"],
        default=argparse.SUPPRESS,
        help=(
            "Semantics for unresolved calls: drop taint, preserve argument "
            "taint into the return value, or conservatively havoc arguments "
            "(default: preserve)."
        ),
    )
    p.add_argument(
        "--cpg-max-states",
        type=_positive_int,
        help="Stop CPG propagation after this many abstract states (reports partial)",
    )
    p.add_argument(
        "--cpg-max-seconds",
        type=_positive_float,
        help="Stop CPG propagation after this many seconds (reports partial)",
    )
    p.add_argument(
        "--cpg-context-depth",
        type=_positive_int,
        default=3,
        help="Maximum CPG call-string depth (default: 3)",
    )
    p.add_argument(
        "--typestate-protocol",
        action="append",
        default=argparse.SUPPRESS,
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
        help="Scan directories recursively (automatic for directory targets)",
    )
    p.add_argument(
        "--exclude",
        action="append",
        nargs="+",
        default=[],
        help="Paths/globs to exclude (repeatable; accepts comma-separated values)",
    )
    p.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Include tests, hidden directories, build outputs, and virtual environments",
    )
    p.add_argument(
        "--no-deduplicate",
        action="store_true",
        help="Report every overlapping AST rule separately instead of folding known vulnerability families",
    )
    p.add_argument(
        "--severity",
        type=str.lower,
        choices=("low", "medium", "high", "critical"),
        default="low",
        help="Minimum severity to report",
    )
    p.add_argument(
        "--confidence",
        type=str.lower,
        choices=("low", "medium", "high"),
        default="low",
        help="Minimum confidence to report",
    )
    p.add_argument(
        "--skip-rule",
        "--skip",
        action="append",
        nargs="+",
        default=[],
        metavar="RULE",
        help="Disable rule IDs or scanner rule names (repeatable; accepts commas)",
    )
    p.add_argument(
        "--fail-on",
        "--fail-on-severity",
        type=str.lower,
        choices=("none", "low", "medium", "high", "critical"),
        help="Return 1 when a reported finding reaches this severity; tool errors remain nonzero",
    )
    p.add_argument(
        "--baseline", type=Path, help="Suppress findings present in a previous JSON report"
    )
    p.add_argument(
        "--ast-unknown-call-policy",
        choices=("preserve", "havoc"),
        default="preserve",
        help="AST-dataflow unresolved calls: preserve argument taint (default; disclosed as partial), or conservatively introduce all source kinds",
    )
    p.add_argument(
        "--ast-entry-source-kind",
        action="append",
        help="Source kinds for AST-dataflow entry parameters (repeatable; default: user_input)",
    )
    p.add_argument(
        "--json-schema",
        choices=("legacy", "unified"),
        default="legacy",
        help="JSON report schema (default: legacy for compatibility; unified has common finding fields)",
    )
    p.add_argument(
        "--format",
        choices=[
            "text",
            "json",
            "sarif",
            "csv",
            "custom",
            "html",
            "screen",
            "xml",
            "yaml",
        ],
        default="text",
        help="Output format",
    )
    p.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file (default: stdout)",
    )
    p.add_argument(
        "--exit-code-policy",
        choices=["findings", "report"],
        default="report",
        help=(
            "Exit-code contract: 'findings' preserves scanner-style nonzero "
            "codes for findings/partial analyses; 'report' (default) returns zero "
            "for complete/partial reports, while invalid/failed analyses remain "
            "nonzero. Findings and completeness are recorded in the report"
        ),
    )
    p.add_argument(
        "--custom-template",
        default=None,
        help="Template string for --format custom "
        "(e.g. '{abspath}:{line}: {test_id} [{severity}] {msg}')",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--debug", "-d", action="store_true", help="Debug output")

    return p


# ── argparse type validators ───────────────────────────────────────────────


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid positive int value: {value!r}")
    if parsed < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {parsed}")
    return parsed


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid non-negative int value: {value!r}")
    if parsed < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {parsed}")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid positive float value: {value!r}")
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"must be > 0, got {parsed}")
    return parsed
