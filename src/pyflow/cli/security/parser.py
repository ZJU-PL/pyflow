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
            "'ifds' (interprocedural dataflow rooted at an entry file), or "
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
        help="JSON config file for IFDS analysis parameters",
    )
    p.add_argument(
        "--analysis",
        choices=["taint", "nullness", "typestate"],
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
        help=(
            "Entry point file relative to the project root for --engine ifds "
            "(auto-detected for directory targets; a file target is its own entry)"
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
            "requests",
            "serialization",
            "sql",
            "sqlalchemy",
            "stdlib",
            "tornado",
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
    p.add_argument("--ifds-max-seconds", type=_positive_float)
    p.add_argument("--ifds-max-path-edges", type=_positive_int)
    p.add_argument("--ifds-max-queue-size", type=_positive_int)
    p.add_argument("--ifds-max-incoming-records", type=_positive_int)
    p.add_argument("--ifds-max-summary-entries", type=_positive_int)
    p.add_argument("--ifds-max-facts-per-node", type=_positive_int)
    p.add_argument("--ifds-max-contexts-per-procedure", type=_positive_int)
    p.add_argument("--ifds-max-memory-bytes", type=_positive_int)
    p.add_argument(
        "--ifds-context-depth", type=_non_negative_int, default=argparse.SUPPRESS
    )
    p.add_argument(
        "--ifds-trace-mode",
        choices=["none", "findings", "all"],
        default=argparse.SUPPRESS,
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
        help="Scan directories recursively",
    )
    p.add_argument(
        "--exclude",
        help="Comma-separated paths to exclude",
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
        "--custom-template",
        default=None,
        help="Template string for --format custom "
        "(e.g. '{abspath}:{line}: {test_id} [{severity}] {msg}')",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--debug", "-d", action="store_true", help="Debug output")


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
