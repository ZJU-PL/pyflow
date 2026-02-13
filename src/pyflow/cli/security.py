"""
Security checker CLI.

Supports two checker engines:
- Pattern-based: Fast AST pattern matching (default)
- Semantic: Deep analysis using PyFlow's analysis pipeline
"""

import argparse
import logging
import sys
from pathlib import Path

from pyflow.checker.pattern.core.manager import SecurityManager
from pyflow.checker.pattern.core.config import SecurityConfig
from pyflow.checker.pattern.core import constants as b_constants
from pyflow.checker.semantic import BugFinderConfig, SemanticManager
from pyflow.checker.microbench import MicroBenchRunner
from pyflow.checker.formatters import text as text_formatter
from pyflow.checker.formatters import json as json_formatter
from pyflow.checker.formatters import sarif as sarif_formatter


def add_security_parser(subparsers):
    """Add security subcommand parser."""
    security_parser = subparsers.add_parser(
        "security",
        help="Run security analysis on Python files",
        description="Run security analysis using pattern-based (AST matching) or "
        "semantic (deep analysis) checker engines. "
        "Use --engine to choose between 'pattern' (default, fast) or 'semantic' (thorough).",
    )
    security_parser.add_argument(
        "targets", nargs="*", help="Files or directories to check"
    )
    security_parser.add_argument(
        "-r", "--recursive", action="store_true", help="Scan directories recursively"
    )
    security_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    security_parser.add_argument(
        "-d", "--debug", action="store_true", help="Debug output"
    )
    security_parser.add_argument(
        "--exclude", help="Comma-separated list of paths to exclude"
    )
    security_parser.add_argument(
        "--engine",
        choices=["pattern", "semantic"],
        default="pattern",
        help="Checker engine to use: 'pattern' for fast AST matching (default), "
        "'semantic' for deep analysis using PyFlow's analysis pipeline",
    )
    security_parser.add_argument(
        "--taint-engine",
        choices=["ast", "ipa", "both"],
        default="ast",
        help="Taint analysis engine (only for --engine semantic): "
        "'ast' for local AST-based analysis (default), "
        "'ipa' for interprocedural IPA-aware analysis, "
        "'both' to run both and compare results",
    )
    security_parser.add_argument(
        "--micro-bench",
        metavar="PATH",
        type=str,
        help="Run micro-benchmarks from SAST-Python3 evaluation suite. "
        "PATH should be a config.json file or directory containing config.json files. "
        "Measures False Positives (FP) and False Negatives (FN).",
    )
    security_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format: 'text' (default), 'json', or 'sarif'",
    )
    security_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file (default: stdout)",
    )


def run_security_analysis(targets, args):
    """Main CLI entry point"""
    # args is already parsed by the main CLI parser

    # Set up logging
    level = (
        logging.DEBUG
        if args.debug
        else logging.INFO if args.verbose else logging.WARNING
    )
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    # Handle micro-benchmark mode
    if args.micro_bench:
        bench_path = Path(args.micro_bench)
        if not bench_path.exists():
            print(f"Error: Benchmark path not found: {bench_path}", file=sys.stderr)
            return 1

        # Run benchmark with specified taint engine
        runner = MicroBenchRunner(
            engine=args.engine, taint_engine=args.taint_engine, verbose=args.verbose
        )
        results = runner.run_benchmark(bench_path)
        runner.print_results(results)
        return 0

    targets = targets or ["."]

    # Determine output file
    output_file = open(args.output, "w") if args.output else sys.stdout

    try:
        # Choose engine based on --engine option
        if args.engine == "semantic":
            # Use semantic checker with adapter manager
            config = BugFinderConfig(
                verbose=args.verbose,
                recursive=args.recursive,
                exclude=tuple(args.exclude.split(",")) if args.exclude else tuple(),
                taint_engine=(
                    args.taint_engine if args.taint_engine != "both" else "ast"
                ),
            )
            manager = SemanticManager(
                config=config, debug=args.debug, verbose=args.verbose, quiet=False
            )
            manager.analyze(targets)
        else:
            # Use pattern-based checker (default)
            config = SecurityConfig()

            # Create security manager
            manager = SecurityManager(
                config=config, debug=args.debug, verbose=args.verbose, quiet=False
            )

            # Discover files
            manager.discover_files(targets, recursive=args.recursive, excluded_paths="")

            # Run security checks
            manager.run_tests()

        # Use formatters to output results
        sev_level = b_constants.LOW
        conf_level = b_constants.LOW

        if args.format == "json":
            json_formatter.report(manager, output_file, sev_level, conf_level)
        elif args.format == "sarif":
            sarif_formatter.report(manager, output_file, sev_level, conf_level)
        else:  # text format
            text_formatter.report(manager, output_file, sev_level, conf_level)

        # Return exit code based on whether issues were found
        issues = manager.get_issue_list(sev_level, conf_level)
        return 1 if issues else 0

    finally:
        if args.output:
            output_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyFlow Security Checker")
    add_security_parser(parser.add_subparsers(dest="command", required=True))

    args = parser.parse_args()
    sys.exit(run_security_analysis(args.targets, args))
