"""CLI for independent result normalization and evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluation import evaluate_results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.security_benchmark_evaluation",
        description="Normalize analyzer output, map rules to CWEs, and compute metrics",
    )
    parser.add_argument("results", type=Path, help="Runner output directory")
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, help="Versioned rule-to-CWE JSON")
    parser.add_argument(
        "--label-pointer",
        default="/cwe",
        help="JSON pointer inside each sample's labels (default: /cwe)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        metrics = evaluate_results(
            args.results,
            args.output,
            mapping_path=args.mapping,
            label_pointer=args.label_pointer,
        )
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(metrics["overall"], sort_keys=True))
    print(f"Metrics: {args.output / 'metrics.json'}")
    return 0
