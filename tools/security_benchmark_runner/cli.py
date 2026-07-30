"""CLI for the manifest-driven security benchmark runner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import BUILTIN_ENGINES, PYFLOW_ENGINES
from .manifest import BenchmarkManifest, ManifestError
from .runner import BenchmarkRunner, RunnerOptions, load_engine_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.security_benchmark_runner",
        description="Run reproducible, manifest-driven analyzer benchmarks",
    )
    commands = parser.add_subparsers(
        dest="command", required=True, help="Benchmark operation"
    )
    run = commands.add_parser("run", help="Run analyzers over a benchmark manifest")
    run.add_argument("manifest", type=Path)
    run.add_argument("--output", "-o", type=Path, required=True)
    run.add_argument(
        "--engine",
        action="append",
        help=(
            "Built-in or configured engine; repeat for multiple engines. "
            "Defaults to the four PyFlow security engines."
        ),
    )
    run.add_argument("--config", type=Path, help="Versioned per-engine JSON config")
    run.add_argument("--sample", action="append", help="Run only this sample id")
    run.add_argument("--jobs", type=_positive_int, default=1)
    run.add_argument("--timeout", type=_positive_float, default=1800.0)
    run.add_argument(
        "--force", action="store_true", help="Replace existing per-engine results"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = BenchmarkManifest.load(args.manifest)
        engines = _selected_engines(args.engine)
        engine_config = load_engine_config(args.config)
        runner = BenchmarkRunner(
            manifest,
            RunnerOptions(
                output_dir=args.output,
                engines=engines,
                jobs=args.jobs,
                timeout_seconds=args.timeout,
                force=args.force,
                sample_ids=frozenset(args.sample or ()),
                engine_config=engine_config,
            ),
        )
        summary = runner.run()
    except (ManifestError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary["status_counts"], sort_keys=True))
    print(f"Summary: {args.output / 'summary.json'}")
    return 0


def _selected_engines(values: list[str] | None) -> tuple[str, ...]:
    if not values:
        return tuple(PYFLOW_ENGINES)
    if "all" in values:
        return BUILTIN_ENGINES
    return tuple(dict.fromkeys(values))


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed
