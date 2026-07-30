from __future__ import annotations

import argparse
import sys
from typing import Any, Sequence

from .config import Config, load_config
from .logger import setup_logging, get_logger
from .commands import build, clean, run, status


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pytool",
        description="A sample CLI tool for testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pytool build --output dist/
  pytool run --verbose
  pytool clean --all
        """,
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        default=None,
        help="Path to configuration file",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    _add_build_parser(subparsers)
    _add_clean_parser(subparsers)
    _add_run_parser(subparsers)
    _add_status_parser(subparsers)

    return parser


def _add_build_parser(subparsers: Any) -> None:
    p = subparsers.add_parser("build", help="Build the project")
    p.add_argument(
        "-o", "--output",
        type=str,
        default="build/",
        help="Output directory",
    )
    p.add_argument(
        "--release",
        action="store_true",
        help="Build in release mode",
    )
    p.add_argument(
        "--target",
        type=str,
        choices=["default", "wasm", "native"],
        default="default",
        help="Build target platform",
    )
    p.add_argument(
        "files",
        nargs="*",
        help="Files to build",
    )


def _add_clean_parser(subparsers: Any) -> None:
    p = subparsers.add_parser("clean", help="Clean build artifacts")
    p.add_argument(
        "--all",
        action="store_true",
        dest="all_artifacts",
        help="Remove all generated files",
    )
    p.add_argument(
        "--cache",
        action="store_true",
        help="Also clean cache directory",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show files that would be deleted",
    )


def _add_run_parser(subparsers: Any) -> None:
    p = subparsers.add_parser("run", help="Run the project")
    p.add_argument(
        "--env",
        type=str,
        action="append",
        default=[],
        help="Environment variables (KEY=VALUE)",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to run on",
    )
    p.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="Host to bind to",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes",
    )
    p.add_argument(
        "--",
        dest="passthrough",
        nargs=argparse.REMAINDER,
        help="Arguments to pass to the application",
    )


def _add_status_parser(subparsers: Any) -> None:
    p = subparsers.add_parser("status", help="Show project status")
    p.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    p.add_argument(
        "--watch",
        action="store_true",
        help="Continuously watch for changes",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    config = load_config(args.config) if args.config else Config()

    log_level = args.log_level
    if args.verbose >= 2:
        log_level = "DEBUG"
    elif args.verbose == 1:
        log_level = "INFO"
    elif args.quiet:
        log_level = "ERROR"

    setup_logging(level=log_level, no_color=args.no_color)
    logger = get_logger(__name__)

    if args.dry_run:
        logger.info("DRY RUN MODE - no changes will be made")

    try:
        if args.command == "build":
            return build(args, config)
        elif args.command == "clean":
            return clean(args, config)
        elif args.command == "run":
            return run(args, config)
        elif args.command == "status":
            return status(args, config)
        else:
            logger.error(f"Unknown command: {args.command}")
            return 1
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose >= 1:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
