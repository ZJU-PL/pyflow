"""Optional stub/runtime consistency checks through mypy's stubtest."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def add_stubtest_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "stubtest",
        help="Compare .pyi stubs with runtime objects (optional dependency)",
        description=(
            "Compare stubs with runtime objects. Requires the optional 'stubs' "
            "extra: pip install 'pyflow-analysis[stubs]'."
        ),
        add_help=False,
    )
    parser.add_argument("stubtest_args", nargs=argparse.REMAINDER)


def _stubtest_executable() -> str | None:
    sibling = Path(sys.executable).with_name("stubtest")
    if sibling.is_file():
        return str(sibling)
    return shutil.which("stubtest")


def run_stubtest(arguments: list[str]) -> int:
    executable = _stubtest_executable()
    if executable is None:
        print(
            "Error: mypy stubtest is not installed. "
            "Install it with: pip install 'pyflow-analysis[stubs]'",
            file=sys.stderr,
        )
        return 2
    try:
        completed = subprocess.run([executable, *arguments], check=False)
    except OSError as exc:
        print(f"Error: could not run mypy stubtest: {exc}", file=sys.stderr)
        return 2
    return completed.returncode
