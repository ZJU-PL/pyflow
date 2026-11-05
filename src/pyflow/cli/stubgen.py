"""Optional stub generation through mypy's stubgen utility."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def add_stubgen_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "stubgen",
        help="Generate .pyi stubs with mypy's stubgen (optional dependency)",
        description=(
            "Generate .pyi stubs from Python source or runtime C modules. "
            "Requires the optional 'stubs' extra: pip install 'pyflow-analysis[stubs]'."
        ),
        add_help=False,
    )
    parser.add_argument("stubgen_args", nargs=argparse.REMAINDER)


def _stubgen_executable() -> str | None:
    sibling = Path(sys.executable).with_name("stubgen")
    if sibling.is_file():
        return str(sibling)
    return shutil.which("stubgen")


def run_stubgen(arguments: list[str]) -> int:
    executable = _stubgen_executable()
    if executable is None:
        print(
            "Error: mypy stubgen is not installed. "
            "Install it with: pip install 'pyflow-analysis[stubs]'",
            file=sys.stderr,
        )
        return 2
    try:
        completed = subprocess.run([executable, *arguments], check=False)
    except OSError as exc:
        print(f"Error: could not run mypy stubgen: {exc}", file=sys.stderr)
        return 2
    return completed.returncode
