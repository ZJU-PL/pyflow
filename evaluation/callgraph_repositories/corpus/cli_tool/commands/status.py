from __future__ import annotations

import json
import os
import platform
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any
import time

from ..config import Config
from ..logger import get_logger

logger = get_logger(__name__)


def status(args: Namespace, config: Config) -> int:
    status_data = _gather_status(config)
    
    if args.json:
        print(json.dumps(status_data, indent=2))
        return 0
    
    if args.watch:
        return _watch_status(config)
    
    _print_status(status_data)
    return 0


def _gather_status(config: Config) -> dict[str, Any]:
    return {
        "project": {
            "name": config.name,
            "version": config.version,
            "author": config.author,
            "description": config.description,
        },
        "directories": {
            "build": str(config.build_dir),
            "output": str(config.output_dir),
            "cache": str(config.cache_dir),
            "build_exists": config.build_dir.exists(),
            "output_exists": config.output_dir.exists(),
            "cache_exists": config.cache_dir.exists(),
        },
        "environment": {
            "python_version": sys.version,
            "platform": platform.platform(),
            "python_executable": sys.executable,
            "cwd": str(Path.cwd()),
        },
        "files": _count_files(),
    }


def _count_files() -> dict[str, int]:
    counts = {
        "python": 0,
        "tests": 0,
        "config": 0,
    }
    
    for path in Path(".").rglob("*.py"):
        if "test" in path.name.lower() or "test" in str(path).lower():
            counts["tests"] += 1
        else:
            counts["python"] += 1
    
    for path in Path(".").rglob("*.json"):
        counts["config"] += 1
    
    return counts


def _print_status(data: dict[str, Any]) -> None:
    project = data["project"]
    print(f"Project: {project['name']} v{project['version']}")
    if project["author"]:
        print(f"Author: {project['author']}")
    print()
    
    dirs = data["directories"]
    print("Directories:")
    for key in ["build", "output", "cache"]:
        path = dirs[key]
        exists = dirs[f"{key}_exists"]
        status = "✓" if exists else "✗"
        print(f"  {status} {key}: {path}")
    print()
    
    env = data["environment"]
    print("Environment:")
    print(f"  Python: {env['python_version'].split()[0]}")
    print(f"  Platform: {env['platform']}")
    print()
    
    files = data["files"]
    print("Files:")
    print(f"  Python: {files['python']}")
    print(f"  Tests: {files['tests']}")
    print(f"  Config: {files['config']}")


def _watch_status(config: Config) -> int:
    logger.info("Watching for changes (press Ctrl+C to stop)")
    
    try:
        while True:
            status_data = _gather_status(config)
            _clear_screen()
            _print_status(status_data)
            print()
            print(f"Last updated: {time.strftime('%H:%M:%S')}")
            time.sleep(2)
    except KeyboardInterrupt:
        logger.info("Stopped watching")
        return 0


def _clear_screen() -> None:
    print("\033[2J\033[H", end="")


class StatusChecker:
    def __init__(self, config: Config):
        self.config = config
        self._checks: list[Any] = []
    
    def add_check(self, check: Any) -> None:
        self._checks.append(check)
    
    def run_checks(self) -> dict[str, Any]:
        results = {}
        for check in self._checks:
            name = check.__name__ if hasattr(check, "__name__") else str(check)
            try:
                results[name] = check()
            except Exception as e:
                results[name] = {"error": str(e)}
        return results
