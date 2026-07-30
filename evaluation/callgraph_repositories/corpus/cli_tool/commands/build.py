from __future__ import annotations

import shutil
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

from ..config import Config
from ..logger import get_logger

logger = get_logger(__name__)


def build(args: Namespace, config: Config) -> int:
    logger.info(f"Building project: {config.name}")
    
    output_dir = Path(args.output) if args.output else config.build_dir
    logger.debug(f"Output directory: {output_dir}")
    
    if args.dry_run:
        logger.info("Would create output directory")
        return 0
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    files = args.files if args.files else _find_source_files()
    logger.info(f"Found {len(files)} source files")
    
    for src_file in files:
        src_path = Path(src_file)
        if not src_path.exists():
            logger.error(f"Source file not found: {src_file}")
            continue
        
        dst_path = output_dir / src_path.name
        logger.debug(f"Copying {src_path} -> {dst_path}")
        
        if not args.dry_run:
            shutil.copy2(src_path, dst_path)
    
    if args.release:
        logger.info("Building in release mode")
        _optimize(output_dir)
    
    logger.info(f"Build complete: {output_dir}")
    return 0


def _find_source_files(directory: Path = Path(".")) -> list[Path]:
    patterns = ["*.py", "*.pyx", "*.pyi"]
    files = []
    for pattern in patterns:
        files.extend(directory.glob(pattern))
    return sorted(files)


def _optimize(output_dir: Path) -> None:
    logger.debug("Running optimizations")
    compiled_files = list(output_dir.glob("*.py"))
    
    for py_file in compiled_files:
        pyc_file = py_file.with_suffix(".pyc")
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(py_file)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(f"Failed to compile {py_file}: {result.stderr}")


class Builder:
    def __init__(self, config: Config):
        self.config = config
        self._steps: list[Any] = []
    
    def add_step(self, step: Any) -> None:
        self._steps.append(step)
    
    def build(self, output_dir: Path, files: list[Path] | None = None) -> int:
        logger.info(f"Starting build with {len(self._steps)} steps")
        
        for i, step in enumerate(self._steps):
            logger.debug(f"Executing step {i + 1}/{len(self._steps)}: {step}")
            try:
                step()
            except Exception as e:
                logger.error(f"Step {i + 1} failed: {e}")
                return 1
        
        return 0


class Target:
    def __init__(self, name: str, platform: str = "default"):
        self.name = name
        self.platform = platform
        self._dependencies: list[str] = []
    
    def depends_on(self, *targets: str) -> None:
        self._dependencies.extend(targets)
    
    @property
    def dependencies(self) -> list[str]:
        return list(self._dependencies)
