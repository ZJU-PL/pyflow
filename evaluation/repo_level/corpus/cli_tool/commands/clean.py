from __future__ import annotations

import shutil
from argparse import Namespace
from pathlib import Path

from ..config import Config
from ..logger import get_logger

logger = get_logger(__name__)


def clean(args: Namespace, config: Config) -> int:
    logger.info("Cleaning project")
    
    dirs_to_clean = []
    
    if args.all_artifacts:
        dirs_to_clean.extend([
            config.build_dir,
            config.output_dir,
        ])
        if args.cache:
            dirs_to_clean.append(config.cache_dir)
    else:
        dirs_to_clean.append(config.build_dir)
        if args.cache:
            dirs_to_clean.append(config.cache_dir)
    
    for dir_path in dirs_to_clean:
        dir_path = Path(dir_path)
        if not dir_path.exists():
            logger.debug(f"Directory does not exist: {dir_path}")
            continue
        
        if args.dry_run:
            logger.info(f"Would remove: {dir_path}")
            _list_files(dir_path)
        else:
            logger.info(f"Removing: {dir_path}")
            shutil.rmtree(dir_path)
    
    _clean_pycache(Path("."))
    
    logger.info("Clean complete")
    return 0


def _list_files(directory: Path) -> None:
    for path in directory.rglob("*"):
        logger.info(f"  {path}")


def _clean_pycache(directory: Path) -> None:
    for pycache in directory.rglob("__pycache__"):
        if pycache.is_dir():
            logger.debug(f"Removing: {pycache}")
            shutil.rmtree(pycache, ignore_errors=True)
    
    for pyc_file in directory.rglob("*.pyc"):
        logger.debug(f"Removing: {pyc_file}")
        pyc_file.unlink()


class Cleaner:
    def __init__(self, config: Config):
        self.config = config
        self._patterns: list[str] = []
        self._dry_run = False
    
    def add_pattern(self, pattern: str) -> None:
        self._patterns.append(pattern)
    
    def set_dry_run(self, value: bool) -> None:
        self._dry_run = value
    
    def clean(self, directory: Path) -> int:
        removed_count = 0
        
        for pattern in self._patterns:
            for path in directory.rglob(pattern):
                if self._dry_run:
                    logger.info(f"Would remove: {path}")
                else:
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
                    logger.debug(f"Removed: {path}")
                removed_count += 1
        
        return removed_count
