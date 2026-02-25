from __future__ import annotations

import shutil
from pathlib import Path
from typing import Iterator


def find_files(
    directory: Path | str,
    patterns: list[str],
    exclude: list[str] | None = None,
) -> list[Path]:
    directory = Path(directory)
    exclude = exclude or []
    files = []
    
    for pattern in patterns:
        for path in directory.rglob(pattern):
            if any(exc in str(path) for exc in exclude):
                continue
            files.append(path)
    
    return sorted(files)


def ensure_dir(path: Path | str) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def copy_tree(src: Path | str, dst: Path | str) -> int:
    src = Path(src)
    dst = Path(dst)
    
    if not src.exists():
        raise FileNotFoundError(f"Source does not exist: {src}")
    
    dst.mkdir(parents=True, exist_ok=True)
    
    count = 0
    for src_file in src.rglob("*"):
        if src_file.is_dir():
            continue
        
        rel_path = src_file.relative_to(src)
        dst_file = dst / rel_path
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dst_file)
        count += 1
    
    return count


def walk_files(directory: Path | str) -> Iterator[Path]:
    directory = Path(directory)
    for path in directory.rglob("*"):
        if path.is_file():
            yield path


def get_file_size(path: Path | str) -> int:
    return Path(path).stat().st_size


def get_directory_size(directory: Path | str) -> int:
    total = 0
    for path in walk_files(directory):
        total += path.stat().st_size
    return total


def touch(path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    return path


def remove_if_exists(path: Path | str) -> bool:
    path = Path(path)
    if path.exists():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return True
    return False
