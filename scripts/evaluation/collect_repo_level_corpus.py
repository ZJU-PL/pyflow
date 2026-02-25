#!/usr/bin/env python3
"""Collect a local repo-level corpus for regression testing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List


@dataclass
class ProjectEntry:
    name: str
    path: str
    python_files: int
    content_hash: str


def _iter_python_files(root: Path):
    for p in root.rglob("*.py"):
        if ".git" in p.parts or "__pycache__" in p.parts:
            continue
        yield p


def _hash_project(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(_iter_python_files(root)):
        rel = str(path.relative_to(root)).encode("utf-8")
        h.update(rel)
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def _copy_project(src: Path, dst: Path) -> int:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in _iter_python_files(src):
        rel = path.relative_to(src)
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, out)
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="evaluation/repo_level", help="Corpus root")
    parser.add_argument(
        "--project",
        action="append",
        required=True,
        help="Local project path to snapshot (repeatable)",
    )
    args = parser.parse_args()

    out_root = Path(args.output).resolve()
    corpus_dir = out_root / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    entries: List[ProjectEntry] = []
    for proj in args.project:
        src = Path(proj).resolve()
        if not src.exists() or not src.is_dir():
            raise SystemExit(f"Project path does not exist: {src}")
        name = src.name
        dst = corpus_dir / name
        count = _copy_project(src, dst)
        digest = _hash_project(dst)
        entries.append(
            ProjectEntry(
                name=name,
                path=str(dst.relative_to(out_root)),
                python_files=count,
                content_hash=digest,
            )
        )

    manifest = {"version": 1, "projects": [asdict(e) for e in sorted(entries, key=lambda x: x.name)]}
    manifest_path = out_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote manifest: {manifest_path}")
    print(f"Collected projects: {len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
