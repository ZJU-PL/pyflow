#!/usr/bin/env python3
"""Extract PySASTBench real-world archives for repeated project analyses."""

from __future__ import annotations

import argparse
import os
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "pysastbench_root",
        type=Path,
        help="PySASTBench root containing RealworldDataset and RealworldDataset.csv.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.environ.get("PYFLOW_EXTRACT_WORKERS", "1")),
    )
    return parser.parse_args()


def _extract(archive: Path, source: Path, output: Path) -> Path:
    target = output / archive.parent.relative_to(source) / archive.stem
    marker = target / ".pyflow-extracted"
    if marker.is_file():
        return target
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()
    with zipfile.ZipFile(archive) as stream:
        for member in stream.infolist():
            (target / member.filename).resolve().relative_to(root)
        stream.extractall(target)
    marker.touch()
    return target


def main() -> int:
    args = _parse_args()
    root = args.pysastbench_root.expanduser().resolve()
    source = root / "RealworldDataset"
    output = root / "RealworldDataset-extracted"
    archives = sorted(source.glob("*/*.zip"))
    if not archives:
        raise SystemExit(f"No archives found below {source}")
    output.mkdir(parents=True, exist_ok=True)
    print(f"archives={len(archives)} workers={args.workers} output={output}", flush=True)
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {
            pool.submit(_extract, archive, source, output): archive
            for archive in archives
        }
        for index, future in enumerate(as_completed(futures), 1):
            future.result()
            if index % 10 == 0 or index == len(archives):
                print(f"completed={index}/{len(archives)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
