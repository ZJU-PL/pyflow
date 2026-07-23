#!/usr/bin/env python3
"""Repo-level regression: build a corpus of projects and run the frontend on it.

Subcommands:
  build   Copy project dirs into a corpus and write manifest.json.
  run     Run the frontend on each project in a corpus and write a report.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Dict, List

from pyflow.application.context import CompilerContext
from pyflow.frontend.extractor import Extractor
from pyflow.util.application.console import Console


def _load_sources(root: Path) -> Dict[str, str]:
    sources: Dict[str, str] = {}
    for p in root.rglob("*.py"):
        if ".git" in p.parts or "__pycache__" in p.parts:
            continue
        sources[str(p)] = p.read_text(encoding="utf-8")
    return sources


def _run_project(project_root: Path) -> Dict[str, object]:
    sources = _load_sources(project_root)
    compiler = CompilerContext(Console())
    extractor = Extractor(compiler, verbose=False, source_code=sources)
    program = extractor.extract_from_multiple_files(sources)
    live_code = len(getattr(program, "liveCode", []) or [])
    telemetry = getattr(program, "frontend_telemetry", {})
    return {
        "project": project_root.name,
        "files": len(sources),
        "live_code": live_code,
        "errors": extractor.errors,
        "failures": extractor.failures,
        "frontend_telemetry": telemetry,
    }


def _load_manifest(path: Path) -> Dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _compare_with_baseline(current: Dict[str, object], baseline: Dict[str, object]) -> List[str]:
    messages: List[str] = []
    cur_projects = {p["project"]: p for p in current.get("projects", [])}
    base_projects = {p["project"]: p for p in baseline.get("projects", [])}
    for name in sorted(set(cur_projects) | set(base_projects)):
        if name not in cur_projects:
            messages.append(f"missing project in current run: {name}")
            continue
        if name not in base_projects:
            messages.append(f"new project in current run: {name}")
            continue
        cur = cur_projects[name]
        base = base_projects[name]
        for metric in ("files", "live_code", "errors", "failures"):
            if cur.get(metric) != base.get(metric):
                messages.append(
                    f"{name}: {metric} changed {base.get(metric)} -> {cur.get(metric)}"
                )
    return messages


def _discover_python_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for path in root.rglob("*.py"):
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        files.append(path)
    return files


def _copy_project(src: Path, dst_root: Path) -> Dict[str, object]:
    if not src.is_dir():
        raise SystemExit(f"Project path is not a directory: {src}")
    name = src.name
    dst = dst_root / "corpus" / name
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    py_files = _discover_python_files(src)
    return {
        "name": name,
        "path": f"corpus/{name}",
        "python_files": len(py_files),
    }


def cmd_build(args: argparse.Namespace) -> int:
    """Build a corpus: copy project dirs and write manifest.json."""
    output_root = Path(args.output).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    projects: List[Dict[str, object]] = []
    for proj_str in args.project:
        projects.append(_copy_project(Path(proj_str).resolve(), output_root))
    manifest = {"version": 1, "projects": projects}
    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote manifest: {manifest_path}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run the frontend on each project in a corpus and write a report."""
    corpus_root = Path(args.corpus).resolve()
    manifest_path = corpus_root / "manifest.json"
    manifest = _load_manifest(manifest_path)
    projects = manifest.get("projects", [])

    run_projects = []
    for proj in projects:
        rel = proj["path"]
        project_root = corpus_root / rel
        run_projects.append(_run_project(project_root))

    report = {
        "corpus": str(corpus_root),
        "projects": sorted(run_projects, key=lambda p: p["project"]),
    }

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote report: {output_path}")

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        diffs = _compare_with_baseline(report, baseline)
        if diffs:
            print("Baseline differences:")
            for d in diffs:
                print(f"- {d}")
            return 2
        print("No baseline differences.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_p = subparsers.add_parser("build", help="Build a corpus from project dirs")
    build_p.add_argument("--output", required=True, help="Output corpus directory")
    build_p.add_argument(
        "--project",
        action="append",
        required=True,
        help="Project directory to include (repeat for multiple)",
    )
    build_p.set_defaults(func=cmd_build)

    run_p = subparsers.add_parser("run", help="Run frontend on corpus and write report")
    run_p.add_argument(
        "--corpus",
        default="evaluation/repo_level",
        help="Corpus root (default: evaluation/repo_level)",
    )
    run_p.add_argument("--output", required=True, help="Output report JSON path")
    run_p.add_argument("--baseline", help="Optional baseline report to compare against")
    run_p.set_defaults(func=cmd_run)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
