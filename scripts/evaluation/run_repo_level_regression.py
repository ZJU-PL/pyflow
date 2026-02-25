#!/usr/bin/env python3
"""Run frontend regression checks across a repo-level corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from pyflow.application.context import CompilerContext
from pyflow.frontend.programextractor import Extractor
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="evaluation/repo_level", help="Corpus root")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--baseline", help="Optional baseline JSON to compare against")
    args = parser.parse_args()

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
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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


if __name__ == "__main__":
    raise SystemExit(main())
