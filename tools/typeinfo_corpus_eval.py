#!/usr/bin/env python3
"""Run the typeinfo/mypy diagnostics harness over a whole corpus.

Each project is evaluated by ``tools/typeinfo_mypy_diff.py --diagnostics`` in
its own process so crashes, hangs, and mypy timeouts in one project cannot
affect the others.  Results are merged into one JSONL detail file and one JSON
summary, and a per-project table is printed.

Usage::

    .venv/bin/python tools/typeinfo_corpus_eval.py \
        --corpus ~/Work/tools/data/py/top100 --jobs 5 --max-modules 3 \
        --out /tmp/corpus_detail.jsonl --summary-out /tmp/corpus_summary.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS = REPO_ROOT / "tools" / "typeinfo_mypy_diff.py"
DEFAULT_CORPUS = Path.home() / "Work/tools/data/py/top100"


def evaluate(project: Path, args) -> dict:
    started = time.time()
    with tempfile.TemporaryDirectory(prefix=f"corpus-{project.name[:16]}-") as td:
        summary_path = Path(td) / "summary.json"
        detail_path = Path(td) / "detail.jsonl"
        command = [
            sys.executable,
            str(HARNESS),
            "--corpus",
            str(args.corpus),
            "--project",
            project.name,
            "--max-modules",
            str(args.max_modules),
            "--diagnostics",
            "--budget",
            str(args.budget),
            "--mypy-timeout",
            str(args.mypy_timeout),
            "--summary-out",
            str(summary_path),
            "--out",
            str(detail_path),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=args.project_timeout,
            )
        except subprocess.TimeoutExpired:
            return {
                "project": project.name,
                "error": "project timeout",
                "elapsed": round(time.time() - started, 1),
                "detail": "",
            }
        detail = detail_path.read_text() if detail_path.exists() else ""
        if not summary_path.exists():
            message = (completed.stderr or completed.stdout).strip().splitlines()[-3:]
            return {
                "project": project.name,
                "error": "harness failed",
                "stderr": "\n".join(message),
                "elapsed": round(time.time() - started, 1),
                "detail": detail,
            }
        data = json.loads(summary_path.read_text())[0]
        data["elapsed"] = round(time.time() - started, 1)
        data["detail"] = detail
        return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--max-modules", type=int, default=3)
    parser.add_argument("--budget", type=float, default=60.0)
    parser.add_argument("--mypy-timeout", type=float, default=45.0)
    parser.add_argument("--project-timeout", type=float, default=600.0)
    parser.add_argument("--include", default=None, help="only projects matching this regex")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--summary-out", default=None)
    args = parser.parse_args()
    args.corpus = Path(args.corpus).expanduser().resolve()

    projects = sorted(entry for entry in args.corpus.iterdir() if entry.is_dir())
    if args.include:
        import re

        pattern = re.compile(args.include)
        projects = [entry for entry in projects if pattern.search(entry.name)]
    if args.limit:
        projects = projects[: args.limit]

    summaries: list[dict] = []
    detail_lines: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {pool.submit(evaluate, project, args): project for project in projects}
        for future in as_completed(futures):
            project = futures[future]
            try:
                data = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                data = {"project": project.name, "error": f"{type(exc).__name__}: {exc}"}
            summaries.append(data)
            if data.get("detail"):
                detail_lines.append(data["detail"].rstrip("\n"))
            status = data.get("error") or (
                f"mypy={data.get('mypy_errors', 0)} "
                f"match={data.get('matched', 0)} "
                f"C3={len(data.get('c3_false_positive', []))} "
                f"C4={len(data.get('c4_false_negative', []))}"
            )
            print(f"[{len(summaries):3d}/{len(projects)}] {project.name:34s} {status}", flush=True)

    summaries.sort(key=lambda item: item.get("project", ""))
    totals = {
        "projects": len(summaries),
        "projects_with_error": sum(1 for item in summaries if item.get("error")),
        "modules": sum(item.get("modules_analysed", 0) for item in summaries),
        "crashes": sum(len(item.get("crashes", [])) for item in summaries),
        "mypy_errors": sum(item.get("mypy_errors", 0) for item in summaries),
        "pyflow_diagnostics": sum(item.get("pyflow_diagnostics", 0) for item in summaries),
        "matched": sum(item.get("matched", 0) for item in summaries),
        "c3": sum(len(item.get("c3_false_positive", [])) for item in summaries),
        "c4": sum(len(item.get("c4_false_negative", [])) for item in summaries),
    }

    print("\n== per project ==")
    print(
        f"{'project':34s} {'mods':>4s} {'mypy':>5s} {'pf':>4s} {'match':>5s} {'C3':>4s} {'C4':>5s}"
    )
    for item in summaries:
        if item.get("error"):
            print(f"{item['project']:34s} ERROR {item['error']}")
            continue
        print(
            f"{item['project']:34s} {item.get('modules_analysed', 0):4d} "
            f"{item.get('mypy_errors', 0):5d} {item.get('pyflow_diagnostics', 0):4d} "
            f"{item.get('matched', 0):5d} {len(item.get('c3_false_positive', [])):4d} "
            f"{len(item.get('c4_false_negative', [])):5d}"
        )
    print("\n== totals ==")
    print(json.dumps(totals, indent=2))

    if args.out:
        Path(args.out).write_text("\n".join(detail_lines) + "\n", encoding="utf-8")
    if args.summary_out:
        Path(args.summary_out).write_text(
            json.dumps({"totals": totals, "projects": summaries}, indent=2, default=str) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
