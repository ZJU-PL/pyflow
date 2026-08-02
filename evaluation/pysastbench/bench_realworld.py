#!/usr/bin/env python3
"""Run PyFlow security engines over extracted PySASTBench projects.

Each ``<CVE>/<project>-vul`` or ``<CVE>/<project>-fix`` directory is one
project-level evaluation item.  Extraction is deliberately a separate step;
this runner only analyzes already extracted projects.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import os
import re
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Sequence


ENGINES = ("ast-scanner", "ast-dataflow", "cpg", "ifds")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_ACTIVE_LOCK = threading.Lock()
_ACTIVE: dict[int, subprocess.Popen[str]] = {}
_CANCEL_REQUESTED = threading.Event()


def _signal_group(process: subprocess.Popen[str], sig: signal.Signals) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, sig)
        else:  # pragma: no cover - Windows fallback
            process.kill()
    except ProcessLookupError:
        pass


def _terminate(process: subprocess.Popen[str]) -> None:
    _signal_group(process, signal.SIGTERM)
    if process.poll() is None:
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
    # The parent can exit while descendants remain in the process group.
    _signal_group(process, signal.SIGKILL)
    try:
        process.communicate(timeout=2.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()


def terminate_active_processes() -> None:
    _CANCEL_REQUESTED.set()
    with _ACTIVE_LOCK:
        processes = list(_ACTIVE.values())
    for process in processes:
        _signal_group(process, signal.SIGKILL)


def reset_cancellation() -> None:
    _CANCEL_REQUESTED.clear()


def run_isolated(
    command: Sequence[str], *, cwd: str, timeout: float
) -> tuple[int, str, str, bool, bool]:
    if _CANCEL_REQUESTED.is_set():
        return 130, "", "", False, True
    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=os.name == "posix",
    )
    with _ACTIVE_LOCK:
        _ACTIVE[process.pid] = process
    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return process.returncode, stdout, stderr, False, _CANCEL_REQUESTED.is_set()
        except subprocess.TimeoutExpired:
            _terminate(process)
            stdout, stderr = process.communicate()
            return 124, stdout, stderr, True, False
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE.pop(process.pid, None)


def _parse_args() -> argparse.Namespace:
    script = Path(__file__).resolve()
    repo_default = script.parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=repo_default)
    parser.add_argument(
        "pysastbench_root",
        type=Path,
        help="PySASTBench root containing RealworldDataset-extracted and metadata.",
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=Path("/tmp/pyflow-pysastbench-realworld-results"),
        help="Result directory (default: /tmp/pyflow-pysastbench-realworld-results).",
    )
    parser.add_argument(
        "--engines",
        action="append",
        default=None,
        metavar="ENGINE[,ENGINE...]",
        help=(
            "Engine(s) to run; repeat the option or separate engines with commas "
            f"(choices: {', '.join(ENGINES)}; default: all)."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.environ.get("PYFLOW_EVAL_WORKERS", "4")),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("PYFLOW_EVAL_TIMEOUT", "60")),
    )
    parser.add_argument("--pyflow", type=Path, default=None)
    return parser.parse_args()


def _selected_engines(values: list[str] | None) -> tuple[str, ...]:
    """Normalize repeated and comma-separated engine selections."""
    if not values:
        return ENGINES
    engines = tuple(
        engine.strip()
        for value in values
        for engine in value.split(",")
        if engine.strip()
    )
    if not engines:
        raise SystemExit("At least one engine must be selected")
    return engines


def _cve_id(value: str) -> str | None:
    match = _CVE_RE.search(value)
    return match.group(0).upper() if match else None


def _load_metadata(path: Path) -> dict[str, dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = csv.DictReader(stream)
        output: dict[str, dict[str, str]] = {}
        for row in rows:
            cve = _cve_id(row.get("CVE", ""))
            if cve:
                output[cve] = row
        return output


def _parse_json(stdout: str) -> tuple[Any, str | None]:
    raw = stdout.strip()
    if not raw:
        return None, "empty stdout"
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as original:
        decoder = json.JSONDecoder()
        for index, char in enumerate(raw):
            if char != "{":
                continue
            try:
                payload, end = decoder.raw_decode(raw[index:])
            except json.JSONDecodeError:
                continue
            if not raw[index + end :].strip():
                return payload, None
        return None, f"{type(original).__name__}: {original}"


def _target_file(row: dict[str, str], project_root: Path) -> Path | None:
    position = row.get("vul position", "")
    first = position.split(";", 1)[0].strip()
    relative = first.split(":", 1)[0].strip()
    if not relative:
        return None
    candidate = project_root / relative
    return candidate if candidate.is_file() else None


def _finding_count(engine: str, payload: Any) -> int:
    if not isinstance(payload, dict):
        return 0
    key = "results" if engine == "ast-scanner" else "findings"
    values = payload.get(key, [])
    return len(values) if isinstance(values, list) else 0


def _cwe_numbers(value: Any) -> set[int]:
    if isinstance(value, dict):
        value = value.get("id")
    if value is None:
        return set()
    return {int(number) for number in re.findall(r"[0-9]+", str(value))}


def _target_specs(row: dict[str, str]) -> list[tuple[str, str]]:
    specs: list[tuple[str, str]] = []
    for item in row.get("vul position", "").split(";"):
        path, _, function = item.strip().partition(":")
        if path:
            specs.append((path.replace("\\", "/"), function.strip()))
    return specs


def _function_ranges(path: Path) -> list[tuple[str, int, int]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return []
    ranges: list[tuple[str, int, int]] = []

    def visit(node: ast.AST, parents: list[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = ".".join([*parents, node.name])
            ranges.append((name, node.lineno, getattr(node, "end_lineno", node.lineno)))
            parents = [*parents, node.name]
        elif isinstance(node, ast.ClassDef):
            parents = [*parents, node.name]
        for child in ast.iter_child_nodes(node):
            visit(child, parents)

    visit(tree, [])
    return ranges


def _function_matches(actual: str, expected: str) -> bool:
    if not expected:
        return True
    return (
        actual == expected
        or actual.endswith("." + expected)
        or actual.split(".")[-1] == expected.split(".")[-1]
    )


def _finding_location(engine: str, finding: dict[str, Any]) -> tuple[str, str, int, Any]:
    if engine == "ast-scanner":
        return (
            str(finding.get("filename", "")),
            "",
            int(finding.get("line_number") or 0),
            finding.get("issue_cwe"),
        )
    if engine == "ast-dataflow":
        return (
            str(finding.get("filename", "")),
            str(finding.get("function", "")),
            int(finding.get("sink_line") or 0),
            finding.get("cwe"),
        )
    location = finding.get("primary_location") or finding.get("location") or {}
    return (
        str(location.get("uri") or finding.get("filename", "")),
        str(finding.get("procedure") or finding.get("function", "")),
        int(location.get("start_line") or finding.get("line") or 0),
        finding.get("cwe"),
    )


def _detected(record: dict[str, Any], metadata: dict[str, dict[str, str]]) -> bool:
    """Require a finding at the benchmark target and with a listed CWE."""
    row = metadata.get(str(record["cve"]).upper())
    payload = record.get("payload")
    if not row or not isinstance(payload, dict):
        return False
    engine = str(record["engine"])
    key = "results" if engine == "ast-scanner" else "findings"
    findings = payload.get(key, [])
    if not isinstance(findings, list):
        return False
    project_root = _project_root(Path(record["project"]))
    expected_cwes = _cwe_numbers(row.get("CWE Type", ""))
    targets = [
        (target_path, target_function, _function_ranges(project_root / target_path))
        for target_path, target_function in _target_specs(row)
        if (project_root / target_path).is_file()
    ]
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        path, function, line, cwe = _finding_location(engine, finding)
        normalized_path = path.replace("\\", "/")
        finding_cwes = _cwe_numbers(cwe)
        if not finding_cwes & expected_cwes:
            continue
        for target_path, target_function, ranges in targets:
            if not (
                normalized_path.endswith("/" + target_path)
                or normalized_path == target_path
                or normalized_path.endswith(target_path)
            ):
                continue
            if engine == "ast-scanner":
                if any(
                    name == target_function
                    and start <= line <= end
                    for name, start, end in ranges
                ):
                    return True
            elif _function_matches(function, target_function):
                return True
    return False


def _record(engine: str, project: Path, **fields: Any) -> dict[str, Any]:
    record = {
        "engine": engine,
        "project": str(project),
        "cve": project.parent.name.upper(),
        "variant": "vul" if project.name.endswith("-vul") else "fix",
        "rc": 0,
        "elapsed_s": 0.0,
        "status": None,
        "finding_count": 0,
        "parse_error": None,
        "stderr": "",
        "payload": None,
        "interrupted": False,
    }
    record.update(fields)
    return record


def _run_engine(
    engine: str,
    project: Path,
    project_root: Path,
    row: dict[str, str],
    repo_root: Path,
    pyflow: Path,
    timeout: float,
) -> dict[str, Any]:
    command = [
        str(pyflow),
        "security",
        str(project_root),
        "--engine",
        engine,
        "--recursive",
        "--format",
        "json",
        "--exit-code-policy",
        "report",
    ]
    if engine != "ast-scanner":
        # An empty --framework requests registry auto-detection for AST/IFDS.
        command.append("--framework")
    if engine == "ifds":
        target = _target_file(row, project_root)
        if target is not None:
            command.extend(["--entry", str(target.relative_to(project_root))])

    started = time.perf_counter()
    try:
        returncode, stdout, stderr, timed_out, cancelled = run_isolated(
            command, cwd=str(repo_root), timeout=timeout
        )
        if cancelled:
            return _record(
                engine,
                project,
                rc=130,
                elapsed_s=time.perf_counter() - started,
                status="interrupted",
                parse_error="interrupted",
                stderr="INTERRUPTED by user",
                interrupted=True,
            )
        if timed_out:
            return _record(
                engine,
                project,
                rc=124,
                status="timeout",
                parse_error="timeout",
                stderr=f"TIMEOUT after {timeout}s\n{stderr}"[-12000:],
                elapsed_s=time.perf_counter() - started,
            )
        payload, parse_error = _parse_json(stdout)
        return _record(
            engine,
            project,
            rc=returncode,
            elapsed_s=time.perf_counter() - started,
            status=payload.get("status") if isinstance(payload, dict) else None,
            parse_error=parse_error,
            stderr=stderr[-12000:],
            finding_count=_finding_count(engine, payload),
            payload=payload,
        )
    except OSError as error:
        return _record(
            engine,
            project,
            rc=127,
            status="failed",
            parse_error=f"{type(error).__name__}: {error}",
            stderr=str(error),
            elapsed_s=time.perf_counter() - started,
        )


def _project_root(project: Path) -> Path:
    """Flatten the common single top-level directory from an archive."""
    children = [
        path
        for path in project.iterdir()
        if path.name not in {".DS_Store", ".pyflow-extracted"}
    ]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return project


def _run_project(
    project: Path,
    metadata: dict[str, dict[str, str]],
    engines: tuple[str, ...],
    repo_root: Path,
    pyflow: Path,
    timeout: float,
) -> list[dict[str, Any]]:
    cve = project.parent.name.upper()
    row = metadata.get(cve, {})
    if not row:
        return [
            _record(
                engine,
                project,
                rc=2,
                status="missing-metadata",
                parse_error="missing metadata row",
            )
            for engine in engines
        ]
    project_root = _project_root(project)
    results: list[dict[str, Any]] = []
    for index, engine in enumerate(engines):
        result = _run_engine(
            engine,
            project,
            project_root,
            row,
            repo_root,
            pyflow,
            timeout,
        )
        results.append(result)
        if result.get("interrupted"):
            results.extend(
                _record(
                    remaining,
                    project,
                    rc=130,
                    status="interrupted",
                    parse_error="interrupted",
                    stderr="INTERRUPTED by user",
                    interrupted=True,
                )
                for remaining in engines[index + 1 :]
            )
            break
    return results


def _summary(records: list[dict[str, Any]], engines: tuple[str, ...]) -> dict[str, Any]:
    summary: dict[str, Any] = {"projects": len({r["project"] for r in records})}
    for engine in engines:
        attempted = [record for record in records if record["engine"] == engine]
        subset = [record for record in attempted if not record.get("interrupted", False)]
        tp = sum(record["variant"] == "vul" and record["detected"] for record in subset)
        fp = sum(record["variant"] == "fix" and record["detected"] for record in subset)
        fn = sum(record["variant"] == "vul" and not record["detected"] for record in subset)
        tn = sum(record["variant"] == "fix" and not record["detected"] for record in subset)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        accuracy = (tp + tn) / len(subset) if subset else 0.0
        summary[engine] = {
            "projects": len(subset),
            "attempted": len(attempted),
            "interrupted": sum(record.get("interrupted", False) for record in attempted),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "timeouts": sum(record["parse_error"] == "timeout" for record in subset),
            "parse_errors": sum(record["parse_error"] not in (None, "timeout") for record in subset),
            "nonzero_rc": sum(record["rc"] != 0 for record in subset),
            "status_counts": {
                str(status): sum(record["status"] == status for record in subset)
                for status in sorted(
                    {record["status"] for record in subset}, key=lambda value: str(value)
                )
            },
            "projects_with_findings": sum(record["finding_count"] > 0 for record in subset),
            "total_findings": sum(record["finding_count"] for record in subset),
            "mean_s": sum(record["elapsed_s"] for record in subset) / len(subset)
            if subset
            else 0.0,
            "total_s": sum(record["elapsed_s"] for record in subset),
        }
    return summary


def _failed_project(project: Path, engines: tuple[str, ...], error: Exception) -> list[dict[str, Any]]:
    message = f"{type(error).__name__}: {error}"
    return [
        _record(
            engine,
            project,
            rc=125,
            status="failed",
            parse_error=message,
            stderr=str(error),
        )
        for engine in engines
    ]


def _consume(
    future: Any,
    futures: dict[Any, Path],
    metadata: dict[str, dict[str, str]],
    engines: tuple[str, ...],
) -> list[dict[str, Any]] | None:
    if future.cancelled():
        return None
    project = futures[future]
    try:
        project_records = future.result()
    except Exception as error:
        project_records = _failed_project(project, engines, error)
    for record in project_records:
        record["detected"] = _detected(record, metadata)
    return project_records


def _store_future(
    future: Any,
    futures: dict[Any, Path],
    processed: set[Any],
    records: list[dict[str, Any]],
    raw: Any,
    metadata: dict[str, dict[str, str]],
    engines: tuple[str, ...],
) -> bool:
    if future in processed:
        return False
    project_records = _consume(future, futures, metadata, engines)
    if project_records is None:
        return False
    records.extend(project_records)
    raw.writelines(json.dumps(record, ensure_ascii=False) + "\n" for record in project_records)
    raw.flush()
    processed.add(future)
    return True


def main() -> int:
    args = _parse_args()
    reset_cancellation()
    repo_root = args.repo_root.expanduser().resolve()
    root = args.pysastbench_root.expanduser().resolve()
    dataset = root / "RealworldDataset-extracted"
    metadata_path = root / "RealworldDataset.csv"
    pyflow = (args.pyflow or repo_root / ".venv" / "bin" / "pyflow").expanduser().resolve()
    engines = _selected_engines(args.engines)
    unknown = sorted(set(engines) - set(ENGINES))
    if unknown:
        raise SystemExit(f"Unknown engine(s): {', '.join(unknown)}")
    if not pyflow.exists():
        raise SystemExit(f"PyFlow executable not found: {pyflow}")
    if not dataset.is_dir():
        raise SystemExit(f"Dataset directory not found: {dataset}")

    metadata = _load_metadata(metadata_path)
    projects = sorted(
        project
        for cve_dir in dataset.iterdir()
        if cve_dir.is_dir()
        for project in cve_dir.iterdir()
        if project.is_dir()
    )
    if not projects:
        raise SystemExit(f"No pre-extracted project directories found below {dataset}")
    args.results.expanduser().mkdir(parents=True, exist_ok=True)
    raw_path = args.results / "raw_results.jsonl"
    records: list[dict[str, Any]] = []
    print(
        f"projects={len(projects)} engines={','.join(engines)} "
        f"workers={args.workers} timeout={args.timeout}s",
        flush=True,
    )
    pool = ThreadPoolExecutor(max_workers=max(1, args.workers))
    futures = {
        pool.submit(
            _run_project,
            project,
            metadata,
            engines,
            repo_root,
            pyflow,
            args.timeout,
        ): project
        for project in projects
    }
    processed: set[Any] = set()
    interrupted = False
    with raw_path.open("w", encoding="utf-8") as raw:
        try:
            for future in as_completed(futures):
                if _store_future(future, futures, processed, records, raw, metadata, engines) and (
                    len(processed) % 10 == 0 or len(processed) == len(projects)
                ):
                    print(f"completed={len(processed)}/{len(projects)}", flush=True)
            pool.shutdown(wait=True)
        except KeyboardInterrupt:
            interrupted = True
            print("Interrupted; terminating active engine process groups...", flush=True)
            terminate_active_processes()
            for future in futures:
                future.cancel()
            pool.shutdown(wait=True, cancel_futures=True)
            for future in futures:
                if future.done() and not future.cancelled():
                    _store_future(future, futures, processed, records, raw, metadata, engines)

    summary = _summary(records, engines)
    summary["interrupted"] = interrupted
    project_records: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        project_records.setdefault(record["project"], []).append(record)
    summary["attempted_projects"] = len(project_records)
    summary["completed_projects"] = sum(
        all(not record.get("interrupted", False) for record in grouped)
        for grouped in project_records.values()
    )
    (args.results / "records.json").write_text(
        json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.results / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2), flush=True)
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
