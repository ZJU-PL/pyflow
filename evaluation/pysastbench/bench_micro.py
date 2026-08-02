#!/usr/bin/env python3
"""Evaluate PyFlow security engines on the PySASTBench synthetic pairs.

This runner intentionally treats one source file as one classification item:
``*_vul.py`` files are positives and their ``*_fix.py`` counterparts are
negatives.  A positive is counted only when a finding has the expected CWE and
lands in the ground-truth function from ``SyntheticDataset.csv``.

The default CWE comparison is semantic rather than textual: CWE-77 accepts
CWE-78 and CWE-94 accepts CWE-95 because the benchmark metadata uses the
broader parent category for those families.  Use ``--strict-cwe`` for exact
numeric matching.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

ENGINES = ("ast-scanner", "ast-dataflow", "cpg", "ifds")
CWE_ALIASES = {"77": frozenset({"77", "78"}), "94": frozenset({"94", "95"})}


def _parse_args() -> argparse.Namespace:
    script = Path(__file__).resolve()
    repo_default = script.parents[2]
    dataset_default = script.parent / "SyntheticDataset"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=repo_default)
    parser.add_argument("--dataset", type=Path, default=dataset_default)
    parser.add_argument("--metadata", type=Path, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/pyflow-pysastbench-results"),
        help="Directory for JSONL records and summaries.",
    )
    parser.add_argument(
        "--engines",
        default=",".join(ENGINES),
        help="Comma-separated engines to run.",
    )
    parser.add_argument("--workers", type=int, default=int(os.environ.get("PYFLOW_EVAL_WORKERS", "8")))
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("PYFLOW_EVAL_TIMEOUT", "45")))
    parser.add_argument(
        "--pyflow",
        type=Path,
        default=None,
        help="PyFlow executable; defaults to <repo-root>/.venv/bin/pyflow.",
    )
    parser.add_argument(
        "--strict-cwe",
        action="store_true",
        help="Require exact CWE numbers instead of the benchmark's semantic aliases.",
    )
    return parser.parse_args()


def _expected_rows(metadata: Path) -> dict[str, dict[str, str]]:
    with metadata.open(encoding="utf-8-sig", newline="") as stream:
        return {row["TestCase"]: row for row in csv.DictReader(stream)}


def _function_scopes(path: Path) -> list[tuple[int, int, str]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    scopes: list[tuple[int, int, str]] = []

    def visit(node: ast.AST, parents: list[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = ".".join([*parents, node.name])
            scopes.append((node.lineno, getattr(node, "end_lineno", node.lineno), name))
            parents = [*parents, node.name]
        elif isinstance(node, ast.ClassDef):
            parents = [*parents, node.name]
        for child in ast.iter_child_nodes(node):
            visit(child, parents)

    visit(tree, [])
    return scopes


def _enclosing_function(path: Path, line: int) -> str | None:
    matches = [
        (end - start, name)
        for start, end, name in _function_scopes(path)
        if start <= line <= end
    ]
    return min(matches)[1] if matches else None


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


def _run_one(engine: str, path: Path, repo_root: Path, pyflow: Path, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    command = [str(pyflow), "security", str(path), "--engine", engine]
    if engine != "ast-scanner":
        command.append("--framework")
    command += ["--format", "json", "--exit-code-policy", "report"]
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        payload, parse_error = _parse_json(completed.stdout)
        return {
            "engine": engine,
            "path": str(path),
            "rc": completed.returncode,
            "elapsed_s": time.perf_counter() - started,
            "payload": payload,
            "parse_error": parse_error,
            "stderr": completed.stderr[-12000:],
            "interrupted": False,
        }
    except subprocess.TimeoutExpired as error:
        stderr = error.stderr or ""
        return {
            "engine": engine,
            "path": str(path),
            "rc": 124,
            "elapsed_s": time.perf_counter() - started,
            "payload": None,
            "parse_error": "timeout",
            "stderr": f"TIMEOUT after {timeout}s\n{stderr}"[-12000:],
            "interrupted": False,
        }
    except OSError as error:
        return {
            "engine": engine,
            "path": str(path),
            "rc": 127,
            "elapsed_s": time.perf_counter() - started,
            "payload": None,
            "parse_error": f"{type(error).__name__}: {error}",
            "stderr": str(error),
            "interrupted": False,
        }


def _findings(engine: str, payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    key = "results" if engine == "ast-scanner" else "findings"
    values = payload.get(key, [])
    return [value for value in values if isinstance(value, dict)]


def _cwe_number(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("id")
    if value is None:
        return None
    text = str(value).upper().replace("CWE-", "")
    return text if text.isdigit() else None


def _finding_cwe(finding: dict[str, Any]) -> str | None:
    value = finding.get("cwe") or finding.get("issue_cwe")
    if value is None and isinstance(finding.get("rule"), dict):
        value = finding["rule"].get("cwe")
    return _cwe_number(value)


def _accepted_cwes(expected: str, strict: bool) -> frozenset[str]:
    if strict:
        return frozenset({expected})
    return CWE_ALIASES.get(expected, frozenset({expected}))


def _is_relevant(engine: str, path: Path, row: dict[str, str], payload: Any, strict: bool) -> tuple[bool, list[dict[str, Any]]]:
    accepted = _accepted_cwes(str(row["CWE Type"]), strict)
    target = row["Vul Position"]
    matches: list[dict[str, Any]] = []
    for finding in _findings(engine, payload):
        if _finding_cwe(finding) not in accepted:
            continue
        if engine == "ast-scanner":
            line = finding.get("line_number") or finding.get("line") or 0
            function = _enclosing_function(path, int(line)) if line else None
            if function is None or function == target or function.endswith("." + target):
                matches.append(finding)
        elif engine == "ast-dataflow":
            function = str(finding.get("function") or "")
            if not function or function == target or function.endswith("." + target):
                matches.append(finding)
        elif engine == "ifds":
            procedure = str(finding.get("procedure") or "")
            if not procedure or procedure == target or procedure.endswith("." + target):
                matches.append(finding)
        else:
            matches.append(finding)
    return bool(matches), matches


def _record(engine: str, path: Path, row: dict[str, str], result: dict[str, Any], strict: bool) -> dict[str, Any]:
    case = path.stem.rsplit("_", 1)[0]
    is_vulnerable = path.stem.endswith("_vul")
    detected, matched = _is_relevant(engine, path, row, result["payload"], strict)
    payload = result["payload"]
    return {
        "engine": engine,
        "case": case,
        "file": path.name,
        "cwe": str(row["CWE Type"]),
        "target": row["Vul Position"],
        "is_vul": is_vulnerable,
        "detected": detected,
        "match_count": len(matched),
        "rc": result["rc"],
        "elapsed_s": result["elapsed_s"],
        "status": payload.get("status") if isinstance(payload, dict) else None,
        "finding_count": len(_findings(engine, payload)),
        "parse_error": result["parse_error"],
        "stderr": result["stderr"],
        "interrupted": result.get("interrupted", False),
    }


def _summary(records: list[dict[str, Any]], engines: tuple[str, ...]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for engine in engines:
        attempted = [record for record in records if record["engine"] == engine]
        subset = [record for record in attempted if not record.get("interrupted", False)]
        tp = sum(record["is_vul"] and record["detected"] for record in subset)
        fp = sum((not record["is_vul"]) and record["detected"] for record in subset)
        fn = sum(record["is_vul"] and (not record["detected"]) for record in subset)
        tn = sum((not record["is_vul"]) and (not record["detected"]) for record in subset)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        accuracy = (tp + tn) / len(subset) if subset else 0.0
        by_cwe: dict[str, dict[str, int]] = {}
        for record in subset:
            stats = by_cwe.setdefault(record["cwe"], {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            key = "tp" if record["is_vul"] and record["detected"] else (
                "fn" if record["is_vul"] else ("fp" if record["detected"] else "tn")
            )
            stats[key] += 1
        output[engine] = {
            "n": len(subset),
            "attempted": len(attempted),
            "interrupted": sum(record.get("interrupted", False) for record in attempted),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "timeouts_or_parse_errors": sum(record["parse_error"] is not None for record in subset),
            "nonzero_rc": sum(record["rc"] != 0 for record in subset),
            "status_counts": {
                str(status): sum(record["status"] == status for record in subset)
                for status in sorted({record["status"] for record in subset})
            },
            "mean_s": sum(record["elapsed_s"] for record in subset) / len(subset),
            "total_s": sum(record["elapsed_s"] for record in subset),
            "by_cwe": by_cwe,
        }
    return output


def _metrics(
    stats: dict[str, Any],
) -> tuple[int, int, int, int, int, float, float, float, float]:
    """Return confusion-matrix counts and derived metrics for display."""
    tp = int(stats.get("tp", 0))
    fp = int(stats.get("fp", 0))
    tn = int(stats.get("tn", 0))
    fn = int(stats.get("fn", 0))
    n = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / n if n else 0.0
    return n, tp, fp, tn, fn, precision, recall, f1, accuracy


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    def render(row: list[str]) -> str:
        return " | ".join(value.ljust(widths[index]) for index, value in enumerate(row))

    divider = "-+-".join("-" * width for width in widths)
    return "\n".join([render(headers), divider, *(render(row) for row in rows)])


def _print_summary(summary: dict[str, Any], engines: tuple[str, ...]) -> None:
    overall_headers = [
        "Engine",
        "Done",
        "Tried",
        "TP",
        "FP",
        "TN",
        "FN",
        "Precision",
        "Recall",
        "F1",
        "Accuracy",
        "Mean(s)",
        "Total(s)",
        "Errors",
    ]
    overall_rows: list[list[str]] = []
    for engine in engines:
        stats = summary[engine]
        _, tp, fp, tn, fn, precision, recall, f1, accuracy = _metrics(stats)
        overall_rows.append(
            [
                engine,
                str(stats.get("n", 0)),
                str(stats.get("attempted", 0)),
                str(tp),
                str(fp),
                str(tn),
                str(fn),
                f"{precision:.3f}",
                f"{recall:.3f}",
                f"{f1:.3f}",
                f"{accuracy:.3f}",
                f"{float(stats.get('mean_s', 0.0)):.2f}",
                f"{float(stats.get('total_s', 0.0)):.2f}",
                str(stats.get("timeouts_or_parse_errors", 0)),
            ]
        )

    cwe_headers = [
        "CWE",
        "Engine",
        "N",
        "TP",
        "FP",
        "TN",
        "FN",
        "Precision",
        "Recall",
        "F1",
        "Accuracy",
    ]
    cwe_rows: list[list[str]] = []
    cwes = sorted(
        {cwe for engine in engines for cwe in summary[engine].get("by_cwe", {})},
        key=int,
    )
    for cwe in cwes:
        for engine in engines:
            stats = summary[engine].get("by_cwe", {}).get(cwe)
            if stats is None:
                continue
            n, tp, fp, tn, fn, precision, recall, f1, accuracy = _metrics(stats)
            cwe_rows.append(
                [
                    f"CWE-{cwe}",
                    engine,
                    str(n),
                    str(tp),
                    str(fp),
                    str(tn),
                    str(fn),
                    f"{precision:.3f}",
                    f"{recall:.3f}",
                    f"{f1:.3f}",
                    f"{accuracy:.3f}",
                ]
            )

    print("\nPySASTBench microbenchmark summary", flush=True)
    print("\nOverall", flush=True)
    print(_table(overall_headers, overall_rows), flush=True)
    print("\nBy CWE", flush=True)
    print(_table(cwe_headers, cwe_rows), flush=True)


def main() -> int:
    args = _parse_args()
    repo_root = args.repo_root.expanduser().resolve()
    dataset = args.dataset.expanduser().resolve()
    metadata = (args.metadata or dataset.parent / "SyntheticDataset.csv").expanduser().resolve()
    pyflow = (args.pyflow or repo_root / ".venv" / "bin" / "pyflow").expanduser().resolve()
    engines = tuple(value.strip() for value in args.engines.split(",") if value.strip())
    unknown = sorted(set(engines) - set(ENGINES))
    if unknown:
        raise SystemExit(f"Unknown engine(s): {', '.join(unknown)}")
    if not pyflow.exists():
        raise SystemExit(f"PyFlow executable not found: {pyflow}")

    rows = _expected_rows(metadata)
    files = sorted(dataset.glob("*/*.py"))
    if not files:
        raise SystemExit(f"No benchmark files found below {dataset}")
    jobs = [(engine, path) for engine in engines for path in files]
    args.output.expanduser().mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    raw_path = args.output / "raw_results.jsonl"
    print(f"jobs={len(jobs)} workers={args.workers} timeout={args.timeout}s", flush=True)
    with raw_path.open("w", encoding="utf-8") as raw:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = {
                pool.submit(_run_one, engine, path, repo_root, pyflow, args.timeout): (engine, path)
                for engine, path in jobs
            }
            for index, future in enumerate(as_completed(futures), 1):
                engine, path = futures[future]
                try:
                    result = future.result()
                except Exception as error:
                    result = {
                        "engine": engine,
                        "path": str(path),
                        "rc": 125,
                        "elapsed_s": 0.0,
                        "payload": None,
                        "parse_error": f"{type(error).__name__}: {error}",
                        "stderr": str(error),
                        "interrupted": False,
                    }
                case = path.stem.rsplit("_", 1)[0]
                if case not in rows:
                    raise SystemExit(f"Missing metadata row for {case}")
                record = _record(engine, path, rows[case], result, args.strict_cwe)
                records.append(record)
                raw.write(json.dumps({"record": record, "payload": result["payload"]}, ensure_ascii=False) + "\n")
                raw.flush()
                if index % 40 == 0 or index == len(jobs):
                    print(f"completed={index}/{len(jobs)}", flush=True)

    summary = _summary(records, engines)
    summary["interrupted"] = False
    summary["attempted_jobs"] = len(jobs)
    summary["completed_jobs"] = len(records)

    (args.output / "records.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    _print_summary(summary, engines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
