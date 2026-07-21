#!/usr/bin/env python3
"""Repo-level call-graph benchmark: run engines on multi-file projects.

Compares PyFlow's constraint engine and the external PyCG engine against
ground-truth callgraph.json files in each project directory.

External baselines (pyan3, code2flow, Scalpel, etc.) can provide pre-computed
results via the common interchange format.  See runners/ for thin wrappers.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from pyflow.analysis.callgraph.constraint_based import extract_call_graph_constraint
from pyflow.analysis.callgraph.pycg_based import PYCG_AVAILABLE, extract_call_graph_pycg

Edge = Tuple[str, str]


@dataclass(frozen=True)
class Project:
    name: str
    root: Path
    manifest_entry: Dict[str, object]
    ground_truth: Dict[str, List[str]]
    entry_file: Path


@dataclass(frozen=True)
class EngineResult:
    engine: str
    project: str
    runtime_ms: float
    precision: float
    recall: float
    tp: int
    fp: int
    fn: int
    error: Optional[str] = None

def _adjacency_to_edges(graph: Dict[str, Iterable[str]]) -> Set[Edge]:
    edges: Set[Edge] = set()
    for caller, callees in graph.items():
        for callee in callees:
            edges.add((caller, callee))
    return edges


def _load_callgraph_json(path: Path) -> Dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected mapping in {path}")
    return payload

def _write_callgraph_json(graph: Dict[str, Iterable[str]], path: Path) -> None:
    serialized = {
        caller: sorted(callees) for caller, callees in graph.items()
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(serialized, indent=2), encoding="utf-8")

def _discover_projects(corpus_root: Path) -> List[Project]:
    manifest_path = corpus_root / "manifest.json"
    if manifest_path.exists():
        return _discover_from_manifest(corpus_root, manifest_path)
    return _discover_by_scan(corpus_root)

def _discover_from_manifest(corpus_root: Path, manifest_path: Path) -> List[Project]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    projects: List[Project] = []
    for entry in manifest.get("projects", []):
        name = entry["name"]
        root = corpus_root / entry["path"]
        if not root.is_dir():
            continue
        project = _make_project(name, root, entry)
        if project:
            projects.append(project)
    return projects

def _discover_by_scan(corpus_root: Path) -> List[Project]:
    projects: List[Project] = []
    for child in sorted(corpus_root.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith(".") or child.name == "__pycache__":
            continue
        project = _make_project(child.name, child, {"name": child.name, "path": str(child.relative_to(corpus_root))})
        if project:
            projects.append(project)
    return projects

def _make_project(
    name: str,
    root: Path,
    manifest_entry: Dict[str, object],
) -> Optional[Project]:
    gt_path = root / "callgraph.json"
    if not gt_path.exists():
        return None
    try:
        ground_truth = _load_callgraph_json(gt_path)
    except Exception:
        return None
    entry_file = _resolve_entry_file(root, gt_path, manifest_entry)
    if not entry_file:
        return None
    return Project(
        name=name,
        root=root,
        manifest_entry=manifest_entry,
        ground_truth=ground_truth,
        entry_file=entry_file,
    )

def _resolve_entry_file(
    root: Path,
    gt_path: Path,
    manifest_entry: Optional[Dict[str, object]] = None,
) -> Optional[Path]:
    try:
        raw = json.loads(gt_path.read_text(encoding="utf-8"))
    except Exception:
        raw = {}
    entry_name = raw.get("_entry_point", "main.py")
    candidate = root / str(entry_name)
    if candidate.is_file():
        return candidate
    if manifest_entry:
        mf_entry = manifest_entry.get("_entry_file")
        if mf_entry:
            candidate = root / str(mf_entry)
            if candidate.is_file():
                return candidate
    for fallback in ("main.py", "__init__.py", "source.py"):
        candidate = root / fallback
        if candidate.is_file():
            return candidate
    return None

def _normalize_graph_for_project(
    graph: Dict[str, Iterable[str]], project_name: str
) -> Dict[str, List[str]]:
    # print(f"Normalizing {project_name}")
    BUILTIN_PREFIXES = (
        "<builtin>", "typing.", "abc.", "itertools.", "functools.",
        "collections.", "pathlib.", "argparse.", "json.", "threading.", "queue.",
        "math.", "os.", "sys.", "io.", "re.", "hmac."
    )

    normalized: Dict[str, List[str]] = {}
    for caller, callees in graph.items():
        if caller.startswith("<builtin>") or caller.startswith("<"):
            continue
        if any(caller.startswith(prefix) for prefix in BUILTIN_PREFIXES):
            normalized_caller = caller
        elif not caller.startswith(project_name):
            normalized_caller = f"{project_name}.{caller}"
        else:
            normalized_caller = caller

        normalized_callees = []
        for callee in callees:
            if callee.startswith("<builtin>") or callee.startswith("<"):
                continue
            if any(callee.startswith(prefix) for prefix in BUILTIN_PREFIXES):
                normalized_callees.append(callee)
            else:
                if not callee.startswith(project_name):
                    callee = f"{project_name}.{callee}"
                normalized_callees.append(callee)

        normalized[normalized_caller] = normalized_callees

    return normalized

def _score(predicted: Set[Edge], expected: Set[Edge]) -> Tuple[float, float, int, int, int]:
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall, tp, fp, fn

def _dump_missing_edges(predicted: Set[Edge], project: Project, engine_name: str, dump_dir: Path) -> None:
    # print(f"Dump {project.name} for {engine_name}")
    gt_edges = _adjacency_to_edges(project.ground_truth)
    missing = gt_edges - predicted
    if not missing:
        return
    out_dir = dump_dir / project.name
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{engine_name}_missing.json"
    missing_dict: Dict[str, List[str]] = {}
    for caller, callee in sorted(missing):
        missing_dict.setdefault(caller, []).append(callee)
    _write_callgraph_json(missing_dict, out_file)
    # print(f"[{engine_name}] {project.name}: {len(missing)} missing edges dumped to {out_file}")

def _run_constraint_engine(project: Project, repeats: int, dump_missing: Optional[Path] = None) -> EngineResult:
    source = project.entry_file.read_text(encoding="utf-8")
    runtimes: List[float] = []
    predicted_edges: Set[Edge] = set()  # type: ignore[no-redef]

    try:
        for _ in range(max(1, repeats)):
            start = time.perf_counter()
            graph = extract_call_graph_constraint(
                source,
                source_path=str(project.entry_file),
                allow_fixture_graph_loading=False,
            )
            elapsed = (time.perf_counter() - start) * 1000.0
            runtimes.append(elapsed)
            normalized_graph = _normalize_graph_for_project(graph.get(), project.name)
            predicted_edges = _adjacency_to_edges(normalized_graph)
            # predicted_edges = _adjacency_to_edges(graph.get())

        precision, recall, tp, fp, fn = _score(
            predicted_edges, _adjacency_to_edges(project.ground_truth)
        )
        if dump_missing:
            _dump_missing_edges(predicted_edges, project, "constraint", dump_missing)
        return EngineResult(
            engine="constraint",
            project=project.name,
            runtime_ms=statistics.mean(runtimes),
            precision=precision,
            recall=recall,
            tp=tp,
            fp=fp,
            fn=fn,
        )
    except Exception as exc:
        return EngineResult(
            engine="constraint",
            project=project.name,
            runtime_ms=float("nan"),
            precision=0.0,
            recall=0.0,
            tp=0,
            fp=0,
            fn=0,
            error=str(exc),
        )

def _run_pycg_engine(project: Project, repeats: int, dump_missing: Optional[Path] = None) -> EngineResult:
    source = project.entry_file.read_text(encoding="utf-8")
    runtimes: List[float] = []
    predicted_edges: Set[Edge] = set()

    try:
        for _ in range(max(1, repeats)):
            start = time.perf_counter()
            graph = extract_call_graph_pycg(
                source,
                source_path=str(project.entry_file),
                use_fixture_fallback=False,
            )
            elapsed = (time.perf_counter() - start) * 1000.0
            runtimes.append(elapsed)
            normalized_graph = _normalize_graph_for_project(graph.get(), project.name)
            predicted_edges = _adjacency_to_edges(normalized_graph)
            # predicted_edges = _adjacency_to_edges(graph.get())

        precision, recall, tp, fp, fn = _score(
            predicted_edges, _adjacency_to_edges(project.ground_truth)
        )
        if dump_missing:
            _dump_missing_edges(predicted_edges, project, "pycg", dump_missing)
        return EngineResult(
            engine="pycg",
            project=project.name,
            runtime_ms=statistics.mean(runtimes),
            precision=precision,
            recall=recall,
            tp=tp,
            fp=fp,
            fn=fn,
        )
    except Exception as exc:
        return EngineResult(
            engine="pycg",
            project=project.name,
            runtime_ms=float("nan"),
            precision=0.0,
            recall=0.0,
            tp=0,
            fp=0,
            fn=0,
            error=str(exc),
        )

def _load_external_results(result_dir: Path, projects: List[Project]) -> List[EngineResult]:
    results: List[EngineResult] = []
    if not result_dir.is_dir():
        return results

    for json_file in sorted(result_dir.glob("*.json")):
        engine_name = json_file.stem
        try:
            payload = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception as exc:
            results.append(EngineResult(
                engine=engine_name,
                project="*",
                runtime_ms=float("nan"),
                precision=0.0,
                recall=0.0,
                tp=0,
                fp=0,
                fn=0,
                error=f"Failed to parse {json_file}: {exc}",
            ))
            continue

        if not isinstance(payload, dict):
            continue

        for project in projects:
            proj_graph = payload.get(project.name)
            if proj_graph is None:
                continue
            if not isinstance(proj_graph, dict):
                continue
            try:
                predicted_edges = _adjacency_to_edges(proj_graph)
                precision, recall, tp, fp, fn = _score(
                    predicted_edges, _adjacency_to_edges(project.ground_truth)
                )
                results.append(EngineResult(
                    engine=engine_name,
                    project=project.name,
                    runtime_ms=float("nan"),
                    precision=precision,
                    recall=recall,
                    tp=tp,
                    fp=fp,
                    fn=fn,
                ))
            except Exception as exc:
                results.append(EngineResult(
                    engine=engine_name,
                    project=project.name,
                    runtime_ms=float("nan"),
                    precision=0.0,
                    recall=0.0,
                    tp=0,
                    fp=0,
                    fn=0,
                    error=str(exc),
                ))

    return results

def _aggregate(results: Sequence[EngineResult]) -> Dict[Tuple[str, str], Dict[str, float]]:
    buckets: Dict[Tuple[str, str], List[EngineResult]] = {}
    for row in results:
        if row.error:
            continue
        buckets.setdefault((row.engine, row.project), []).append(row)

    summary: Dict[Tuple[str, str], Dict[str, float]] = {}
    for key, rows in buckets.items():
        summary[key] = {
            "count": float(len(rows)),
            "precision": statistics.mean(item.precision for item in rows),
            "recall": statistics.mean(item.recall for item in rows),
            "runtime_ms": statistics.mean(item.runtime_ms for item in rows) if all(
                not math.isnan(item.runtime_ms) for item in rows
            ) else float("nan"),
        }
    return summary

def _print_summary(results: Sequence[EngineResult]) -> None:
    summary = _aggregate(results)
    if not summary:
        print("No results to display.")
        return

    engine_w = max(len(key[0]) for key in summary) + 1
    proj_w = max(len(key[1]) for key in summary) + 1
    print("\n" + "=" * 80)
    print("REPO-LEVEL CALL GRAPH BENCHMARK".center(80))
    print("=" * 80)

    header = (
        f"{'Engine':<{engine_w}}{'Project':<{proj_w}}"
        f"{'Precision':>10}{'Recall':>8}{'Runtime(ms)':>13}"
    )
    print(header)
    print("-" * 80)

    for (engine, project), values in sorted(summary.items()):
        rt_str = f"{values['runtime_ms']:.2f}" if values['runtime_ms'] == values['runtime_ms'] else "N/A"
        print(
            f"{engine:<{engine_w}}{project:<{proj_w}}"
            f"{values['precision']:>10.3f}{values['recall']:>8.3f}"
            f"{rt_str:>13}"
        )

    print("\n" + "=" * 80)
    print("PER-ENGINE AVERAGES".center(80))
    print("=" * 80)

    engine_aggregates: Dict[str, List[Dict[str, float]]] = {}
    for (engine, _project), values in summary.items():
        engine_aggregates.setdefault(engine, []).append(values)

    eng_w = max(len(e) for e in engine_aggregates) + 1
    avg_header = f"{'Engine':<{eng_w}}{'Projects':>10}{'Avg Prec':>10}{'Avg Rec':>9}{'Avg RT(ms)':>12}"
    print(avg_header)
    print("-" * 80)

    for engine in sorted(engine_aggregates):
        items = engine_aggregates[engine]
        n = float(len(items))
        avg_p = statistics.mean(v["precision"] for v in items)
        avg_r = statistics.mean(v["recall"] for v in items)
        rts = [v["runtime_ms"] for v in items if v["runtime_ms"] == v["runtime_ms"]]
        avg_rt = statistics.mean(rts) if rts else float("nan")
        rt_str = f"{avg_rt:.2f}" if avg_rt == avg_rt else "N/A"
        print(f"{engine:<{eng_w}}{int(n):>10}{avg_p:>10.3f}{avg_r:>9.3f}{rt_str:>12}")

    _print_deltas(summary)
    _print_errors(results)
    _print_mismatch_hint(results)
    print()

def _print_deltas(summary: Dict[Tuple[str, str], Dict[str, float]]) -> None:
    projects = sorted({proj for (_eng, proj) in summary})
    engines = sorted({eng for (eng, _proj) in summary})
    if len(engines) < 2:
        return
    baseline = engines[0]

    print("\n" + "=" * 80)
    print(f"DELTAS vs {baseline} (positive = improvement over baseline)".center(80))
    print("=" * 80)

    proj_w = max(len(p) for p in projects) + 1
    delta_header = f"{'Project':<{proj_w}}"
    for eng in engines[1:]:
        delta_header += f"{' ' + eng + ' ΔPrec':>14}{' ΔRec':>8}{' ΔRT':>10}"
    print(delta_header)
    print("-" * 80)

    for project in projects:
        base = summary.get((baseline, project))
        if not base:
            continue
        line = f"{project:<{proj_w}}"
        for eng in engines[1:]:
            cur = summary.get((eng, project))
            if not cur:
                line += f"{'N/A':>14}{'N/A':>8}{'N/A':>10}"
                continue
            dp = cur["precision"] - base["precision"]
            dr = cur["recall"] - base["recall"]
            has_rt = (
                cur["runtime_ms"] == cur["runtime_ms"] and
                base["runtime_ms"] == base["runtime_ms"]
            )
            drt = (cur["runtime_ms"] - base["runtime_ms"]) if has_rt else float("nan")
            rt_str = f"{drt:+.2f}" if drt == drt else "N/A"
            line += f"{dp:>+14.3f}{dr:>+8.3f}{rt_str:>10}"
        print(line)

def _print_errors(results: Sequence[EngineResult]) -> None:
    failed = [r for r in results if r.error]
    if not failed:
        return
    print(f"\n{len(failed)} engine result(s) recorded errors:")
    for r in failed:
        print(f"  [{r.engine}] {r.project}: {r.error}")

def _print_mismatch_hint(results: Sequence[EngineResult]) -> None:
    zero_recall = [r for r in results if not r.error and r.recall == 0.0 and r.precision == 0.0]
    if not zero_recall:
        return
    engines = sorted({r.engine for r in zero_recall})
    print(f"\nNOTE: {len(zero_recall)} result(s) have zero precision AND zero recall.")
    print("This usually means naming conventions differ between the engine output and ground truth.")
    print("Re-run with --dump-outputs /tmp/debug/ to compare the raw outputs side-by-side:")
    print(f"  python {__file__} --dump-outputs /tmp/debug/ --project <name>")
    print("  cat /tmp/debug/<project>/constraint.json")
    print("  cat /tmp/debug/<project>/ground_truth.json")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Repo-level call-graph benchmark comparing engines on multi-file projects.",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("evaluation/repo_level"),
        help="Path to corpus root (default: evaluation/repo_level)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Number of timed analysis repeats per project (default: 1)",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Write per-project engine results to JSON",
    )
    parser.add_argument(
        "--dump-outputs",
        type=Path,
        default=None,
        help="Write each engine's call-graph JSON to a directory for inspection",
    )
    parser.add_argument(
        "--dump-missing",
        type=Path,
        default=None,
        help="Dump edges missing from engine output (present in GT but not predicted) to directory",
    )
    parser.add_argument(
        "--external-result-dir",
        type=Path,
        default=None,
        help="Load pre-computed results from external baselines (JSON format)",
    )
    parser.add_argument(
        "--engine",
        action="append",
        choices=["constraint", "pycg"],
        help="Which built-in engines to run (repeat for multiple). Default: all built-in.",
    )
    parser.add_argument(
        "--project",
        action="append",
        help="Limit to specific project names (repeat for multiple).",
    )
    args = parser.parse_args()

    corpus_root = args.corpus.resolve()
    if not corpus_root.is_dir():
        print(f"Corpus directory not found: {corpus_root}")
        return 1

    projects = _discover_projects(corpus_root)
    if not projects:
        print("No projects with callgraph.json ground truth found.")
        return 1

    if args.project:
        selected = set(args.project)
        projects = [p for p in projects if p.name in selected]
        if not projects:
            print(f"No projects matching: {args.project}")
            return 1

    engines = args.engine or ["constraint", "pycg"] if PYCG_AVAILABLE else ["constraint"]

    results: List[EngineResult] = []
    for project in projects:
        print(f"Processing {project.name} (entry: {project.entry_file.name}) ...")
        if "constraint" in engines:
            results.append(
                _run_constraint_engine(project, repeats=args.repeat, dump_missing=args.dump_missing)
            )
        if "pycg" in engines and PYCG_AVAILABLE:
            results.append(
                _run_pycg_engine(project, repeats=args.repeat, dump_missing=args.dump_missing)
            )

        if args.dump_outputs:
            _dump_project_graphs(project, args.dump_outputs)

    if args.external_result_dir:
        ext_results = _load_external_results(
            args.external_result_dir.resolve(), projects
        )
        results.extend(ext_results)

    _print_summary(results)

    if args.output_json:
        serializable = []
        for item in results:
            d = item.__dict__.copy()
            if d.get("runtime_ms", 0.0) != d.get("runtime_ms", 0.0):
                d["runtime_ms"] = None
            serializable.append(d)
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
        print(f"Wrote results to {args.output_json}")

    failed = [r for r in results if r.error]
    return 2 if failed else 0


def _dump_project_graphs(project: Project, dump_dir: Path) -> None:
    source = project.entry_file.read_text(encoding="utf-8")
    out_dir = dump_dir / project.name
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        cg = extract_call_graph_constraint(
            source,
            source_path=str(project.entry_file),
            allow_fixture_graph_loading=False,
        )
        normalized_graph = _normalize_graph_for_project(cg.get(), project.name)
        predicted_edges = _adjacency_to_edges(normalized_graph)
        _write_callgraph_json(normalized_graph, out_dir / "constraint.json")
    except Exception:
        pass

    if PYCG_AVAILABLE:
        try:
            cg = extract_call_graph_pycg(
                source,
                source_path=str(project.entry_file),
                use_fixture_fallback=False,
            )
            normalized_graph = _normalize_graph_for_project(cg.get(), project.name)
            predicted_edges = _adjacency_to_edges(normalized_graph)
            _write_callgraph_json(normalized_graph, out_dir / "pycg.json")
        except Exception:
            pass

    _write_callgraph_json(project.ground_truth, out_dir / "ground_truth.json")


if __name__ == "__main__":
    raise SystemExit(main())
