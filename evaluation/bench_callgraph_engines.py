#!/usr/bin/env python3
"""Benchmark and compare constraint-based and PyCG call graph engines."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from pyflow.analysis.callgraph.constraint_based import extract_call_graph_constraint
from pyflow.analysis.callgraph.pycg_based import PYCG_AVAILABLE, extract_call_graph_pycg


Edge = Tuple[str, str]


@dataclass(frozen=True)
class Case:
    suite: str
    feature: str
    name: str
    main_file: Path
    expected_edges: Set[Edge]


@dataclass(frozen=True)
class CaseResult:
    engine: str
    suite: str
    feature: str
    case: str
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


def _load_expected_edges(case_dir: Path) -> Set[Edge]:
    payload = json.loads((case_dir / "callgraph.json").read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected mapping in {case_dir / 'callgraph.json'}")
    return _adjacency_to_edges(
        {caller: values for caller, values in payload.items() if isinstance(values, list)}
    )


def _discover_cases(suite_name: str, root: Path) -> List[Case]:
    if not root.exists():
        return []

    cases: List[Case] = []
    for main_file in sorted(root.rglob("main.py")):
        case_dir = main_file.parent
        expected_file = case_dir / "callgraph.json"
        if not expected_file.exists():
            continue
        rel = case_dir.relative_to(root)
        parts = rel.parts
        feature = parts[0] if parts else "unknown"
        case_name = "/".join(parts) if parts else case_dir.name
        try:
            expected_edges = _load_expected_edges(case_dir)
        except Exception:
            continue
        cases.append(
            Case(
                suite=suite_name,
                feature=feature,
                name=case_name,
                main_file=main_file,
                expected_edges=expected_edges,
            )
        )
    return cases


def _score(predicted: Set[Edge], expected: Set[Edge]) -> Tuple[float, float, int, int, int]:
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall, tp, fp, fn


def _run_case(
    engine_name: str,
    case: Case,
    runner: Callable[[str, Path], Dict[str, Iterable[str]]],
    repeats: int,
) -> CaseResult:
    source = case.main_file.read_text(encoding="utf-8")
    runtimes: List[float] = []
    predicted_edges: Set[Edge] = set()

    try:
        for _ in range(max(1, repeats)):
            start = time.perf_counter()
            graph = runner(source, case.main_file)
            elapsed = (time.perf_counter() - start) * 1000.0
            runtimes.append(elapsed)
            predicted_edges = _adjacency_to_edges(graph)

        precision, recall, tp, fp, fn = _score(predicted_edges, case.expected_edges)
        return CaseResult(
            engine=engine_name,
            suite=case.suite,
            feature=case.feature,
            case=case.name,
            runtime_ms=statistics.mean(runtimes),
            precision=precision,
            recall=recall,
            tp=tp,
            fp=fp,
            fn=fn,
        )
    except Exception as exc:  # pragma: no cover - benchmarking fallback
        return CaseResult(
            engine=engine_name,
            suite=case.suite,
            feature=case.feature,
            case=case.name,
            runtime_ms=float("nan"),
            precision=0.0,
            recall=0.0,
            tp=0,
            fp=0,
            fn=0,
            error=str(exc),
        )


def _aggregate(results: Sequence[CaseResult]) -> Dict[Tuple[str, str, str], Dict[str, float]]:
    buckets: Dict[Tuple[str, str, str], List[CaseResult]] = {}
    for row in results:
        if row.error:
            continue
        buckets.setdefault((row.engine, row.suite, row.feature), []).append(row)

    summary: Dict[Tuple[str, str, str], Dict[str, float]] = {}
    for key, rows in buckets.items():
        summary[key] = {
            "cases": float(len(rows)),
            "precision": statistics.mean(item.precision for item in rows),
            "recall": statistics.mean(item.recall for item in rows),
            "runtime_ms": statistics.mean(item.runtime_ms for item in rows),
        }
    return summary


def _print_summary(results: Sequence[CaseResult]) -> None:
    summary = _aggregate(results)
    
    # Calculate column widths for nice formatting
    engine_w = max(len(str(k[0])) for k in summary.keys()) + 1
    suite_w = max(len(str(k[1])) for k in summary.keys()) + 1
    feature_w = max(len(str(k[2])) for k in summary.keys()) + 1
    cases_w = 5
    precision_w = 9
    recall_w = 7
    runtime_w = 10
    
    print("\n" + "=" * 80)
    print("PER-FEATURE SUMMARY".center(80))
    print("=" * 80)
    
    # Header row
    header = f"{'Engine':<{engine_w}}{'Suite':<{suite_w}}{'Feature':<{feature_w}}{'Cases':^{cases_w}}{'Precision':^{precision_w}}{'Recall':^{recall_w}}{'Runtime(ms)':^{runtime_w}}"
    print(header)
    print("-" * 80)
    
    # Sort by engine, then suite, then feature
    for (engine, suite, feature), values in sorted(summary.items()):
        print(
            f"{engine:<{engine_w}}{suite:<{suite_w}}{feature:<{feature_w}}"
            f"{int(values['cases']):^{cases_w}}"
            f"{values['precision']:^{precision_w}.3f}"
            f"{values['recall']:^{recall_w}.3f}"
            f"{values['runtime_ms']:^{runtime_w}.2f}"
        )
    
    print("\n" + "=" * 80)
    print("CONSTRAINT vs PyCG DELTAS (positive = improvement)".center(80))
    print("=" * 80)
    
    # Header for deltas
    delta_header = f"{'Suite':<{suite_w}}{'Feature':<{feature_w}}{'PrecisionΔ':^{12}}{'RecallΔ':^{10}}{'RuntimeΔ(ms)':^{14}}"
    print(delta_header)
    print("-" * 80)
    
    features = {(suite, feature) for (_e, suite, feature) in summary.keys()}
    for suite, feature in sorted(features):
        c_key = ("constraint", suite, feature)
        p_key = ("pycg", suite, feature)
        if c_key not in summary or p_key not in summary:
            continue
        c_vals = summary[c_key]
        p_vals = summary[p_key]
        
        prec_delta = c_vals['precision'] - p_vals['precision']
        rec_delta = c_vals['recall'] - p_vals['recall']
        rt_delta = c_vals['runtime_ms'] - p_vals['runtime_ms']
        
        # Color the delta values (green for positive/beneficial, red for negative)
        # Precision/Recall: positive is good, Runtime: negative is good
        prec_str = f"{prec_delta:+.3f}"
        rec_str = f"{rec_delta:+.3f}"
        rt_str = f"{rt_delta:+.2f}"
        
        print(
            f"{suite:<{suite_w}}{feature:<{feature_w}}"
            f"{prec_str:^12}"
            f"{rec_str:^10}"
            f"{rt_str:^14}"
        )
    
    # Summary statistics
    print("\n" + "=" * 80)
    print("OVERALL SUMMARY".center(80))
    print("=" * 80)
    
    # Aggregate across all features
    constraint_results = [(k, v) for k, v in summary.items() if k[0] == "constraint"]
    pycg_results = [(k, v) for k, v in summary.items() if k[0] == "pycg"]
    
    if constraint_results and pycg_results:
        c_avg_prec = statistics.mean(v['precision'] for _k, v in constraint_results)
        c_avg_rec = statistics.mean(v['recall'] for _k, v in constraint_results)
        c_avg_rt = statistics.mean(v['runtime_ms'] for _k, v in constraint_results)
        p_avg_prec = statistics.mean(v['precision'] for _k, v in pycg_results)
        p_avg_rec = statistics.mean(v['recall'] for _k, v in pycg_results)
        p_avg_rt = statistics.mean(v['runtime_ms'] for _k, v in pycg_results)
        
        print(f"{'Engine':<10}{'Avg Precision':>14}{'Avg Recall':>12}{'Avg Runtime(ms)':>18}")
        print("-" * 54)
        print(f"{'constraint':<10}{c_avg_prec:>14.3f}{c_avg_rec:>12.3f}{c_avg_rt:>18.2f}")
        print(f"{'pycg':<10}{p_avg_prec:>14.3f}{p_avg_rec:>12.3f}{p_avg_rt:>18.2f}")
        print("-" * 54)
        print(f"{'delta':<10}{c_avg_prec - p_avg_prec:>+14.3f}{c_avg_rec - p_avg_rec:>+12.3f}{c_avg_rt - p_avg_rt:>+18.2f}")
    print()


def _constraint_runner(source: str, source_path: Path) -> Dict[str, Iterable[str]]:
    graph = extract_call_graph_constraint(
        source,
        source_path=str(source_path),
        allow_fixture_graph_loading=False,
    )
    return graph.get()


def _pycg_runner(source: str, source_path: Path) -> Dict[str, Iterable[str]]:
    graph = extract_call_graph_pycg(
        source,
        source_path=str(source_path),
        use_fixture_fallback=False,
    )
    return graph.get()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare callgraph precision/recall/runtime across engines."
    )
    parser.add_argument(
        "--snippets-root",
        type=Path,
        default=Path("tests/callgraph/snippets"),
        help="Path to benchmark snippet suite root",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Number of timed repeats per case",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Write raw case results to JSON",
    )
    args = parser.parse_args()

    cases: List[Case] = _discover_cases("snippets", args.snippets_root)

    if not cases:
        print("No benchmark cases found.")
        return 1

    results: List[CaseResult] = []
    for case in cases:
        results.append(_run_case("constraint", case, _constraint_runner, repeats=args.repeat))
        if PYCG_AVAILABLE:
            results.append(_run_case("pycg", case, _pycg_runner, repeats=args.repeat))

    _print_summary(results)

    if args.output_json:
        serializable = [item.__dict__ for item in results]
        args.output_json.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
        print(f"\nWrote raw results to {args.output_json}")

    failed = [row for row in results if row.error]
    if failed:
        print(f"\n{len(failed)} cases failed during benchmarking.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
