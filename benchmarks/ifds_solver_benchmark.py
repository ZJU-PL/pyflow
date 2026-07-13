"""Repeatable synthetic benchmark for IFDS solver regression tracking."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import time

from pyflow.analysis.ifds import IFDSProblem, IFDSSolver, SolverOptions, Supergraph


class BenchmarkProblem(IFDSProblem[str, int, int]):
    def __init__(self, size: int, fact_count: int) -> None:
        graph = Supergraph[str, int]()
        graph.add_procedure("main", 0, [size - 1])
        for node in range(1, size):
            graph.add_node("main", node)
            graph.add_normal_edge(node - 1, node)
            if node > 1 and node % 5 == 0:
                graph.add_normal_edge(node - 2, node)
        self._graph = graph
        self.fact_count = fact_count

    @property
    def supergraph(self):
        return self._graph

    @property
    def zero_fact(self):
        return 0

    def initial_seeds(self):
        return {0: frozenset({0})}

    def normal_flow(self, node, successor, fact):
        del node, successor
        return (fact, (fact + 1) % self.fact_count)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes", type=int, default=5_000)
    parser.add_argument("--facts", type=int, default=32)
    parser.add_argument("--max-seconds", type=float)
    args = parser.parse_args()

    problem = BenchmarkProblem(args.nodes, args.facts)
    started = time.perf_counter()
    result = IFDSSolver(options=SolverOptions(max_seconds=args.max_seconds)).solve(
        problem
    )
    elapsed = time.perf_counter() - started
    payload = {
        "nodes": args.nodes,
        "facts": args.facts,
        "elapsed_seconds": elapsed,
        "status": result.status.value,
        "termination_reason": result.termination_reason,
        "statistics": asdict(result.statistics),
    }
    print(json.dumps(payload, sort_keys=True))
    return 0 if result.is_complete else 3


if __name__ == "__main__":
    raise SystemExit(main())
