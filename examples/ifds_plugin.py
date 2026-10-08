"""Find functions reachable from module code with a small custom IFDS analysis.

Try: python examples/ifds_plugin.py
Then: python examples/ifds_plugin.py your_program.py
"""

import argparse
from pathlib import Path
import sys

from pyflow.api.ifds import load_analysis_session
from pyflow.analysis.ifds.core.problem import IFDSProblem, ZERO
from pyflow.analysis.ifds.core.solver import IFDSSolver


class VisitedFunctions(IFDSProblem):
    """Domain: function names (strings), plus the special ZERO seed."""

    zero_fact = ZERO

    def __init__(self, session):
        self.graph = session.adapter.supergraph
        self.entry_codes = {entry.code for entry in session.program.entryPoints}

    @property
    def supergraph(self):
        return self.graph

    def initial_seeds(self):
        return {
            self.graph.entry_of(proc): frozenset({ZERO})
            for proc in self.graph.ordered_procedures()
            if proc.code in self.entry_codes
        }

    def normal_flow(self, node, successor, fact):
        return (fact,)

    def call_flow(self, call_node, callee, fact):
        # Keep ZERO so subsequent calls can also generate function-name facts.
        return (ZERO, callee.code.codeName()) if fact is ZERO else (fact,)

    def return_flow(self, call_node, callee, exit_node, return_site, call_fact, exit_fact):
        return (exit_fact,)

    def call_to_return_flow(self, call_node, return_site, fact):
        return (fact,)


def analyze_file(path):
    session = load_analysis_session([path], entry_file=path)
    result = IFDSSolver().solve(VisitedFunctions(session))
    return session, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "file",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "tests/fixtures/analysis_inputs/ifds_demo.py",
        help="Python file to analyze (default: the bundled helper/unused demo)",
    )
    args = parser.parse_args()
    if not args.file.is_file():
        parser.error(f"file not found: {args.file}")
    session, result = analyze_file(args.file)
    names = sorted(
        {
            fact
            for node in session.adapter.supergraph.ordered_nodes()
            for fact in result.facts_at(node)
            if fact is not ZERO
        }
    )
    print(f"Analyzed: {args.file.name}")
    print("Reachable functions: " + (", ".join(names) or "none"))
    for message in session.diagnostic_messages:
        print(message, file=sys.stderr)
    if not result.is_complete:
        print(f"Analysis incomplete: {result.termination_reason}", file=sys.stderr)
    return 0 if result.is_complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
